// ============================================================================
// ChunkStore.hpp — the world: its chunks, and the deterministic terrain.
//
// A chunk is a 16 x 128 x 16 column of blocks. The world is a map of those
// columns, addressed by chunk coordinate, and a chunk is generated on the
// first time it is asked for.
//
// The terrain is a function of the world coordinate and the world seed, and
// of nothing else. The same seed gives the same world on every machine and
// in every build, which is what lets a frame capture be compared against a
// reference and what lets an agent say "the world at these coordinates has
// this block" and be right.
//
// The generator layers five things, in the order a real world builds them:
//
//   1. the continental shape, which decides where land is at all
//   2. the erosion, which decides how rough that land is
//   3. the mountain ridges, which only appear where the land is old and
//      uneroded
//   4. the surface material, which comes from the climate fields
//   5. the caves, the ores, the water and the trees
//
// None of it is sampled from a texture or read from a file. It is all
// arithmetic on coordinates.
// ============================================================================

#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#include "Block.hpp"

namespace sunshine {

constexpr int32_t kChunkSize = 16;      // blocks along X and Z
constexpr int32_t kChunkHeight = 128;   // blocks along Y
constexpr int32_t kSeaLevel = 62;

// The chunk coordinate. X and Z address a chunk; Y is always the whole
// column, so a chunk is a full-height slice of the world.
struct ChunkKey {
    int32_t x = 0;
    int32_t z = 0;

    bool operator==(const ChunkKey& o) const { return x == o.x && z == o.z; }
};

struct ChunkKeyHash {
    size_t operator()(const ChunkKey& k) const {
        uint32_t h = static_cast<uint32_t>(k.x) * 0x9E3779B1U;
        h ^= static_cast<uint32_t>(k.z) * 0x85EBCA77U;
        h ^= h >> 15;
        return static_cast<size_t>(h);
    }
};

// One column of the world.
class Chunk {
public:
    Chunk() : blocks_(static_cast<size_t>(kChunkSize) * kChunkHeight * kChunkSize, kBlockAir) {}

    uint8_t get(int32_t lx, int32_t ly, int32_t lz) const {
        if (lx < 0 || lx >= kChunkSize || lz < 0 || lz >= kChunkSize) return kBlockAir;
        if (ly < 0) return static_cast<uint8_t>(BlockType::Bedrock);
        if (ly >= kChunkHeight) return kBlockAir;
        return blocks_[index(lx, ly, lz)];
    }

    void set(int32_t lx, int32_t ly, int32_t lz, uint8_t value) {
        if (lx < 0 || lx >= kChunkSize || lz < 0 || lz >= kChunkSize) return;
        if (ly < 0 || ly >= kChunkHeight) return;
        blocks_[index(lx, ly, lz)] = value;
    }

    // True when the block is one the generator can replace, so that a tree
    // leaf does not overwrite a cave wall it happens to land on.
    bool isReplaceable(int32_t lx, int32_t ly, int32_t lz) const {
        const uint8_t b = get(lx, ly, lz);
        return b == kBlockAir || b == static_cast<uint8_t>(BlockType::Water);
    }

    const std::vector<uint8_t>& blocks() const { return blocks_; }

private:
    static size_t index(int32_t lx, int32_t ly, int32_t lz) {
        return static_cast<size_t>(lx) +
               static_cast<size_t>(kChunkSize) * (static_cast<size_t>(lz) +
               static_cast<size_t>(kChunkSize) * static_cast<size_t>(ly));
    }

    std::vector<uint8_t> blocks_;
};

// The climate of a column, which is what decides the biome.
enum class Biome : uint8_t {
    Ocean,
    Beach,
    Plains,
    Forest,
    Desert,
    Savanna,
    Tundra,
    Snow,
    Mountains,
};

// The shape of a tree.
enum class TreeKind : uint8_t {
    None,
    Oak,
    Conifer,
};

// One block of a tree, in the world.
struct TreeBlock {
    int32_t x = 0;
    int32_t y = 0;
    int32_t z = 0;
    uint8_t block = 0;
};

// The measurements of a tree.
//
// These are what the conifer is judged by. A tree that is certified
// because it looks like a conifer is not certified; a tree that has a
// trunk, tiers of foliage, and a crown that narrows as it goes up is.
struct TreeMetrics {
    int32_t baseY = 0;       // the ground the tree stands on
    int32_t height = 0;       // the blocks from the ground to the top
    int32_t width = 0;        // the widest the tree is, at any height
    int32_t tiers = 0;        // the number of different widths in the crown
    int32_t trunkHeight = 0;  // the height of the bare trunk
    int32_t leafBlocks = 0;   // the blocks of foliage

    // The width of the tree at each height above the ground.
    std::vector<int32_t> sliceWidth;

    // How tall the tree is against how wide it is.
    double ratio() const {
        return width > 0 ? static_cast<double>(height) / static_cast<double>(width) : 0.0;
    }

    // The share of the height, measured from the top, that narrows
    // without a break.
    bool topTapers() const;
};

const char* biomeName(Biome b);

// The world. Owns the chunks and generates them on demand.
class World {
public:
    explicit World(uint32_t seed = 0x5EED1234U) : seed_(seed) {}

    uint32_t seed() const { return seed_; }
    void setSeed(uint32_t seed) {
        seed_ = seed;
        chunks_.clear();
    }

    // A plain world, with no hills, no caves and no trees.
    //
    // It is there to tell a broken renderer apart from a broken world,
    // because a flat world draws a flat plane and nothing else.
    void setFlat(bool flat) { flat_ = flat; }
    bool isFlat() const { return flat_; }

    // The chunk at a chunk coordinate, generated if it does not exist yet.
    Chunk& chunk(int32_t cx, int32_t cz);

    // The block at a world coordinate. Y outside the column is air above
    // and bedrock below, so a column that reaches the bottom of the world
    // still has a floor.
    uint8_t blockAt(int32_t wx, int32_t wy, int32_t wz);

    // The biome of a world column.
    Biome biomeAt(int32_t wx, int32_t wz);

    // The height of the ground of a column.
    int32_t terrainHeight(int32_t wx, int32_t wz) const;

    // The blocks of one tree.
    //
    // The tree is built here and nowhere else, so the tree that is
    // measured and the tree that is placed are the same tree.
    void buildTree(TreeKind kind, int32_t originX, int32_t originZ, int32_t groundY,
                   uint32_t seed, std::vector<TreeBlock>& out) const;

    // The measurements of one tree, from the blocks of it.
    static TreeMetrics measureTreeShape(const std::vector<TreeBlock>& blocks, int32_t groundY);

    // The height of the surface.
    int32_t surfaceHeight(int32_t wx, int32_t wz);

    // Where the ruins of the world are, and the ground they stand on.
    //
    // They are in the same place every time, because the seed decides,
    // so that a camera can be pointed at one and the picture is the same
    // on every run.
    struct RuinOrigin {
        int32_t x = 0;
        int32_t z = 0;
        int32_t groundY = 0;
    };
    std::vector<RuinOrigin> ruinOrigins() const;

    size_t chunkCount() const { return chunks_.size(); }
    size_t generatedCount() const { return generated_.size(); }

    // Drop the chunks that are too far from a point, so that a camera that
    // keeps walking does not keep every chunk it ever passed alive.
    //
    // The chunks that are kept are those inside a radius, measured in
    // chunks, of the given chunk coordinate. The number dropped is
    // returned so the caller can report it.
    size_t evictBeyond(int32_t centerChunkX, int32_t centerChunkZ, int32_t radiusInChunks);

private:
    void generateChunk(Chunk& chunk, int32_t cx, int32_t cz);
    void generateColumn(Chunk& chunk, int32_t cx, int32_t cz, int32_t lx, int32_t lz);
    void placeTrees(Chunk& chunk, int32_t cx, int32_t cz);
    void placeTree(Chunk& chunk, int32_t cx, int32_t cz, int32_t originX, int32_t originZ);

    // The ruins of the world.
    //
    // They stand on the ground, and the ground is made flat under them,
    // so that the foundation rests on it and does not float.
    void placeRuins(Chunk& chunk, int32_t cx, int32_t cz);


    // The climate and height fields, evaluated in world space.
    float continentalness(int32_t wx, int32_t wz) const;
    float erosion(int32_t wx, int32_t wz) const;
    float temperature(int32_t wx, int32_t wz) const;
    float humidity(int32_t wx, int32_t wz) const;

    uint32_t seed_ = 0;
    bool flat_ = false;
    std::unordered_map<ChunkKey, std::unique_ptr<Chunk>, ChunkKeyHash> chunks_;
    std::vector<ChunkKey> generated_;
};

} // namespace sunshine
