// ============================================================================
// VoxelWorld.hpp - deterministic procedural voxel world.
//
// The world is a PURE FUNCTION of world coordinates. GetBlock(wx,wy,wz) has
// no state and no chunk dependency, which is what makes cross-chunk face
// culling correct by construction: the mesher asks the world about the
// neighbour one block outside the chunk and gets the same answer the
// neighbouring chunk would have produced.
//
// Chunk storage is a cache over that function, not the source of truth.
// ============================================================================

#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#include "SunshineWorldConfig.hpp"

namespace RawrXD {
namespace Voxel {

// The configurable world generator. It is forward declared here because it
// is defined in terms of BlockType, which lives in this header. The world
// holds it through a shared pointer, so the two headers do not have to
// include each other.
class SunshineWorld;

// The vendored, fully configurable generator.
namespace sunshine {
class Generator;
}

// Block palette. The values are indices into the colour table used by the
// pixel shader; 0 is air and is never emitted as geometry.
enum class BlockType : uint8_t {
    Air = 0,
    Stone = 1,
    Dirt = 2,
    Grass = 3,
    Sand = 4,
    Snow = 5,
    Water = 6,
    Bedrock = 7,
    Wood = 8,
    Leaves = 9,
    Brick = 10,
};

inline constexpr int32_t kChunkWidth = 16;
// The world is 128 blocks tall. The configurable generator's terrain range
// (a sea level near the middle of the column, mountains above it) needs the
// headroom, and a taller column is also what lets a river cut down through
// the rock without reaching the sea floor.
inline constexpr int32_t kChunkHeight = 128;
inline constexpr int32_t kChunkDepth = 16;
inline constexpr int32_t kChunkVolume = kChunkWidth * kChunkHeight * kChunkDepth;

struct ChunkCoord {
    int32_t x = 0;
    int32_t z = 0;

    bool operator==(const ChunkCoord& o) const { return x == o.x && z == o.z; }
    bool operator!=(const ChunkCoord& o) const { return !(*this == o); }
};

struct ChunkCoordHash {
    size_t operator()(const ChunkCoord& c) const noexcept {
        return (static_cast<size_t>(static_cast<uint32_t>(c.x)) * 73856093u) ^
               (static_cast<size_t>(static_cast<uint32_t>(c.z)) * 19349663u);
    }
};

// One chunk of blocks. Row-major in X, then Y, then Z:
//   index = x + y * kChunkWidth + z * kChunkWidth * kChunkHeight
struct Chunk {
    ChunkCoord coord;
    std::vector<uint8_t> blocks = std::vector<uint8_t>(static_cast<size_t>(kChunkVolume), 0);

    uint8_t At(int32_t x, int32_t y, int32_t z) const {
        if (x < 0 || x >= kChunkWidth || y < 0 || y >= kChunkHeight || z < 0 || z >= kChunkDepth)
            return 0;
        return blocks[static_cast<size_t>(x + y * kChunkWidth + z * kChunkWidth * kChunkHeight)];
    }
    void Set(int32_t x, int32_t y, int32_t z, uint8_t v) {
        if (x < 0 || x >= kChunkWidth || y < 0 || y >= kChunkHeight || z < 0 || z >= kChunkDepth)
            return;
        blocks[static_cast<size_t>(x + y * kChunkWidth + z * kChunkWidth * kChunkHeight)] = v;
    }
};

class VoxelWorld {
public:
    // The built-in generator: a hash driven terrain with biomes and caves.
    explicit VoxelWorld(uint32_t seed = 0x5EED1234u) : seed_(seed) {}

    // The configurable Sunshine generator. The world then answers every
    // block query from the generator, and the mesher, the renderer and the
    // chunk cache are unchanged: the generator is just another pure
    // function of world coordinates.
    explicit VoxelWorld(const SunshineWorldConfig& config);

    // Declared here and defined in the translation unit that knows the
    // generator, so the shared pointer to an incomplete type is destroyed
    // where the type is complete.
    ~VoxelWorld();
    VoxelWorld(const VoxelWorld&) = delete;
    VoxelWorld& operator=(const VoxelWorld&) = delete;

    uint32_t seed() const { return seed_; }

    // The pure function: the block at a world coordinate.
    BlockType GetBlock(int32_t wx, int32_t wy, int32_t wz) const;

    // True when the block is a liquid. Liquids do not emit side faces against
    // other liquids, and they do not occlude anything.
    static bool IsLiquid(BlockType t) { return t == BlockType::Water; }
    // True when a face between `self` and `other` should be emitted. Solid
    // against air is visible; solid against liquid is visible (you can see the
    // shoreline); liquid against liquid is not; anything against anything else
    // solid is not.
    static bool FaceVisible(BlockType self, BlockType other) {
        if (self == BlockType::Air) return false;
        if (other == BlockType::Air) return true;
        if (IsLiquid(other)) return !IsLiquid(self);
        return false;
    }

    // Surface height (the first air block above the topmost solid block) for a
    // world column. Cached because the mesher and the tree placer both ask.
    int32_t SurfaceHeight(int32_t wx, int32_t wz) const;

    // Chunk generation. Deterministic for a given (coord, seed).
    Chunk GenerateChunk(int32_t cx, int32_t cz) const;

    // Chunk cache. The first call for a coordinate generates and stores it.
    const Chunk& GetOrCreateChunk(int32_t cx, int32_t cz);
    const Chunk* FindChunk(int32_t cx, int32_t cz) const;
    size_t cachedChunkCount() const { return chunks_.size(); }

    // Drops every cached chunk. The next access regenerates identically.
    void ClearChunkCache() { chunks_.clear(); }

private:
    float Fractal2D(float x, float z, uint32_t salt, int octaves) const;
    float Fractal3D(float x, float y, float z, uint32_t salt, int octaves) const;
    void PlaceTrees(Chunk& chunk, int32_t cx, int32_t cz) const;

    uint32_t seed_;
    // Null when the built-in generator is used. When it is set, every block
    // query is answered by the configurable generator, and the mesher, the
    // renderer and the chunk cache are unchanged: the generator is just
    // another pure function of world coordinates.
    std::shared_ptr<sunshine::Generator> sunshine_;
    mutable std::unordered_map<ChunkCoord, Chunk, ChunkCoordHash> chunks_;
};

} // namespace Voxel
} // namespace RawrXD
