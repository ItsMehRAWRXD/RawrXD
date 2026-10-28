// ============================================================================
// ChunkStore.cpp — the terrain generator.
//
// Every function here is a pure function of the world coordinate and the
// world seed. Nothing reads a file, nothing reads a clock, and nothing
// depends on the order the chunks are generated in. That is the whole
// contract: the world at a coordinate is the same world everywhere.
// ============================================================================

#include "ChunkStore.hpp"

#include <algorithm>

#include "Math.hpp"
#include "Noise.hpp"
#include "RuinBuilder.hpp"

namespace sunshine {

const char* biomeName(Biome b) {
    switch (b) {
        case Biome::Ocean:    return "ocean";
        case Biome::Beach:    return "beach";
        case Biome::Plains:   return "plains";
        case Biome::Forest:   return "forest";
        case Biome::Desert:   return "desert";
        case Biome::Savanna:  return "savanna";
        case Biome::Tundra:   return "tundra";
        case Biome::Snow:     return "snow";
        case Biome::Mountains:return "mountains";
    }
    return "unknown";
}

namespace {

// The field seeds. They are offsets from the world seed so that two fields
// never share a pattern.
constexpr uint32_t kSeedContinental = 0x0000U;
constexpr uint32_t kSeedErosion      = 0x1111U;
constexpr uint32_t kSeedTemperature  = 0x2222U;
constexpr uint32_t kSeedHumidity     = 0x3333U;
constexpr uint32_t kSeedRidge        = 0x4444U;
constexpr uint32_t kSeedCave         = 0x5555U;
constexpr uint32_t kSeedOre          = 0x6666U;
constexpr uint32_t kSeedTree         = 0x7777U;
constexpr uint32_t kSeedForest      = 0x8A5FU;
constexpr uint32_t kSeedCavern       = 0x9B3CU;   // R9: large cavern rooms
constexpr uint32_t kSeedCavernPillar = 0xA2F1U;   // R9: pillars in caverns
constexpr uint32_t kSeedStalactite   = 0xB4E8U;   // R9: ceiling formations
constexpr uint32_t kSeedStalagmite   = 0xC7D5U;   // R9: floor formations

// The tiers of a conifer.
//
// Each tier is a ring of foliage that is wider at its foot than at its
// head, and the tier above is never wider than the tier below ended, so
// the whole crown narrows as it goes up. The last tier is the point at
// the top.
struct ConiferTier {
    int32_t baseRadius;
    int32_t topRadius;
};

// The tiers of a conifer, from the bottom.
//
// A young tree has fewer tiers and is narrower, and an old one has more
// and is wider, so that the shape of the tree says how old it is. Both
// shapes step down at least three times, so that the silhouette of a
// young tree says what it is as clearly as the silhouette of an old one.
constexpr ConiferTier kConiferTiersYoung[3] = {
    {2, 1},
    {1, 0},
    {0, 0},
};

constexpr ConiferTier kConiferTiersOld[4] = {
    {3, 2},
    {2, 1},
    {1, 0},
    {0, 0},
};

// The number of tiers and the width of the bottom tier, for a tree of a
// given height.
void coniferShape(int32_t height, int& tierCount, const ConiferTier*& tiers) {
    if (height < 18) {
        tierCount = 3;
        tiers = kConiferTiersYoung;
    } else {
        tierCount = 4;
        tiers = kConiferTiersOld;
    }
}

// The tree of a column, or none.
//
// A tree only grows where the climate allows it, and only on some of the
// columns that allow it. The column hash decides which, and a slow field
// decides how many: a forest has thickets and clearings in it, and a
// forest that is the same everywhere is not a forest.
TreeKind treeAt(int32_t wx, int32_t wz, Biome biome, uint32_t seed) {
    float chance = 0.0f;
    switch (biome) {
        case Biome::Forest:  chance = 0.20f; break;
        case Biome::Plains:  chance = 0.006f; break;
        case Biome::Savanna: chance = 0.012f; break;
        case Biome::Snow:
        case Biome::Tundra:   chance = 0.060f; break;
        default: return TreeKind::None;
    }

    // The density of the stand, from a slow field. It runs from a quarter
    // of the base chance in the clearings to twice it in the thickets.
    const float density = fbm2D(static_cast<float>(wx) / 46.0f, static_cast<float>(wz) / 46.0f,
                                seed + kSeedForest, 3);
    chance *= (0.18 + 1.9f * density);

    if (hashUnit(wx, 0, wz, seed + kSeedTree) >= chance) return TreeKind::None;

    // The forest is the conifer forest, and the cold ground has stunted
    // conifers in it. The open ground has broadleaves.
    if (biome == Biome::Forest || biome == Biome::Snow || biome == Biome::Tundra) {
        return TreeKind::Conifer;
    }
    return TreeKind::Oak;
}

} // namespace

// The blocks of one tree.
//
// The tree is built in world space and is then clipped into the chunk it
// belongs to, and the tree that is measured and the tree that is placed
// are the same tree because they come from the same blocks.
void World::buildTree(TreeKind kind, int32_t originX, int32_t originZ, int32_t groundY,
                      uint32_t seed, std::vector<TreeBlock>& out) const {
    out.clear();
    if (kind == TreeKind::None) return;

    if (kind == TreeKind::Conifer) {
        // The trunk is bare for a few blocks, so that the tree stands on
        // a stem and the crown is held above the ground.
        const int32_t trunk = 3 + static_cast<int32_t>(hashUnit(originX, 1, originZ, seed) * 3.0f);

        // The age of the tree. A young tree is short and narrow and an
        // old one is tall and wide, so the shape of the tree says how old
        // it is without anything being drawn to say it.
        const int32_t total = 13 + static_cast<int32_t>(hashUnit(originX, 2, originZ, seed) * 15.0f);

        int tierCount = 0;
        const ConiferTier* tiers = nullptr;
        coniferShape(total, tierCount, tiers);
        const int32_t crown = total - trunk;

        // The crown is split between the tiers, and the first one takes
        // what is left over.
        int32_t tierHeight[4];
        int32_t remaining = crown;
        for (int tier = 0; tier < tierCount - 1; ++tier) {
            tierHeight[tier] = remaining / (tierCount - tier);
            remaining -= tierHeight[tier];
        }
        tierHeight[tierCount - 1] = remaining;

        // The crown sits on top of the trunk, not around it, so that the
        // trunk is bare for its whole height.
        int32_t y = groundY + 1 + trunk;

        for (int tier = 0; tier < tierCount; ++tier) {
            const ConiferTier shape = tiers[tier];
            const int32_t height = tierHeight[tier];

            // Each tier is pushed off the trunk by a seeded amount, so
            // that two trees side by side are not the same tree.
            const int32_t offsetX =
                static_cast<int32_t>(hashUnit(originX + tier, 3, originZ, seed) * 3.0f) - 1;
            const int32_t offsetZ =
                static_cast<int32_t>(hashUnit(originX, 4, originZ + tier, seed) * 3.0f) - 1;

            for (int32_t t = 0; t < height; ++t) {
                // The radius of the tier at this height, which narrows
                // as the tier goes up.
                const int32_t span = shape.baseRadius - shape.topRadius;
                int32_t radius = shape.baseRadius;
                if (span > 0 && height > 1) {
                    radius = shape.baseRadius - (t * span) / (height - 1);
                }
                if (radius < shape.topRadius) radius = shape.topRadius;
                if (radius < 0) radius = 0;

                for (int32_t dx = -radius; dx <= radius; ++dx) {
                    for (int32_t dz = -radius; dz <= radius; ++dz) {
                        // The tiers are round rather than square.
                        if (radius > 0 && (dx * dx + dz * dz) > (radius * radius + 1)) continue;
                        TreeBlock block;
                        block.x = originX + offsetX + dx;
                        block.y = y + t;
                        block.z = originZ + offsetZ + dz;
                        block.block = static_cast<uint8_t>(BlockType::Leaves);
                        out.push_back(block);
                    }
                }
            }
            y += height;
        }

        // The trunk, from the ground to the crown.
        for (int32_t t = 0; t < trunk; ++t) {
            TreeBlock block;
            block.x = originX;
            block.y = groundY + 1 + t;
            block.z = originZ;
            block.block = static_cast<uint8_t>(BlockType::Wood);
            out.push_back(block);
        }
        return;
    }

    // The broadleaf: a short trunk and a round crown.
    const int32_t trunk = 4 + static_cast<int32_t>(hashUnit(originX, 1, originZ, seed) * 2.0f);
    const int32_t radius = 2 + static_cast<int32_t>(hashUnit(originX, 2, originZ, seed) * 1.5f);

    for (int32_t t = 0; t < trunk; ++t) {
        TreeBlock block;
        block.x = originX;
        block.y = groundY + 1 + t;
        block.z = originZ;
        block.block = static_cast<uint8_t>(BlockType::Wood);
        out.push_back(block);
    }

    for (int32_t dy = -1; dy <= 2; ++dy) {
        const int32_t r = (dy >= 2) ? radius - 1 : radius;
        for (int32_t dx = -r; dx <= r; ++dx) {
            for (int32_t dz = -r; dz <= r; ++dz) {
                if (dx * dx + dz * dz > r * r + 1) continue;
                if (dy == -1 && dx == 0 && dz == 0) continue;
                TreeBlock block;
                block.x = originX + dx;
                block.y = groundY + 1 + trunk + dy;
                block.z = originZ + dz;
                block.block = static_cast<uint8_t>(BlockType::Leaves);
                out.push_back(block);
            }
        }
    }
}

// The measurements of one tree.
TreeMetrics World::measureTreeShape(const std::vector<TreeBlock>& blocks, int32_t groundY) {
    TreeMetrics metrics;
    metrics.baseY = groundY;
    if (blocks.empty()) return metrics;

    int32_t top = groundY;
    int32_t minX = blocks[0].x;
    int32_t maxX = blocks[0].x;
    int32_t minZ = blocks[0].z;
    int32_t maxZ = blocks[0].z;

    for (const TreeBlock& block : blocks) {
        if (block.y > top) top = block.y;
        if (block.x < minX) minX = block.x;
        if (block.x > maxX) maxX = block.x;
        if (block.z < minZ) minZ = block.z;
        if (block.z > maxZ) maxZ = block.z;
        if (block.block != static_cast<uint8_t>(BlockType::Wood)) ++metrics.leafBlocks;
    }

    metrics.height = top - groundY;

    // The width of the tree at each height, which is the span of the
    // blocks at that height and not the number of them.
    std::vector<int32_t> minAt(static_cast<size_t>(metrics.height + 1), 0x7FFFFFFF);
    std::vector<int32_t> maxAt(static_cast<size_t>(metrics.height + 1), -0x7FFFFFFF);
    std::vector<bool> hasAt(static_cast<size_t>(metrics.height + 1), false);

    for (const TreeBlock& block : blocks) {
        const int32_t level = block.y - groundY;
        if (level < 0 || level > metrics.height) continue;
        const size_t at = static_cast<size_t>(level);
        if (block.x < minAt[at]) minAt[at] = block.x;
        if (block.x > maxAt[at]) maxAt[at] = block.x;
        hasAt[at] = true;
    }

    metrics.sliceWidth.assign(static_cast<size_t>(metrics.height + 1), 0);
    for (int32_t level = 0; level <= metrics.height; ++level) {
        const size_t at = static_cast<size_t>(level);
        if (!hasAt[at]) continue;
        metrics.sliceWidth[at] = maxAt[at] - minAt[at] + 1;
        if (metrics.sliceWidth[at] > metrics.width) metrics.width = metrics.sliceWidth[at];
    }

    // The trunk: the run of levels at the bottom that are one block wide.
    //
    // The tree stands on the ground, so the first level with anything on
    // it is the one above the ground, and the count starts there.
    int32_t first = 0;
    while (first <= metrics.height && metrics.sliceWidth[static_cast<size_t>(first)] == 0) ++first;
    int32_t trunk = 0;
    while (first + trunk <= metrics.height &&
           metrics.sliceWidth[static_cast<size_t>(first + trunk)] == 1) {
        ++trunk;
    }
    metrics.trunkHeight = trunk;

    // The tiers: the number of different widths in the crown, which is
    // the number of steps down the silhouette.
    std::vector<int32_t> widths;
    for (int32_t level = first; level <= metrics.height; ++level) {
        const int32_t w = metrics.sliceWidth[static_cast<size_t>(level)];
        if (w <= 0) continue;
        if (widths.empty() || widths.back() != w) widths.push_back(w);
    }
    metrics.tiers = static_cast<int32_t>(widths.size());

    return metrics;
}

// Whether the crown of the tree narrows all the way to the top.
//
// The top quarter of the height is looked at, and the width there has to
// fall and never rise. A tree that is a lollipop has a crown that is the
// same width all the way up and then stops, and it fails this.
bool TreeMetrics::topTapers() const {
    if (sliceWidth.size() < 8) return false;

    const int32_t top = static_cast<int32_t>(sliceWidth.size()) - 1;
    const int32_t from = top - top / 4;

    int32_t previous = 0;
    for (int32_t level = from; level <= top; ++level) {
        const int32_t w = sliceWidth[static_cast<size_t>(level)];
        if (w <= 0) continue;
        if (previous != 0 && w > previous) return false;
        previous = w;
    }
    return previous > 0;
}

// ---------------------------------------------------------------------------
// Climate fields
// ---------------------------------------------------------------------------

// The climate fields.
//
// The periods are short enough that a walk of a few hundred blocks
// crosses several climates. With a long period the whole of the ground
// that is being looked at has one climate in it, and a world of one
// climate is not a world.
float World::continentalness(int32_t wx, int32_t wz) const {
    return fbm2D(static_cast<float>(wx) / 260.0f, static_cast<float>(wz) / 260.0f,
                 seed_ + kSeedContinental, 4);
}

float World::erosion(int32_t wx, int32_t wz) const {
    return fbm2D(static_cast<float>(wx) / 120.0f, static_cast<float>(wz) / 120.0f,
                 seed_ + kSeedErosion, 3);
}

float World::temperature(int32_t wx, int32_t wz) const {
    return fbm2D(static_cast<float>(wx) / 210.0f, static_cast<float>(wz) / 210.0f,
                 seed_ + kSeedTemperature, 3);
}

float World::humidity(int32_t wx, int32_t wz) const {
    return fbm2D(static_cast<float>(wx) / 165.0f, static_cast<float>(wz) / 165.0f,
                 seed_ + kSeedHumidity, 3);
}

int32_t World::terrainHeight(int32_t wx, int32_t wz) const {
    if (flat_) return kSeaLevel + 4;

    const float cont = continentalness(wx, wz);
    const float ero = erosion(wx, wz);

    // The base land. The continentalness field is centred so that roughly
    // a third of the world is below the sea level.
    int32_t height = static_cast<int32_t>(std::floor(cont * 26.0f + 62.0f));

    // The rolling detail, damped where the land is eroded.
    const float hills = fbm2D(static_cast<float>(wx) / 42.0f, static_cast<float>(wz) / 42.0f,
                              seed_ + kSeedRidge, 4);
    const float hillAmplitude = 2.0f + (1.0f - ero) * 5.0f;
    height += static_cast<int32_t>(std::floor((hills - 0.5f) * 2.0f * hillAmplitude));

    // The mountains. They only appear where the land is high and the
    // erosion is low, which keeps the ranges narrow instead of covering
    // the whole world.
    const float ridge = ridge2D(static_cast<float>(wx) / 150.0f, static_cast<float>(wz) / 150.0f,
                                seed_ + kSeedRidge, 4);
    const float mountainMask = clampf((cont - 0.52f) * 3.4f, 0.0f, 1.0f) *
                               clampf((0.62f - ero) * 3.0f, 0.0f, 1.0f);
    if (mountainMask > 0.0f) {
        height += static_cast<int32_t>(std::floor(ridge * ridge * 52.0f * mountainMask));
    }

    return std::max(2, std::min(kChunkHeight - 12, height));
}

Biome World::biomeAt(int32_t wx, int32_t wz) {
    const int32_t height = terrainHeight(wx, wz);
    const float temp = temperature(wx, wz);
    const float wet = humidity(wx, wz);
    const float ero = erosion(wx, wz);

    if (height < kSeaLevel - 1) return Biome::Ocean;
    if (height <= kSeaLevel + 1) return Biome::Beach;
    if (height > 96) return Biome::Mountains;

    if (temp < 0.24f) return Biome::Snow;
    if (temp < 0.36f) return Biome::Tundra;
    if (temp > 0.68f) {
        if (wet < 0.32f) return Biome::Desert;
        return Biome::Savanna;
    }
    if (wet > 0.56f && ero < 0.62f) return Biome::Forest;
    return Biome::Plains;
}

int32_t World::surfaceHeight(int32_t wx, int32_t wz) {
    const int32_t cx = static_cast<int32_t>(std::floor(static_cast<double>(wx) / kChunkSize));
    const int32_t cz = static_cast<int32_t>(std::floor(static_cast<double>(wz) / kChunkSize));
    Chunk& c = chunk(cx, cz);
    const int32_t lx = wx - cx * kChunkSize;
    const int32_t lz = wz - cz * kChunkSize;

    for (int32_t y = kChunkHeight - 1; y >= 0; --y) {
        const uint8_t b = c.get(lx, y, lz);
        if (b != kBlockAir && b != static_cast<uint8_t>(BlockType::Water)) {
            return y;
        }
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Chunk generation
// ---------------------------------------------------------------------------

void World::generateColumn(Chunk& chunk, int32_t cx, int32_t cz, int32_t lx, int32_t lz) {
    const int32_t wx = cx * kChunkSize + lx;
    const int32_t wz = cz * kChunkSize + lz;

    const int32_t height = terrainHeight(wx, wz);
    const Biome biome = biomeAt(wx, wz);

    // The material of the surface block and the soil under it.
    uint8_t surface = static_cast<uint8_t>(BlockType::Grass);
    uint8_t soil = static_cast<uint8_t>(BlockType::Dirt);
    switch (biome) {
        case Biome::Ocean:
        case Biome::Beach:
            surface = static_cast<uint8_t>(BlockType::Sand);
            soil = static_cast<uint8_t>(BlockType::Sand);
            break;
        case Biome::Desert:
            surface = static_cast<uint8_t>(BlockType::Sand);
            soil = static_cast<uint8_t>(BlockType::Sand);
            break;
        case Biome::Snow:
            surface = static_cast<uint8_t>(BlockType::Snow);
            soil = static_cast<uint8_t>(BlockType::Dirt);
            break;
        case Biome::Tundra:
            surface = static_cast<uint8_t>(BlockType::Grass);
            soil = static_cast<uint8_t>(BlockType::Dirt);
            break;
        case Biome::Mountains:
            if (height > 104) {
                surface = static_cast<uint8_t>(BlockType::Snow);
                soil = static_cast<uint8_t>(BlockType::Stone);
            } else {
                surface = static_cast<uint8_t>(BlockType::Stone);
                soil = static_cast<uint8_t>(BlockType::Stone);
            }
            break;
        case Biome::Savanna:
            surface = static_cast<uint8_t>(BlockType::Grass);
            soil = static_cast<uint8_t>(BlockType::Dirt);
            break;
        default:
            break;
    }

    for (int32_t y = 0; y <= height && y < kChunkHeight; ++y) {
        uint8_t block;

        if (y == 0) {
            block = static_cast<uint8_t>(BlockType::Bedrock);
        } else if (y == height) {
            block = surface;
        } else if (y > height - 4) {
            block = soil;
        } else {
            block = static_cast<uint8_t>(BlockType::Stone);
        }

        // The caves. Two three-dimensional noise fields are combined so
        // that the tunnels are long rather than blobby.
        if (!flat_ && y > 3 && y < height - 1) {
            const float caveA = fbm3D(static_cast<float>(wx) / 34.0f,
                                      static_cast<float>(y) / 20.0f,
                                      static_cast<float>(wz) / 34.0f,
                                      seed_ + kSeedCave, 3);
            const float caveB = fbm3D(static_cast<float>(wx) / 19.0f + 41.0f,
                                      static_cast<float>(y) / 15.0f,
                                      static_cast<float>(wz) / 19.0f - 17.0f,
                                      seed_ + kSeedCave + 0x99U, 2);
            const float tunnel = caveA * 0.65f + caveB * 0.35f;
            if (tunnel > 0.655f) {
                block = kBlockAir;
            } else if (block == static_cast<uint8_t>(BlockType::Stone)) {
                // The ores sit inside the stone, and they are rarer the
                // deeper they are.
                const uint32_t ore = hash3(wx, y, wz, seed_ + kSeedOre);
                const float oreChance = 0.0065f * (1.0f - static_cast<float>(y) / static_cast<float>(kChunkHeight));
                if (oreChance > 0.0f && (static_cast<float>(ore & 0xFFFFU) / 65535.0f) < oreChance) {
                    block = ((ore >> 16) & 1U) ? static_cast<uint8_t>(BlockType::IronOre)
                                               : static_cast<uint8_t>(BlockType::CoalOre);
                } else if (((ore >> 24) & 0x0FU) == 0x0AU) {
                    block = static_cast<uint8_t>(BlockType::Gravel);
                }
            }
        }

        chunk.set(lx, y, lz, block);
    }

    // The water fills everything below the sea level that the terrain left
    // empty.
    if (height < kSeaLevel) {
        for (int32_t y = height + 1; y <= kSeaLevel; ++y) {
            if (y >= 0 && y < kChunkHeight && chunk.get(lx, y, lz) == kBlockAir) {
                chunk.set(lx, y, lz, static_cast<uint8_t>(BlockType::Water));
            }
        }
    }
}

// The tree at a world column, or none.
void World::placeTree(Chunk& chunk, int32_t cx, int32_t cz, int32_t originX, int32_t originZ) {
    const Biome biome = biomeAt(originX, originZ);
    const TreeKind kind = treeAt(originX, originZ, biome, seed_);
    if (kind == TreeKind::None) return;

    // The base of the tree is the top solid block of the column. It is
    // computed from the terrain fields rather than by reading the world,
    // because reading the world here would generate the neighbouring chunk
    // from inside the generation of this one.
    const int32_t ground = terrainHeight(originX, originZ);
    if (ground < kSeaLevel + 1 || ground > 100) return;

    // The tree is built in world space and then clipped into this chunk,
    // so a tree whose trunk is in the next chunk still has its leaves
    // here. The tree that is built is the tree that is measured, because
    // both come from the same blocks.
    const uint32_t treeSeed = seed_ ^ static_cast<uint32_t>(originX * 73856093) ^
                              static_cast<uint32_t>(originZ * 19349663);
    std::vector<TreeBlock> blocks;
    buildTree(kind, originX, originZ, ground, treeSeed, blocks);

    for (const TreeBlock& block : blocks) {
        const int32_t lx = block.x - cx * kChunkSize;
        const int32_t lz = block.z - cz * kChunkSize;
        if (lx < 0 || lx >= kChunkSize || lz < 0 || lz >= kChunkSize) continue;
        if (block.y < 0 || block.y >= kChunkHeight) continue;
        if (!chunk.isReplaceable(lx, block.y, lz)) continue;
        chunk.set(lx, block.y, lz, block.block);
    }
}

std::vector<World::RuinOrigin> World::ruinOrigins() const {
    std::vector<RuinOrigin> origins;
    for (int32_t index = 0; index < 3; ++index) {
        RuinOrigin origin;
        origin.x = 40 + index * 88 + static_cast<int32_t>(hash3(index, 1, 0, seed_) % 17U);
        origin.z = -56 + index * 71 + static_cast<int32_t>(hash3(index, 2, 0, seed_) % 19U);
        origin.groundY = terrainHeight(origin.x, origin.z);
        if (origin.groundY < kSeaLevel + 2 || origin.groundY > 92) continue;
        origins.push_back(origin);
    }
    return origins;
}

// The ruins of the world.
//
// There are a few of them and they are in the same place every time,
// because the seed decides. The ground under one is made flat, so that
// the foundation of the ruin rests on the ground and not in the side of
// a hill.
void World::placeRuins(Chunk& chunk, int32_t cx, int32_t cz) {
    for (int32_t index = 0; index < 3; ++index) {
        // Where this one is.
        const int32_t originX = 40 + index * 88 + static_cast<int32_t>(hash3(index, 1, 0, seed_) % 17U);
        const int32_t originZ = -56 + index * 71 + static_cast<int32_t>(hash3(index, 2, 0, seed_) % 19U);

        // The ground it stands on.
        const int32_t ground = terrainHeight(originX, originZ);
        if (ground < kSeaLevel + 2 || ground > 92) continue;

        // The plan, moved to where this one is.
        RuinPlan plan = planRuin(seed_ + static_cast<uint32_t>(index) * 7919U, ground);
        for (RuinPart& part : plan.parts) {
            part.x += originX;
            part.z += originZ;
        }
        for (RuinArch& arch : plan.arches) {
            arch.x += originX;
            arch.z += originZ;
        }

        // The footprint of the ruin, so that the ground under it can be
        // made flat and the blocks can be put in the right chunks.
        int32_t minX = originX, maxX = originX;
        int32_t minZ = originZ, maxZ = originZ;
        for (const RuinPart& part : plan.parts) {
            minX = std::min(minX, part.x);
            maxX = std::max(maxX, part.x + part.width - 1);
            minZ = std::min(minZ, part.z);
            maxZ = std::max(maxZ, part.z + part.depth - 1);
        }

        // The ground under it, made flat.
        for (int32_t x = minX; x <= maxX; ++x) {
            for (int32_t z = minZ; z <= maxZ; ++z) {
                const int32_t lx = x - cx * kChunkSize;
                const int32_t lz = z - cz * kChunkSize;
                if (lx < 0 || lx >= kChunkSize || lz < 0 || lz >= kChunkSize) continue;
                for (int32_t y = 0; y <= ground; ++y) {
                    chunk.set(lx, y, lz, static_cast<uint8_t>(BlockType::Stone));
                }
            }
        }

        // The ruin itself.
        const std::vector<RuinBlock> blocks =
            buildRuin(plan, static_cast<uint8_t>(BlockType::Stone),
                      static_cast<uint8_t>(BlockType::Gravel));
        for (const RuinBlock& block : blocks) {
            const int32_t lx = block.x - cx * kChunkSize;
            const int32_t lz = block.z - cz * kChunkSize;
            if (lx < 0 || lx >= kChunkSize || lz < 0 || lz >= kChunkSize) continue;
            if (block.y < 0 || block.y >= kChunkHeight) continue;
            chunk.set(lx, block.y, lz, block.block);
        }
    }
}

void World::placeTrees(Chunk& chunk, int32_t cx, int32_t cz) {
    if (flat_) return;

    // The trees of the neighbouring columns are grown into this chunk as
    // well, so a crown that crosses a chunk border is not cut in half.
    for (int32_t dz = -1; dz <= 1; ++dz) {
        for (int32_t dx = -1; dx <= 1; ++dx) {
            const int32_t ncx = cx + dx;
            const int32_t ncz = cz + dz;
            for (int32_t lz = 0; lz < kChunkSize; ++lz) {
                for (int32_t lx = 0; lx < kChunkSize; ++lx) {
                    const int32_t wx = ncx * kChunkSize + lx;
                    const int32_t wz = ncz * kChunkSize + lz;
                    const Biome biome = biomeAt(wx, wz);
                    if (treeAt(wx, wz, biome, seed_) == TreeKind::None) continue;
                    placeTree(chunk, cx, cz, wx, wz);
                }
            }
        }
    }
}

void World::generateChunk(Chunk& chunk, int32_t cx, int32_t cz) {
    for (int32_t lz = 0; lz < kChunkSize; ++lz) {
        for (int32_t lx = 0; lx < kChunkSize; ++lx) {
            generateColumn(chunk, cx, cz, lx, lz);
        }
    }
    placeTrees(chunk, cx, cz);
    placeRuins(chunk, cx, cz);
}

Chunk& World::chunk(int32_t cx, int32_t cz) {
    const ChunkKey key{cx, cz};
    const auto it = chunks_.find(key);
    if (it != chunks_.end()) return *it->second;

    auto owned = std::make_unique<Chunk>();
    Chunk& ref = *owned;
    chunks_.emplace(key, std::move(owned));
    generated_.push_back(key);
    generateChunk(ref, cx, cz);
    return ref;
}

size_t World::evictBeyond(int32_t centerChunkX, int32_t centerChunkZ, int32_t radiusInChunks) {
    const int64_t r2 = static_cast<int64_t>(radiusInChunks) * radiusInChunks;

    size_t dropped = 0;
    for (auto it = chunks_.begin(); it != chunks_.end();) {
        const int64_t dx = static_cast<int64_t>(it->first.x) - centerChunkX;
        const int64_t dz = static_cast<int64_t>(it->first.z) - centerChunkZ;
        if (dx * dx + dz * dz > r2) {
            it = chunks_.erase(it);
            ++dropped;
        } else {
            ++it;
        }
    }
    if (dropped > 0) {
        generated_.erase(
            std::remove_if(generated_.begin(), generated_.end(),
                           [&](const ChunkKey& k) {
                               const int64_t dx = static_cast<int64_t>(k.x) - centerChunkX;
                               const int64_t dz = static_cast<int64_t>(k.z) - centerChunkZ;
                               return dx * dx + dz * dz > r2;
                           }),
            generated_.end());
    }
    return dropped;
}

uint8_t World::blockAt(int32_t wx, int32_t wy, int32_t wz) {    if (wy < 0) return static_cast<uint8_t>(BlockType::Bedrock);
    if (wy >= kChunkHeight) return kBlockAir;

    const int32_t cx = static_cast<int32_t>(std::floor(static_cast<double>(wx) / kChunkSize));
    const int32_t cz = static_cast<int32_t>(std::floor(static_cast<double>(wz) / kChunkSize));
    Chunk& c = chunk(cx, cz);
    const int32_t lx = wx - cx * kChunkSize;
    const int32_t lz = wz - cz * kChunkSize;
    return c.get(lx, wy, lz);
}

} // namespace sunshine
