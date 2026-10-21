// ============================================================================
// VoxelWorld.cpp - deterministic terrain, biomes, caves and trees.
//
// Noise is value noise over a hashed integer lattice: a hash of the lattice
// point gives a pseudo-random value, and the lattice is interpolated with a
// smoothstep. That gives a continuous, repeatable field from nothing but an
// integer hash, which is what makes the world identical on every machine and
// on every run.
// ============================================================================

#include "VoxelWorld.hpp"

#include <algorithm>
#include <cmath>

namespace RawrXD {
namespace Voxel {
namespace {

// Integer hash (a 32-bit finalizer of a Murmur-style mix). Deterministic and
// branch free, so the same coordinate always yields the same value.
inline uint32_t HashU32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

inline uint32_t Hash2(int32_t x, int32_t z, uint32_t seed, uint32_t salt) {
    uint32_t h = seed ^ salt;
    h = HashU32(h + static_cast<uint32_t>(x) * 0x9e3779b9u);
    h = HashU32(h ^ (static_cast<uint32_t>(z) * 0x85ebca6bu + 0x165667b1u));
    return h;
}

inline uint32_t Hash3(int32_t x, int32_t y, int32_t z, uint32_t seed, uint32_t salt) {
    uint32_t h = Hash2(x, z, seed, salt);
    h = HashU32(h ^ (static_cast<uint32_t>(y) * 0xc2b2ae35u + 0x27d4eb2fu));
    return h;
}

inline float Unit(uint32_t h) {
    // 24 bits of mantissa into [0,1).
    return static_cast<float>(h >> 8) * (1.0f / 16777216.0f);
}

inline float SmoothStep(float t) {
    return t * t * (3.0f - 2.0f * t);
}

// 2D value noise with smoothstep interpolation.
inline float ValueNoise2D(float x, float z, uint32_t seed, uint32_t salt) {
    const float fx = std::floor(x);
    const float fz = std::floor(z);
    const int32_t ix = static_cast<int32_t>(fx);
    const int32_t iz = static_cast<int32_t>(fz);
    const float tx = SmoothStep(x - fx);
    const float tz = SmoothStep(z - fz);

    const float v00 = Unit(Hash2(ix, iz, seed, salt));
    const float v10 = Unit(Hash2(ix + 1, iz, seed, salt));
    const float v01 = Unit(Hash2(ix, iz + 1, seed, salt));
    const float v11 = Unit(Hash2(ix + 1, iz + 1, seed, salt));

    const float a = v00 + (v10 - v00) * tx;
    const float b = v01 + (v11 - v01) * tx;
    return a + (b - a) * tz;
}

// 3D value noise with smoothstep interpolation.
inline float ValueNoise3D(float x, float y, float z, uint32_t seed, uint32_t salt) {
    const float fx = std::floor(x);
    const float fy = std::floor(y);
    const float fz = std::floor(z);
    const int32_t ix = static_cast<int32_t>(fx);
    const int32_t iy = static_cast<int32_t>(fy);
    const int32_t iz = static_cast<int32_t>(fz);
    const float tx = SmoothStep(x - fx);
    const float ty = SmoothStep(y - fy);
    const float tz = SmoothStep(z - fz);

    const auto lerp = [](float a, float b, float t) { return a + (b - a) * t; };

    const float c000 = Unit(Hash3(ix, iy, iz, seed, salt));
    const float c100 = Unit(Hash3(ix + 1, iy, iz, seed, salt));
    const float c010 = Unit(Hash3(ix, iy + 1, iz, seed, salt));
    const float c110 = Unit(Hash3(ix + 1, iy + 1, iz, seed, salt));
    const float c001 = Unit(Hash3(ix, iy, iz + 1, seed, salt));
    const float c101 = Unit(Hash3(ix + 1, iy, iz + 1, seed, salt));
    const float c011 = Unit(Hash3(ix, iy + 1, iz + 1, seed, salt));
    const float c111 = Unit(Hash3(ix + 1, iy + 1, iz + 1, seed, salt));

    const float x00 = lerp(c000, c100, tx);
    const float x10 = lerp(c010, c110, tx);
    const float x01 = lerp(c001, c101, tx);
    const float x11 = lerp(c011, c111, tx);
    const float y0 = lerp(x00, x10, ty);
    const float y1 = lerp(x01, x11, ty);
    return lerp(y0, y1, tz);
}

constexpr int32_t kSeaLevel = 18;
constexpr int32_t kMaxTerrainHeight = kChunkHeight - 12;

} // namespace

float VoxelWorld::Fractal2D(float x, float z, uint32_t salt, int octaves) const {
    float sum = 0.0f;
    float amplitude = 1.0f;
    float norm = 0.0f;
    float fx = x;
    float fz = z;
    for (int i = 0; i < octaves; ++i) {
        sum += ValueNoise2D(fx, fz, seed_, salt + static_cast<uint32_t>(i) * 0x9e37u) * amplitude;
        norm += amplitude;
        amplitude *= 0.5f;
        fx *= 2.03f;
        fz *= 2.03f;
    }
    return sum / (norm > 0.0f ? norm : 1.0f);
}

float VoxelWorld::Fractal3D(float x, float y, float z, uint32_t salt, int octaves) const {
    float sum = 0.0f;
    float amplitude = 1.0f;
    float norm = 0.0f;
    float fx = x;
    float fy = y;
    float fz = z;
    for (int i = 0; i < octaves; ++i) {
        sum += ValueNoise3D(fx, fy, fz, seed_, salt + static_cast<uint32_t>(i) * 0x9e37u) * amplitude;
        norm += amplitude;
        amplitude *= 0.5f;
        fx *= 2.07f;
        fy *= 2.07f;
        fz *= 2.07f;
    }
    return sum / (norm > 0.0f ? norm : 1.0f);
}

int32_t VoxelWorld::SurfaceHeight(int32_t wx, int32_t wz) const {
    // Continent shape decides where the land is; hills break up the surface.
    const float continent = Fractal2D(static_cast<float>(wx) * 0.0035f,
                                      static_cast<float>(wz) * 0.0035f, 0x1111u, 4);
    const float hills = Fractal2D(static_cast<float>(wx) * 0.021f,
                                  static_cast<float>(wz) * 0.021f, 0x2222u, 3);
    const float ridge = Fractal2D(static_cast<float>(wx) * 0.009f,
                                  static_cast<float>(wz) * 0.009f, 0x3333u, 2);

    float h = 4.0f + continent * 46.0f + hills * 7.0f;
    // A ridged term sharpens the high ground into something worth looking at.
    h += (ridge > 0.62f ? (ridge - 0.62f) * 42.0f : 0.0f);

    int32_t height = static_cast<int32_t>(h);
    if (height < 1) height = 1;
    if (height > kMaxTerrainHeight) height = kMaxTerrainHeight;
    return height;
}

BlockType VoxelWorld::GetBlock(int32_t wx, int32_t wy, int32_t wz) const {
    if (wy < 0) return BlockType::Bedrock;
    if (wy >= kChunkHeight) return BlockType::Air;

    const int32_t height = SurfaceHeight(wx, wz);

    if (wy == 0) return BlockType::Bedrock;

    // Below the surface. The top three blocks are soil, the rest is stone.
    if (wy < height) {
        if (wy == height - 1) {
            // Surface material depends on the biome.
            const float temperature = Fractal2D(static_cast<float>(wx) * 0.0018f + 512.0f,
                                                static_cast<float>(wz) * 0.0018f - 128.0f, 0x4444u, 3);
            const float moisture = Fractal2D(static_cast<float>(wx) * 0.0021f - 64.0f,
                                             static_cast<float>(wz) * 0.0021f + 96.0f, 0x5555u, 3);
            if (height <= kSeaLevel + 1) return BlockType::Sand;      // beach and seabed
            if (temperature > 0.66f && moisture < 0.45f) return BlockType::Sand; // desert
            if (temperature < 0.26f) return BlockType::Snow;           // cold
            if (moisture < 0.24f) return BlockType::Dirt;              // dry scrub
            return BlockType::Grass;
        }
        if (wy > height - 4) return BlockType::Dirt;
        return BlockType::Stone;
    }

    // At or above the surface.
    if (wy <= kSeaLevel) return BlockType::Water;

    // Caves: a 3D field that only carves below the surface and above bedrock.
    if (wy < height - 2) {
        const float cave = Fractal3D(static_cast<float>(wx) * 0.055f,
                                     static_cast<float>(wy) * 0.085f,
                                     static_cast<float>(wz) * 0.055f, 0x6666u, 2);
        if (cave > 0.685f) return BlockType::Air;
    }

    return BlockType::Air;
}

void VoxelWorld::PlaceTrees(Chunk& chunk, int32_t cx, int32_t cz) const {
    // Trees are placed per world column on a coarse lattice so that a tree
    // straddling a chunk boundary is still produced identically by both
    // chunks. The lattice cell is 5x5 blocks; a cell is a tree site with
    // probability 1/9.
    constexpr int32_t kTreeCell = 5;
    const int32_t baseX = cx * kChunkWidth;
    const int32_t baseZ = cz * kChunkDepth;

    for (int32_t lz = -1; lz <= kChunkDepth / kTreeCell; ++lz) {
        for (int32_t lx = -1; lx <= kChunkWidth / kTreeCell; ++lx) {
            const int32_t cellX = (baseX / kTreeCell) + lx;
            const int32_t cellZ = (baseZ / kTreeCell) + lz;
            const uint32_t h = Hash2(cellX, cellZ, seed_, 0x7A7Au);
            if ((h % 9u) != 0u) continue;

            const int32_t jitterX = static_cast<int32_t>(h >> 8) % kTreeCell;
            const int32_t jitterZ = static_cast<int32_t>(h >> 16) % kTreeCell;
            const int32_t treeX = cellX * kTreeCell + jitterX;
            const int32_t treeZ = cellZ * kTreeCell + jitterZ;

            const int32_t ground = SurfaceHeight(treeX, treeZ) + 1;
            if (ground <= kSeaLevel + 1) continue;             // no trees in water
            if (ground + 7 >= kChunkHeight) continue;

            const uint32_t variant = Hash2(treeX, treeZ, seed_, 0x7B7Bu);
            const int32_t trunk = 4 + static_cast<int32_t>(variant % 3u);

            // Trunk.
            for (int32_t i = 0; i < trunk; ++i) {
                const int32_t wx = treeX;
                const int32_t wy = ground + i;
                const int32_t wz = treeZ;
                const int32_t lx2 = wx - baseX;
                const int32_t lz2 = wz - baseZ;
                if (lx2 < 0 || lx2 >= kChunkWidth || lz2 < 0 || lz2 >= kChunkDepth) continue;
                if (wy < 0 || wy >= kChunkHeight) continue;
                chunk.Set(lx2, wy, lz2, static_cast<uint8_t>(BlockType::Wood));
            }

            // Canopy: a 5x5x2 shell with the corners knocked off.
            const int32_t topY = ground + trunk - 1;
            for (int32_t dy = -2; dy <= 1; ++dy) {
                for (int32_t dz = -2; dz <= 2; ++dz) {
                    for (int32_t dx = -2; dx <= 2; ++dx) {
                        const int32_t adx = dx < 0 ? -dx : dx;
                        const int32_t adz = dz < 0 ? -dz : dz;
                        const int32_t ady = dy < 0 ? -dy : dy;
                        if (ady == 2 && (adx > 1 || adz > 1)) continue;
                        if (adx == 2 && adz == 2) continue;
                        const int32_t wx = treeX + dx;
                        const int32_t wy = topY + dy;
                        const int32_t wz = treeZ + dz;
                        const int32_t lx2 = wx - baseX;
                        const int32_t lz2 = wz - baseZ;
                        if (lx2 < 0 || lx2 >= kChunkWidth || lz2 < 0 || lz2 >= kChunkDepth) continue;
                        if (wy < 0 || wy >= kChunkHeight) continue;
                        if (chunk.At(lx2, wy, lz2) == 0) {
                            chunk.Set(lx2, wy, lz2, static_cast<uint8_t>(BlockType::Leaves));
                        }
                    }
                }
            }
        }
    }
}

Chunk VoxelWorld::GenerateChunk(int32_t cx, int32_t cz) const {
    Chunk chunk;
    chunk.coord = ChunkCoord{cx, cz};
    const int32_t baseX = cx * kChunkWidth;
    const int32_t baseZ = cz * kChunkDepth;

    for (int32_t lz = 0; lz < kChunkDepth; ++lz) {
        for (int32_t lx = 0; lx < kChunkWidth; ++lx) {
            const int32_t wx = baseX + lx;
            const int32_t wz = baseZ + lz;
            const int32_t height = SurfaceHeight(wx, wz);
            const int32_t top = height < kChunkHeight ? height : kChunkHeight - 1;
            for (int32_t ly = 0; ly <= top; ++ly) {
                chunk.Set(lx, ly, lz, static_cast<uint8_t>(GetBlock(wx, ly, wz)));
            }
        }
    }

    PlaceTrees(chunk, cx, cz);
    return chunk;
}

const Chunk* VoxelWorld::FindChunk(int32_t cx, int32_t cz) const {
    auto it = chunks_.find(ChunkCoord{cx, cz});
    return it == chunks_.end() ? nullptr : &it->second;
}

const Chunk& VoxelWorld::GetOrCreateChunk(int32_t cx, int32_t cz) {
    const ChunkCoord key{cx, cz};
    auto it = chunks_.find(key);
    if (it != chunks_.end()) return it->second;
    Chunk generated = GenerateChunk(cx, cz);
    return chunks_.emplace(key, std::move(generated)).first->second;
}

} // namespace Voxel
} // namespace RawrXD
