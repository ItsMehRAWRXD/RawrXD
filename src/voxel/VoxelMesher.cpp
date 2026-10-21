// ============================================================================
// VoxelMesher.cpp - greedy meshing with cross-chunk face culling and AO.
//
// Algorithm (per axis d, per plane along d):
//   1. At every plane, compare the cell below the plane with the cell above.
//      Exactly one of them can be solid-and-visible, so a plane contributes
//      at most one face.
//   2. Build a 2D mask of (block type, normal sign) over the plane.
//   3. Merge equal neighbours into maximal rectangles (classic greedy
//      meshing), which collapses a flat field into single quads.
//   4. Emit one quad per rectangle, with per-vertex ambient occlusion sampled
//      from the blocks around each corner.
//
// The mask is indexed by the chunk's own cells, but the BLOCK VALUES come from
// the world, so a face at a chunk boundary is culled against the real
// neighbour in the adjacent chunk.
//
// All sampling happens in one padded index space:
//   paddedIndex(a) = chunkLocalIndex(a) + kOffset[a]
//   worldCoord(a)  = base(a) + (paddedIndex(a) - kOffset[a])
// ============================================================================

#include "VoxelMesher.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace RawrXD {
namespace Voxel {
namespace {

// Padded sampling volume: one step beyond the chunk for the face test, two
// steps in the tangent directions for ambient occlusion.
constexpr int32_t kPadX = 2;
constexpr int32_t kPadY = 1;
constexpr int32_t kPadZ = 2;

constexpr int32_t kSizeX = kChunkWidth + 2 * kPadX + 1;   // 21
constexpr int32_t kSizeY = kChunkHeight + 2 * kPadY + 1;  // 67
constexpr int32_t kSizeZ = kChunkDepth + 2 * kPadZ + 1;   // 21

inline int32_t Index(int32_t px, int32_t py, int32_t pz) {
    return px + py * kSizeX + pz * kSizeX * kSizeY;
}

inline bool Opaque(uint8_t t) {
    return t != static_cast<uint8_t>(BlockType::Air) && t != static_cast<uint8_t>(BlockType::Water);
}

} // namespace

uint32_t BlockColor(BlockType type) {
    switch (type) {
    case BlockType::Stone:   return 0xFF7A7A7Au;
    case BlockType::Dirt:    return 0xFF79553Bu;
    case BlockType::Grass:   return 0xFF4E9A3Fu;
    case BlockType::Sand:    return 0xFFD9C27Bu;
    case BlockType::Snow:    return 0xFFF2F4F7u;
    case BlockType::Water:   return 0xFF3A6FD8u;
    case BlockType::Bedrock: return 0xFF3A3A3Fu;
    case BlockType::Wood:    return 0xFF6B4A2Bu;
    case BlockType::Leaves:  return 0xFF2F7A32u;
    case BlockType::Air:
    default:                 return 0x00000000u;
    }
}

ChunkMesh MeshChunk(const VoxelWorld& world, int32_t chunkX, int32_t chunkZ) {
    ChunkMesh mesh;

    // ---- 1. Fill the padded volume from the world ---------------------------
    std::vector<uint8_t> pad(static_cast<size_t>(kSizeX) * kSizeY * kSizeZ, 0);

    const int32_t baseX = chunkX * kChunkWidth;
    const int32_t baseZ = chunkZ * kChunkDepth;

    for (int32_t pz = 0; pz < kSizeZ; ++pz) {
        const int32_t wz = baseZ + pz - kPadZ;
        for (int32_t py = 0; py < kSizeY; ++py) {
            const int32_t wy = py - kPadY;
            for (int32_t px = 0; px < kSizeX; ++px) {
                const int32_t wx = baseX + px - kPadX;
                pad[static_cast<size_t>(Index(px, py, pz))] =
                    static_cast<uint8_t>(world.GetBlock(wx, wy, wz));
            }
        }
    }

    const int32_t kOffset[3] = {kPadX, kPadY, kPadZ};
    const int32_t kCells[3] = {kChunkWidth, kChunkHeight, kChunkDepth};
    const int32_t kBase[3] = {baseX, 0, baseZ};

    // ---- 2. Sweep each axis -----------------------------------------------
    for (int32_t d = 0; d < 3; ++d) {
        const int32_t u = (d + 1) % 3;
        const int32_t v = (d + 2) % 3;
        const int32_t uCells = kCells[u];
        const int32_t vCells = kCells[v];
        const int32_t uCellsTotal = kCells[u];
        const int32_t vCellsTotal = kCells[v];
        (void)uCellsTotal;
        (void)vCellsTotal;

        std::vector<uint8_t> maskBlock(static_cast<size_t>(uCells) * vCells, 0);
        std::vector<int8_t> maskSign(static_cast<size_t>(uCells) * vCells, 0);
        std::vector<uint8_t> maskAo(static_cast<size_t>(uCells) * vCells * 4, 0);

        // The block at (padded index along d, cell uu, cell vv).
        auto blockAt = [&](int32_t pd, int32_t uu, int32_t vv) -> uint8_t {
            int32_t p[3];
            p[d] = pd;
            p[u] = uu + kOffset[u];
            p[v] = vv + kOffset[v];
            return pad[static_cast<size_t>(Index(p[0], p[1], p[2]))];
        };

        const int32_t planeBegin = kOffset[d];
        const int32_t planeEnd = kOffset[d] + kCells[d];  // inclusive

        for (int32_t pd = planeBegin; pd <= planeEnd; ++pd) {
            std::fill(maskBlock.begin(), maskBlock.end(), 0);
            std::fill(maskSign.begin(), maskSign.end(), 0);
            std::fill(maskAo.begin(), maskAo.end(), 0);

            for (int32_t vv = 0; vv < vCells; ++vv) {
                for (int32_t uu = 0; uu < uCells; ++uu) {
                    const uint8_t a = blockAt(pd - 1, uu, vv);
                    const uint8_t b = blockAt(pd, uu, vv);

                    const bool aVisible = VoxelWorld::FaceVisible(static_cast<BlockType>(a),
                                                                 static_cast<BlockType>(b));
                    const bool bVisible = VoxelWorld::FaceVisible(static_cast<BlockType>(b),
                                                                 static_cast<BlockType>(a));
                    if (!aVisible && !bVisible) continue;

                    const uint8_t solid = aVisible ? a : b;
                    const int8_t sign = aVisible ? +1 : -1;  // +1 -> normal along +d
                    // The open side of the face, in padded index space.
                    const int32_t nPd = aVisible ? pd : (pd - 1);

                    const size_t mi = static_cast<size_t>(vv) * uCells + uu;
                    maskBlock[mi] = solid;
                    maskSign[mi] = sign;
                    ++mesh.faceCount;

                    // ---- Ambient occlusion ------------------------------------
                    // For each of the four corners of the face, sample the three
                    // blocks that touch that corner on the open side.
                    for (int32_t corner = 0; corner < 4; ++corner) {
                        const int32_t du = (corner == 1 || corner == 2) ? +1 : -1;
                        const int32_t dv = (corner == 2 || corner == 3) ? +1 : -1;

                        int32_t p[3];
                        p[d] = nPd;
                        p[u] = uu + kOffset[u];
                        p[v] = vv + kOffset[v];

                        int32_t s1[3] = {p[0], p[1], p[2]};
                        int32_t s2[3] = {p[0], p[1], p[2]};
                        int32_t sc[3] = {p[0], p[1], p[2]};
                        s1[u] += du;
                        s2[v] += dv;
                        sc[u] += du;
                        sc[v] += dv;

                        const bool occ1 = Opaque(pad[static_cast<size_t>(Index(s1[0], s1[1], s1[2]))]);
                        const bool occ2 = Opaque(pad[static_cast<size_t>(Index(s2[0], s2[1], s2[2]))]);
                        const bool occC = Opaque(pad[static_cast<size_t>(Index(sc[0], sc[1], sc[2]))]);

                        const uint8_t ao = (occ1 && occ2)
                            ? 0u
                            : static_cast<uint8_t>(3u - ((occ1 ? 1u : 0u) + (occ2 ? 1u : 0u) + (occC ? 1u : 0u)));
                        maskAo[mi * 4 + static_cast<size_t>(corner)] = ao;
                    }
                }
            }

            // ---- Merge the mask into maximal rectangles --------------------
            for (int32_t vv = 0; vv < vCells; ++vv) {
                for (int32_t uu = 0; uu < uCells;) {
                    const size_t mi = static_cast<size_t>(vv) * uCells + uu;
                    const uint8_t block = maskBlock[mi];
                    const int8_t sign = maskSign[mi];
                    if (block == 0) { ++uu; continue; }

                    // Extend along u.
                    int32_t w = 1;
                    while (uu + w < uCells) {
                        const size_t mj = static_cast<size_t>(vv) * uCells + (uu + w);
                        if (maskBlock[mj] != block || maskSign[mj] != sign) break;
                        ++w;
                    }

                    // Extend along v while the whole run matches.
                    int32_t h = 1;
                    while (vv + h < vCells) {
                        bool matches = true;
                        for (int32_t i = 0; i < w; ++i) {
                            const size_t mj = static_cast<size_t>(vv + h) * uCells + (uu + i);
                            if (maskBlock[mj] != block || maskSign[mj] != sign) { matches = false; break; }
                        }
                        if (!matches) break;
                        ++h;
                    }

                    // ---- Emit the quad ---------------------------------------
                    const uint8_t ao0 = maskAo[(static_cast<size_t>(vv) * uCells + uu) * 4 + 0];
                    const uint8_t ao1 = maskAo[(static_cast<size_t>(vv) * uCells + (uu + w - 1)) * 4 + 1];
                    const uint8_t ao2 = maskAo[(static_cast<size_t>(vv + h - 1) * uCells + (uu + w - 1)) * 4 + 2];
                    const uint8_t ao3 = maskAo[(static_cast<size_t>(vv + h - 1) * uCells + uu) * 4 + 3];

                    const uint32_t rgb = BlockColor(static_cast<BlockType>(block));

                    // The four corners of the merged rectangle, in padded index
                    // space: the plane along d, and the cell extents along u/v.
                    int32_t cornerPos[4][3];
                    const int32_t uPos[4] = {uu, uu + w, uu + w, uu};
                    const int32_t vPos[4] = {vv, vv, vv + h, vv + h};
                    for (int32_t c = 0; c < 4; ++c) {
                        cornerPos[c][d] = pd;
                        cornerPos[c][u] = uPos[c] + kOffset[u];
                        cornerPos[c][v] = vPos[c] + kOffset[v];
                    }

                    const uint32_t baseIndex = static_cast<uint32_t>(mesh.vertices.size());
                    for (int32_t c = 0; c < 4; ++c) {
                        VoxelVertex vert;
                        const int32_t p[3] = {cornerPos[c][0], cornerPos[c][1], cornerPos[c][2]};
                        vert.px = static_cast<float>(kBase[0] + (p[0] - kOffset[0]));
                        vert.py = static_cast<float>(kBase[1] + (p[1] - kOffset[1]));
                        vert.pz = static_cast<float>(kBase[2] + (p[2] - kOffset[2]));
                        float n[3] = {0.0f, 0.0f, 0.0f};
                        n[d] = static_cast<float>(sign);
                        vert.nx = n[0];
                        vert.ny = n[1];
                        vert.nz = n[2];
                        vert.color = rgb;
                        // Each vertex carries the AO of ITS OWN corner. For a
                        // merged quad the corner AO is taken from the cell that
                        // owns that corner of the rectangle.
                        const uint8_t ao = (c == 0) ? ao0 : (c == 1) ? ao1 : (c == 2) ? ao2 : ao3;
                        vert.blockAo = (static_cast<uint32_t>(block) & 0xFFu) |
                                       ((static_cast<uint32_t>(ao) & 0x3u) << 8);
                        mesh.vertices.push_back(vert);
                    }

                    // Winding: counter-clockwise when viewed from the normal.
                    if (sign > 0) {
                        mesh.indices.push_back(baseIndex + 0);
                        mesh.indices.push_back(baseIndex + 1);
                        mesh.indices.push_back(baseIndex + 2);
                        mesh.indices.push_back(baseIndex + 0);
                        mesh.indices.push_back(baseIndex + 2);
                        mesh.indices.push_back(baseIndex + 3);
                    } else {
                        mesh.indices.push_back(baseIndex + 0);
                        mesh.indices.push_back(baseIndex + 2);
                        mesh.indices.push_back(baseIndex + 1);
                        mesh.indices.push_back(baseIndex + 0);
                        mesh.indices.push_back(baseIndex + 3);
                        mesh.indices.push_back(baseIndex + 2);
                    }
                    ++mesh.quadCount;

                    // Clear the merged region so it is not emitted again.
                    for (int32_t j = 0; j < h; ++j) {
                        for (int32_t i = 0; i < w; ++i) {
                            const size_t mj = static_cast<size_t>(vv + j) * uCells + (uu + i);
                            maskBlock[mj] = 0;
                            maskSign[mj] = 0;
                        }
                    }

                    uu += w;
                }
            }
        }
    }

    mesh.triangleCount = static_cast<uint32_t>(mesh.indices.size() / 3);
    return mesh;
}

} // namespace Voxel
} // namespace RawrXD
