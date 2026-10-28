// ============================================================================
// GreedyMesher.cpp — the mesher.
//
// The algorithm is the usual one: for each of the three axes, walk the
// chunk one slice at a time, build a mask of the faces that are visible in
// that slice, and then merge the mask into the largest rectangles that
// share a block type and a face direction.
//
// The ambient occlusion is computed from the position of the vertex rather
// than from the cell it came from. That matters: a vertex on the border
// between two cells is the same vertex for both of them, and computing the
// occlusion from the position means the two cells agree about it. A cell
// based calculation would put a lighting seam down the middle of every
// merged rectangle.
// ============================================================================

#include "GreedyMesher.hpp"

#include <algorithm>
#include <cmath>

#include "Block.hpp"
#include "ChunkStore.hpp"

namespace sunshine {

const float kFaceNormal[6][3] = {
    { 1.0f, 0.0f, 0.0f},  // +X
    {-1.0f, 0.0f, 0.0f},  // -X
    { 0.0f, 1.0f, 0.0f},  // +Y
    { 0.0f,-1.0f, 0.0f},  // -Y
    { 0.0f, 0.0f, 1.0f},  // +Z
    { 0.0f, 0.0f,-1.0f},  // -Z
};

namespace {

// One cell of the mask: the face that is drawn there, if any.
struct MaskEntry {
    uint8_t block = 0;
    uint8_t face = 0;
    bool valid = false;
};

bool sameFace(const MaskEntry& a, const MaskEntry& b) {
    return a.valid && b.valid && a.block == b.block && a.face == b.face;
}

// Whether a face of `cell` is drawn against `neighbour`.
//
//   * air has no faces
//   * an opaque neighbour hides the face entirely, which is what removes
//     the interior of the world
//   * two water blocks hide each other, so a lake has only its surface
bool drawsFace(uint8_t cell, uint8_t neighbour) {
    if (cell == kBlockAir) return false;
    if (isOpaque(static_cast<BlockType>(neighbour))) return false;
    if (cell == static_cast<uint8_t>(BlockType::Water)) {
        return neighbour != static_cast<uint8_t>(BlockType::Water);
    }
    return true;
}

// Whether a block hides the light around a corner.
bool occludes(uint8_t block) {
    return isSolid(static_cast<BlockType>(block));
}

} // namespace

ChunkMesh meshChunk(BlockSource& source, int32_t chunkX, int32_t chunkZ) {
    ChunkMesh mesh;

    const int32_t ox = chunkX * kChunkSize;
    const int32_t oz = chunkZ * kChunkSize;

    // The extents of the chunk along each axis.
    const int32_t extent[3] = {kChunkSize, kChunkHeight, kChunkSize};

    // For the axis being swept, the other two axes are the mask axes.
    // The table below gives, for each swept axis, the index of the first
    // mask axis and the second, and the world base of each.
    //
    //   swept 0 (X): mask axes are Y and Z
    //   swept 1 (Y): mask axes are Z and X
    //   swept 2 (Z): mask axes are X and Y
    static const int kMaskAxis[3][2] = {{1, 2}, {2, 0}, {0, 1}};

    for (int d = 0; d < 3; ++d) {
        const int uAxis = kMaskAxis[d][0];
        const int vAxis = kMaskAxis[d][1];
        const int32_t uExtent = extent[uAxis];
        const int32_t vExtent = extent[vAxis];

        // The world base of the mask axes.
        int32_t uBase = 0;
        int32_t vBase = 0;
        if (uAxis == 0) uBase = ox;
        else if (uAxis == 2) uBase = oz;
        if (vAxis == 0) vBase = ox;
        else if (vAxis == 2) vBase = oz;

        std::vector<MaskEntry> mask(static_cast<size_t>(uExtent) * vExtent);

        // The world coordinate of the cell that owns a mask cell.
        const auto cellWorld = [&](int32_t slice, int32_t u, int32_t v, int32_t out[3]) {
            const int32_t s = (d == 0) ? ox + slice : (d == 1) ? slice : oz + slice;
            const int32_t uu = uBase + u;
            const int32_t vv = vBase + v;
            if (d == 0)      { out[0] = s; out[1] = uu; out[2] = vv; }
            else if (d == 1) { out[0] = vv; out[1] = s; out[2] = uu; }
            else             { out[0] = uu; out[1] = vv; out[2] = s; }
        };

        // The world coordinate of a face corner.
        const auto cornerWorld = [&](int32_t slice, int32_t cornerU, int32_t cornerV,
                                     int32_t positive, int32_t out[3]) {
            int32_t cell[3];
            cellWorld(slice, 0, 0, cell);
            const int32_t plane = cell[d] + (positive ? 1 : 0);
            int32_t w[3];
            w[d] = plane;
            w[uAxis] = cornerU;
            w[vAxis] = cornerV;
            out[0] = w[0];
            out[1] = w[1];
            out[2] = w[2];
        };

        for (int32_t slice = 0; slice < extent[d]; ++slice) {
            std::fill(mask.begin(), mask.end(), MaskEntry{});

            // Build the mask of this slice.
            for (int32_t v = 0; v < vExtent; ++v) {
                for (int32_t u = 0; u < uExtent; ++u) {
                    int32_t a[3];
                    cellWorld(slice, u, v, a);
                    int32_t b[3];
                    cellWorld(slice + 1, u, v, b);

                    const uint8_t blockA = source.blockAt(a[0], a[1], a[2]);
                    const uint8_t blockB = source.blockAt(b[0], b[1], b[2]);

                    MaskEntry& entry = mask[static_cast<size_t>(u) * vExtent + v];

                    if (drawsFace(blockA, blockB)) {
                        // The face sits on the side of A that points along +d.
                        entry.block = blockA;
                        entry.face = static_cast<uint8_t>(d * 2);
                        entry.valid = true;
                    } else if (drawsFace(blockB, blockA)) {
                        // The face sits on the side of B that points along -d.
                        entry.block = blockB;
                        entry.face = static_cast<uint8_t>(d * 2 + 1);
                        entry.valid = true;
                    }
                }
            }

            // Merge the mask into rectangles and emit them.
            for (int32_t v = 0; v < vExtent; ++v) {
                for (int32_t u = 0; u < uExtent; ++u) {
                    const size_t index = static_cast<size_t>(u) * vExtent + v;
                    if (!mask[index].valid) continue;

                    const MaskEntry seed = mask[index];

                    // How far the rectangle runs along u.
                    int32_t width = 1;
                    while (u + width < uExtent &&
                           sameFace(mask[static_cast<size_t>(u + width) * vExtent + v], seed)) {
                        ++width;
                    }

                    // And how far it runs along v.
                    int32_t height = 1;
                    while (v + height < vExtent) {
                        bool ok = true;
                        for (int32_t k = 0; k < width; ++k) {
                            if (!sameFace(mask[static_cast<size_t>(u + k) * vExtent + v + height], seed)) {
                                ok = false;
                                break;
                            }
                        }
                        if (!ok) break;
                        ++height;
                    }

                    // The four corners of the rectangle, in the world.
                    const bool positive = (seed.face % 2) == 0;
                    const int32_t faceAxis = seed.face / 2;

                    int32_t c00[3], c10[3], c11[3], c01[3];
                    cornerWorld(slice, uBase + u, vBase + v, positive, c00);
                    cornerWorld(slice, uBase + u + width, vBase + v, positive, c10);
                    cornerWorld(slice, uBase + u + width, vBase + v + height, positive, c11);
                    cornerWorld(slice, uBase + u, vBase + v + height, positive, c01);

                    // The occlusion of each corner, from the three cells
                    // that touch it on the outside of the face.
                    const float* normal = kFaceNormal[seed.face];
                    const int32_t nAxis = faceAxis;

                    // The two axes of the face that are not its normal.
                    const int32_t t1 = (nAxis + 1) % 3;
                    const int32_t t2 = (nAxis + 2) % 3;

                    const auto cornerAo = [&](const int32_t corner[3], int32_t su, int32_t sv) -> uint8_t {
                        int32_t p1[3] = {corner[0], corner[1], corner[2]};
                        p1[nAxis] += normal[nAxis] > 0 ? 1 : -1;
                        p1[t1] += su;
                        int32_t p2[3] = {corner[0], corner[1], corner[2]};
                        p2[nAxis] += normal[nAxis] > 0 ? 1 : -1;
                        p2[t2] += sv;
                        int32_t p3[3] = {p1[0], p1[1], p1[2]};
                        p3[t2] += sv;

                        const bool s1 = occludes(source.blockAt(p1[0], p1[1], p1[2]));
                        const bool s2 = occludes(source.blockAt(p2[0], p2[1], p2[2]));
                        const bool sc = occludes(source.blockAt(p3[0], p3[1], p3[2]));

                        if (s1 && s2) return 0;
                        const int32_t lit = 3 - (static_cast<int32_t>(s1) + static_cast<int32_t>(s2) +
                                                 static_cast<int32_t>(sc));
                        return static_cast<uint8_t>(lit < 0 ? 0 : (lit > 3 ? 3 : lit));
                    };

                    // The sign of the offset for each corner, along the two
                    // face axes. The corner at the low edge of the cell
                    // looks towards -1, the one at the high edge towards
                    // +1.
                    const int32_t su0 = -1, su1 = 1;
                    const int32_t sv0 = -1, sv1 = 1;

                    const uint8_t ao00 = cornerAo(c00, su0, sv0);
                    const uint8_t ao10 = cornerAo(c10, su1, sv0);
                    const uint8_t ao11 = cornerAo(c11, su1, sv1);
                    const uint8_t ao01 = cornerAo(c01, su0, sv1);

                    const auto emit = [&](const int32_t pos[3], uint8_t ao) {
                        VoxelVertex vert;
                        vert.x = static_cast<float>(pos[0]);
                        vert.y = static_cast<float>(pos[1]);
                        vert.z = static_cast<float>(pos[2]);
                        vert.packed = static_cast<float>(
                            packBlockAndFace(seed.block, seed.face, ao));
                        mesh.vertices.push_back(vert);
                    };

                    // Two triangles.
                    emit(c00, ao00); emit(c10, ao10); emit(c11, ao11);
                    emit(c00, ao00); emit(c11, ao11); emit(c01, ao01);

                    // Clear the rectangle from the mask.
                    for (int32_t dv = 0; dv < height; ++dv) {
                        for (int32_t du = 0; du < width; ++du) {
                            mask[static_cast<size_t>(u + du) * vExtent + v + dv] = MaskEntry{};
                        }
                    }
                }
            }
        }
    }

    return mesh;
}

} // namespace sunshine
