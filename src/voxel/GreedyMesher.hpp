// ============================================================================
// GreedyMesher.hpp — turning blocks into triangles.
//
// The mesher walks each chunk one axis-aligned slice at a time and, for
// every cell of the slice, decides whether a face is visible on it. The
// visible faces are then merged into the largest possible rectangles, which
// is what "greedy meshing" means: a flat field of grass becomes a handful
// of quads instead of thousands of little ones.
//
// A face is visible when the cell holds a solid block and the cell next to
// it does not hide it. Two solid blocks next to each other hide the shared
// face, which is the entire reason the interior of the world is not drawn.
// Water is a special case: it is not opaque, so it draws its own faces and
// it does not hide the faces of the blocks beside it.
//
// Every vertex carries the ambient occlusion of its corner, computed from
// the three cells that touch that corner. That is what stops a flat
// surface from looking like a flat surface.
// ============================================================================

#pragma once

#include <cstdint>
#include <vector>

namespace sunshine {

// The vertex the GPU receives.
//
// Sixteen bytes, and every one of them a float:
//
//   x, y, z        the world position of the corner
//   packed         the block type, the face index and the ambient
//                  occlusion, packed into one float
//
// The block type and the face index and the occlusion are packed into
// one number rather than carried in three floats, because a vertex of
// twelve bytes for the position and four for everything else is the
// stride that the hardware is happiest with, and because a float that
// holds a small whole number needs nothing special to be read back.
struct VoxelVertex {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    float packed = 0.0f;
};

static_assert(sizeof(VoxelVertex) == 16, "the vertex stride is part of the contract with the shader");

// The packing of the block, the face and the occlusion.
inline uint32_t packBlockAndFace(uint8_t block, uint8_t face, uint8_t occlusion) {
    return static_cast<uint32_t>(block) |
           (static_cast<uint32_t>(face) << 8) |
           (static_cast<uint32_t>(occlusion & 3U) << 16);
}

// The six faces, in a fixed order. The index is what the shader uses to
// work out the normal.
enum VoxelFace : uint8_t {
    kFacePosX = 0,
    kFaceNegX = 1,
    kFacePosY = 2,
    kFaceNegY = 3,
    kFacePosZ = 4,
    kFaceNegZ = 5,
};

// The six directions a face can point, as unit vectors.
extern const float kFaceNormal[6][3];

// The mesh of one chunk, in world coordinates.
struct ChunkMesh {
    std::vector<VoxelVertex> vertices;
    size_t triangleCount() const { return vertices.size() / 3; }
};

// The source of the blocks the mesher reads.
//
// The mesher reads across chunk borders, so the source has to answer for
// any world coordinate, not only for the chunk being meshed.
class BlockSource {
public:
    virtual ~BlockSource() = default;
    virtual uint8_t blockAt(int32_t wx, int32_t wy, int32_t wz) = 0;
};

// Build the mesh of the chunk at a chunk coordinate.
//
// `source` supplies the blocks; the chunk's own blocks and its neighbours'
// blocks are all read through it, so the borders are correct.
ChunkMesh meshChunk(BlockSource& source, int32_t chunkX, int32_t chunkZ);

} // namespace sunshine
