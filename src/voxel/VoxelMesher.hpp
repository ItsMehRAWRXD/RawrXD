// ============================================================================
// VoxelMesher.hpp - greedy voxel meshing with cross-chunk culling.
//
// The mesher asks the WORLD about every neighbour it needs, including the
// blocks one (and two, for ambient occlusion) outside the chunk. That is what
// removes the internal faces that a chunk-local mesher would emit at every
// chunk boundary.
//
// Greedy meshing merges coplanar faces of the same block into one quad, so a
// flat 16x16 grass field is 1 quad rather than 256.
// ============================================================================

#pragma once

#include <cstdint>
#include <vector>

#include "VoxelWorld.hpp"

namespace RawrXD {
namespace Voxel {

// 32-byte vertex. The stride is a power of two and every field is naturally
// aligned, so the D3D12 vertex buffer view can advertise exactly 32.
struct VoxelVertex {
    float px = 0.0f;
    float py = 0.0f;
    float pz = 0.0f;
    float nx = 0.0f;
    float ny = 0.0f;
    float nz = 0.0f;
    uint32_t color = 0xFFFFFFFFu;  // packed RGBA8
    uint32_t blockAo = 0u;         // block type (bits 0..7) | this corner's AO (bits 8..9)
};
static_assert(sizeof(VoxelVertex) == 32, "VoxelVertex must be exactly 32 bytes.");

struct ChunkMesh {
    std::vector<VoxelVertex> vertices;
    std::vector<uint32_t> indices;
    uint32_t faceCount = 0;      // quads before merging
    uint32_t quadCount = 0;      // quads actually emitted
    uint32_t triangleCount = 0;
};

// Greedy-meshes one chunk of the world. The mesh is in world space.
ChunkMesh MeshChunk(const VoxelWorld& world, int32_t chunkX, int32_t chunkZ);

// The colour table the mesher uses. Kept next to the mesher so the palette
// and the geometry can never drift apart.
uint32_t BlockColor(BlockType type);

} // namespace Voxel
} // namespace RawrXD
