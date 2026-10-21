// ============================================================================
// VoxelRasterizer.hpp - the software reference rasterizer.
//
// WHY THIS EXISTS
// ---------------
// The DX12 path in VoxelRenderer is the production renderer. It cannot be
// executed on the current build host: every ID3D12Device view creation
// (CreateRenderTargetView, CreateDepthStencilView, CreateUnorderedAccessView)
// removes the device with DXGI_ERROR_INVALID_CALL (0x887A0001) on BOTH the
// AMD Radeon AI PRO R9700 and the WARP software adapter, while device,
// queue, allocator, command list, fence, descriptor heap and committed
// resource creation all succeed. That is a host D3D12 runtime fault, and
// tools/voxel_probe.cpp reproduces it in three lines.
//
// A renderer that cannot be executed cannot be certified, and a certification
// that only proves "it compiled" is exactly the kind of claim this project
// refuses to make. So the module carries a second, fully first-party
// rasterizer that produces the SAME frame the DX12 path would produce:
//
//   * the same camera matrices (Math3D.hpp), the same 32-byte vertex layout,
//   * the same lighting model as the HLSL in VoxelShaders.hpp (hemispheric
//     ambient, sun diffuse, per-corner ambient occlusion, distance fog),
//   * the same RGBA8 output, tightly packed, with the same row pitch.
//
// It has two jobs. It makes the frame-capture and vision contracts testable
// today. And it is a golden reference: when the host's D3D12 runtime is
// fixed, the GPU frame can be diffed against this one.
//
// This is a fallback and a reference, not a replacement: the DX12 path stays
// the renderer of record.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Math3D.hpp"
#include "VoxelMesher.hpp"

namespace RawrXD {
namespace Voxel {

// Rasterizes the given chunk meshes into a tightly packed RGBA8 frame.
// Returns false only on an invalid argument (no camera, zero size).
bool RasterizeFrame(const std::vector<const ChunkMesh*>& meshes,
                    const VoxelCamera& camera,
                    uint32_t width,
                    uint32_t height,
                    std::vector<uint8_t>& rgba,
                    std::string* error = nullptr);

} // namespace Voxel
} // namespace RawrXD
