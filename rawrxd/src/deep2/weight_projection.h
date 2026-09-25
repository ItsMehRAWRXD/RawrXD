#pragma once
// ============================================================================
// weight_projection.h — AVX-512 host-staged weight upload + GEMV dispatch
// Uses Deep2::VulkanCompute and Deep2::GGUFTensor directly.
// Staging path: double-buffered MaterialTicket (SubmitMaterialUploadAsync /
// WaitMaterialUpload). No separate Vulkan init — caller owns VulkanCompute.
// ============================================================================
#include <cstdint>
#include <cstddef>
#include <immintrin.h>

#include "vulkan_compute.h"
#include "GGUFLoader.hpp"

namespace Deep2 {

struct ProjectionConfig {
    uint32_t rows;           // output rows  (e.g. out_features)
    uint32_t cols;           // input cols   (e.g. in_features)
    float    scale{1.0f};
    float    bias{0.0f};
    // Chunk size in bytes for double-buffered staging (default 16 MB).
    size_t   chunkBytes{16ull * 1024 * 1024};
};

// Streams a GGUFTensor's raw bytes through AVX-512 non-temporal FMA
// pre-processing into device-local VRAM via double-buffered MaterialTickets.
// The caller must have already called VulkanCompute::initialize().
// On success the weight is resident in the VulkanCompute weight cache under
// cacheKey and can be dispatched via DispatchGemvQuant / DispatchWeight.
bool WeightProjectionUpload(
    VulkanCompute&       gpu,
    const GGUFTensor&    tensor,
    const ProjectionConfig& cfg,
    uint64_t             cacheKey,
    uint64_t             epoch);

// Applies scale+bias via AVX-512 FMA with non-temporal stores into dst.
// dst must be 64-byte aligned. Falls back to scalar for the tail.
// src is the raw mmap'd tensor bytes reinterpreted as float (F32 tensors only).
void WeightProjectionTransformF32(
    const float* __restrict src,
    float*       __restrict dst,
    size_t                  count,
    float                   scale,
    float                   bias) noexcept;

} // namespace Deep2
