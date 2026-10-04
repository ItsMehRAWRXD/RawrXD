// RAWRXD_SOVEREIGN_KERNEL_VECTORDISPATCH_H
// C++ wrapper for Sovereign Kernel Vector Dispatch (x64 AVX-512 assembly)

#pragma once
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// Dispatch context for skvd_dispatch_loop
#pragma pack(push, 1)
typedef struct {
    const float* tensor_base_a;
    const float* tensor_base_b;
    float*       tensor_base_c;
    uint64_t     stride_a;
    uint64_t     stride_b;
    uint64_t     stride_c;
    uint16_t     lane_mask;
    uint16_t     reserved;
} skvd_dispatch_context_t;
#pragma pack(pop)

// Tensor shape for stride resolver
typedef struct {
    uint32_t rank;
    uint64_t strides[8]; // max 8 dimensions
} skvd_tensor_shape_t;

// ---------------------------------------------------------------------------
// Assembly entry points
// ---------------------------------------------------------------------------

// 1-cycle dispatch loop skeleton
//   ctx = dispatch context with tensor bases and strides
//   iterations = number of FMA tiles to process
// Returns: cycles_elapsed (approximate, = iterations executed)
uint64_t skvd_dispatch_loop(skvd_dispatch_context_t* ctx, uint64_t iteration_count);

// SIMD lane binding initializer
//   lane_enable_mask = 16-bit mask (bit i = lane i enabled)
//   out_lane_bindings = 16 x uint64_t array
void skvd_lane_bind(uint16_t lane_enable_mask, uint64_t* out_lane_bindings);

// Tensor stride resolver
//   shape = tensor dimensions and strides
//   indices = one index per dimension
//   out_byte_offset = computed byte offset result
void skvd_stride_resolve(const skvd_tensor_shape_t* shape, const uint32_t* indices, uint64_t* out_byte_offset);

// Fused multiply-add pipeline (batch of 4 FMAs per tile)
//   a, b = input tiles (ZMM-aligned, float32)
//   c = accumulator output (ZMM-aligned, 64 bytes)
//   count = number of 16-float tiles
void skvd_fma_pipeline(const float* a, const float* b, float* c, uint64_t count);

// ---------------------------------------------------------------------------
// High-level C++ wrapper (type-safe)
// ---------------------------------------------------------------------------
#ifdef __cplusplus
} // extern "C"

namespace rawrxd::asm_core {

class SovereignVectorDispatch {
public:
    // Initialize with lane mask (default: all 16 lanes enabled)
    explicit SovereignVectorDispatch(uint16_t lane_mask = 0xFFFF);

    // Bind tensors and run dispatch loop
    // Returns approximate cycles taken
    uint64_t dispatch(const float* a, const float* b, float* c,
                      uint64_t stride_a, uint64_t stride_b, uint64_t stride_c,
                      uint64_t iterations);

    // Resolve tensor offset from multi-dimensional indices
    static uint64_t resolveOffset(const skvd_tensor_shape_t& shape,
                                   const uint32_t* indices);

    // Batch FMA pipeline (4 tiles per inner loop)
    void fmaPipeline(const float* a, const float* b, float* c, uint64_t tile_count);

private:
    uint16_t lane_mask_;
    uint64_t lane_bindings_[16];
    skvd_dispatch_context_t ctx_;
};

} // namespace rawrxd::asm_core

#endif // __cplusplus
