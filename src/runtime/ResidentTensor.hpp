// ============================================================================
// ResidentTensor.hpp — Unified execution ABI
// ============================================================================
// Common tensor descriptor consumed by both RawrXD residency and Deep2 kernels.
// No ownership semantics — borrowed pointer to resident memory.
//
// Usage:
//   WeightResidencyPool produces ResidentTensor
//   StreamRouterAdapter consumes ResidentTensor
//   FusedInferenceKernel executes against ResidentTensor
// ============================================================================
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace rawrxd {

enum class QuantType : uint8_t {
    F32   = 0,
    F16   = 1,
    Q4_0  = 2,
    Q4_1  = 3,
    Q5_0  = 4,
    Q5_1  = 5,
    Q8_0  = 6,
    Q8_1  = 7,
    Q2_K  = 8,
    Q3_K  = 9,
    Q4_K  = 10,
    Q5_K  = 11,
    Q6_K  = 12,
    Q8_K  = 13,
    IQ2_XXS = 14,
    Unknown = 255
};

struct ResidentTensor {
    uint64_t    id;           // Canonical tensor id (from model loader)
    const void* data;         // Resident memory pointer (borrowed)
    size_t      bytes;        // Size in bytes
    QuantType   quant;        // Quantization format
    uint32_t    generation;   // Residency generation (invalidation)
    uint32_t    rows;         // Logical shape: rows
    uint32_t    cols;         // Logical shape: cols
    float       scale;        // Dequantization scale (if quantized)
    float       zero_point;   // Dequantization zero point

    // Convenience: is this already FP32 resident?
    bool IsFp32Resident() const noexcept { return quant == QuantType::F32; }

    // Convenience: element count (only valid for F32)
    size_t ElementCount() const noexcept {
        return (quant == QuantType::F32) ? (bytes / sizeof(float)) : 0;
    }
};

// ---------------------------------------------------------------------------
// ExecutionRequest — unified dispatch descriptor
// ---------------------------------------------------------------------------
enum class Operation : uint8_t {
    MatMul = 0,
    Attention = 1,
    LayerNorm = 2,
    Activation = 3,
    MoERoute = 4,
    Copy = 5
};

struct ExecutionContext {
    uint32_t layer;           // Layer index
    uint32_t seq_pos;         // Sequence position (for RoPE)
    uint32_t batch_size;      // Batched prefill size
    bool     use_gpu;         // Prefer GPU path if available
    bool     use_fused;       // Prefer fused kernel if available
};

struct ExecutionRequest {
    Operation       op;
    ResidentTensor* weights;    // May be null for weightless ops
    const float*    input;
    float*          output;
    uint32_t        input_dim;
    uint32_t        output_dim;
    ExecutionContext ctx;
};

} // namespace rawrxd
