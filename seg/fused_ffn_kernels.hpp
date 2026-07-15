// ============================================================================
// Fused FFN Kernels
// ============================================================================
// Combines multiple operations to reduce memory round-trips
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>

namespace SEG {

// Fused SiLU + Multiply + Down Projection
// Computes: output = (silu(gate) * up) @ down_weights
// Reduces memory bandwidth by avoiding intermediate storage
void FusedSiLUMulDownProj(const float* gate, const float* up,
                          const float* down_weights,
                          float* output,
                          size_t hidden, size_t intermediate);

// Fused RMSNorm + MatMul
// Computes: output = RMSNorm(input) @ weights
// Reduces memory round-trips
void FusedRMSNormMatMul(const float* input, const float* norm_weights,
                        const float* matmul_weights,
                        float* output,
                        size_t hidden, size_t output_dim,
                        float eps);

} // namespace SEG
