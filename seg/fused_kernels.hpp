// ============================================================================
// Fused Kernels for Maximum Performance
// ============================================================================
// Combines multiple operations to reduce memory round-trips
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace SEG {

// Fused RMSNorm + MatMul
// Computes: output = MatMul(RMSNorm(input, weight_norm), weights)
// Reduces memory traffic by avoiding separate passes
void FusedRMSNormMatMul(const float* input, const float* weight_norm,
                        const float* weights, float* output,
                        size_t N, size_t K, float eps);

// Fused Multiply + MatMul (for FFN)
// Computes: output = MatMul(activated * up, down_weights)
// where activated is already SiLU(gate) - precomputed
void FusedMultiplyMatMul(const float* activated, const float* up,
                          const float* down_weights, float* output,
                          size_t hidden, size_t intermediate);

// Fused Residual + RMSNorm
// Computes: output = RMSNorm(input + residual, weight)
void FusedResidualRMSNorm(const float* input, const float* residual,
                          const float* weight, float* output,
                          size_t size, float eps);

// Fused QKV projection with shared input
// Computes Q, K, V projections from same normalized input
// Shares the RMSNorm output across all three projections
void FusedQKVProjection(const float* input_normed,
                         const float* q_weights, const float* k_weights,
                         const float* v_weights,
                         float* q_out, float* k_out, float* v_out,
                         size_t hidden, size_t kv_hidden);

} // namespace SEG
