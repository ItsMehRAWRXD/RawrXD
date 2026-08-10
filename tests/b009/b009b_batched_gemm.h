// ============================================================================
// B009-B Batched GEMM Interface — Performance Path Scaffold
// ============================================================================
//
// PURPOSE:
//   Defines the batched GEMM interface that B009-B will implement to realize
//   performance improvements over B009-A's per-token matmuls.
//
//   Current state: STUB — all batched operations fall back to per-token
//   ExecuteLayerMatMul calls. This preserves correctness while the batched
//   kernel is being developed.
//
//   When batched GEMM is ready, replace the stub implementations with
//   actual batched matrix multiplication (e.g., via oneDNN, OpenBLAS, or
//   custom AVX-512 batched kernels).
//
// ============================================================================

#ifndef B009B_BATCHED_GEMM_H
#define B009B_BATCHED_GEMM_H

#include <cstdint>
#include <vector>
#include <string>

// Forward declaration at global scope
class RawrXDTransformer;

namespace RawrXD::B009B {

// ============================================================================
// Batched GEMM Context
// ============================================================================
// Holds per-batch pointers and dimensions for a single batched matmul.
// All pointers must be contiguous in the batch dimension (T).
struct BatchedGemmDesc {
    const float* A;           // [T x M x K] or [T x K] if M=1
    const float* B;           // [K x N] weight matrix (shared across batch)
    float* C;                 // [T x M x N] output
    int T;                    // batch size (number of tokens)
    int M;                    // rows per batch item (usually 1 for token-outer)
    int K;                    // inner dimension
    int N;                    // output dimension
    const char* weightName;   // for weight lookup / telemetry
    uint32_t layer;           // layer index for layer-specific weights
};

// ============================================================================
// Batched Operation Interface
// ============================================================================

/// Batched QKV projection: compute Q, K, V for all tokens in a single operation.
/// Input:  hidden[T x dim]
/// Output: q[T x dim], k[T x kv_dim], v[T x kv_dim]
/// Weights: attn_q.weight[dim x dim], attn_k.weight[dim x kv_dim], attn_v.weight[dim x kv_dim]
bool BatchedQKVProjection(
    RawrXDTransformer* transformer,
    const float* hidden, float* q, float* k, float* v,
    int T, int dim, int kv_dim, uint32_t layer);

/// Batched FFN SwiGLU: compute gate and up projections for all tokens.
/// Input:  x[T x dim]
/// Output: gate[T x hidden_dim], up[T x hidden_dim]
/// Weights: ffn_gate.weight[dim x hidden_dim], ffn_up.weight[dim x hidden_dim]
bool BatchedFFNGateUp(
    RawrXDTransformer* transformer,
    const float* x, float* gate, float* up,
    int T, int dim, int hidden_dim, uint32_t layer);

/// Batched FFN down projection: compute down projection for all tokens.
/// Input:  activated[T x hidden_dim] (already SiLU(gate) * up)
/// Output: out[T x dim]
/// Weights: ffn_down.weight[hidden_dim x dim]
bool BatchedFFNDown(
    RawrXDTransformer* transformer,
    const float* activated, float* out,
    int T, int hidden_dim, int dim, uint32_t layer);

/// Batched output projection: compute logits for all token positions.
/// Input:  final_x[T x dim] (after final norm)
/// Output: logits[T x vocab_size]
/// Weights: output.weight[dim x vocab_size]
bool BatchedOutputProjection(
    RawrXDTransformer* transformer,
    const float* final_x, float* logits,
    int T, int dim, int vocab_size);

// ============================================================================
// Telemetry
// ============================================================================
struct BatchedGemmTelemetry {
    uint64_t batched_qkv_calls = 0;
    uint64_t batched_ffn_gateup_calls = 0;
    uint64_t batched_ffn_down_calls = 0;
    uint64_t batched_output_calls = 0;
    uint64_t fallback_per_token_calls = 0;  // when batched path falls back
    double total_batched_ms = 0.0;
    double total_fallback_ms = 0.0;
};

extern BatchedGemmTelemetry g_batched_gemm_telemetry;

} // namespace RawrXD::B009B

#endif // B009B_BATCHED_GEMM_H
