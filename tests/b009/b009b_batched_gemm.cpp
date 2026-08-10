// ============================================================================
// B009-B Batched GEMM Implementation — STUB (falls back to per-token matmuls)
// ============================================================================
//
// PURPOSE:
//   Stub implementation of batched GEMM operations. All functions fall back
//   to per-token ExecuteLayerMatMul calls, preserving B009-A correctness.
//
//   When batched kernels are ready, replace these stubs with actual
//   batched matrix multiplication.
//
// ============================================================================

#include "b009b_batched_gemm.h"
#include "rawrxd_transformer.h"
#include <cstdio>

namespace RawrXD::B009B {

BatchedGemmTelemetry g_batched_gemm_telemetry{};

// ============================================================================
// Batched QKV Projection (STUB)
// ============================================================================
bool BatchedQKVProjection(
    RawrXDTransformer* transformer,
    const float* hidden, float* q, float* k, float* v,
    int T, int dim, int kv_dim, uint32_t layer)
{
    if (!transformer || T <= 0 || dim <= 0) return false;

    const std::string prefix = "blk." + std::to_string(layer) + ".";
    bool ok = true;

    for (int t = 0; t < T; ++t) {
        const float* xt = hidden + static_cast<size_t>(t) * dim;
        float* qt = q + static_cast<size_t>(t) * dim;
        float* kt = k + static_cast<size_t>(t) * kv_dim;
        float* vt = v + static_cast<size_t>(t) * kv_dim;

        ok = ok && transformer->ExecuteLayerMatMul(prefix + "attn_q.weight", xt, qt, dim, dim, layer);
        ok = ok && transformer->ExecuteLayerMatMul(prefix + "attn_k.weight", xt, kt, dim, kv_dim, layer);
        ok = ok && transformer->ExecuteLayerMatMul(prefix + "attn_v.weight", xt, vt, dim, kv_dim, layer);
    }

    if (ok) {
        ++g_batched_gemm_telemetry.batched_qkv_calls;
    } else {
        ++g_batched_gemm_telemetry.fallback_per_token_calls;
    }
    return ok;
}

// ============================================================================
// Batched FFN Gate+Up (STUB)
// ============================================================================
bool BatchedFFNGateUp(
    RawrXDTransformer* transformer,
    const float* x, float* gate, float* up,
    int T, int dim, int hidden_dim, uint32_t layer)
{
    if (!transformer || T <= 0 || dim <= 0) return false;

    const std::string prefix = "blk." + std::to_string(layer) + ".ffn_";
    bool ok = true;

    for (int t = 0; t < T; ++t) {
        const float* xt = x + static_cast<size_t>(t) * dim;
        float* gt = gate + static_cast<size_t>(t) * hidden_dim;
        float* ut = up + static_cast<size_t>(t) * hidden_dim;

        ok = ok && transformer->ExecuteLayerMatMul(prefix + "gate.weight", xt, gt, dim, hidden_dim, layer);
        ok = ok && transformer->ExecuteLayerMatMul(prefix + "up.weight", xt, ut, dim, hidden_dim, layer);
    }

    if (ok) {
        ++g_batched_gemm_telemetry.batched_ffn_gateup_calls;
    } else {
        ++g_batched_gemm_telemetry.fallback_per_token_calls;
    }
    return ok;
}

// ============================================================================
// Batched FFN Down (STUB)
// ============================================================================
bool BatchedFFNDown(
    RawrXDTransformer* transformer,
    const float* activated, float* out,
    int T, int hidden_dim, int dim, uint32_t layer)
{
    if (!transformer || T <= 0 || hidden_dim <= 0) return false;

    const std::string prefix = "blk." + std::to_string(layer) + ".ffn_";
    bool ok = true;

    for (int t = 0; t < T; ++t) {
        const float* at = activated + static_cast<size_t>(t) * hidden_dim;
        float* ot = out + static_cast<size_t>(t) * dim;

        ok = ok && transformer->ExecuteLayerMatMul(prefix + "down.weight", at, ot, hidden_dim, dim, layer);
    }

    if (ok) {
        ++g_batched_gemm_telemetry.batched_ffn_down_calls;
    } else {
        ++g_batched_gemm_telemetry.fallback_per_token_calls;
    }
    return ok;
}

// ============================================================================
// Batched Output Projection (STUB)
// ============================================================================
bool BatchedOutputProjection(
    RawrXDTransformer* transformer,
    const float* final_x, float* logits,
    int T, int dim, int vocab_size)
{
    if (!transformer || T <= 0 || dim <= 0) return false;

    // For now, only compute logits for the last token (same contract as Forward)
    // When fully batched, this should compute all T positions.
    const float* last_x = final_x + static_cast<size_t>(T - 1) * dim;
    bool ok = transformer->ExecuteLayerMatMul("output.weight", last_x, logits, dim, vocab_size,
                                                  static_cast<uint32_t>(std::max(0, 28))); // layer=28 for output

    if (ok) {
        ++g_batched_gemm_telemetry.batched_output_calls;
    } else {
        ++g_batched_gemm_telemetry.fallback_per_token_calls;
    }
    return ok;
}

} // namespace RawrXD::B009B
