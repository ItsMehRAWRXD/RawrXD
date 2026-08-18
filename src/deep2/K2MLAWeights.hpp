// ============================================================================
// K2MLAWeights.hpp — K2-002 MLA Tensor Schema
//
// CORRECTION: kv_a_mqa output is NOT a single 576-dim latent.
// It splits into:
//   compressed_kv[512] → RMSNorm → kv_b → K_nope + V
//   k_pe[64]          → RoPE    → K_pe
// Final K = K_nope + K_pe (concatenation/combination per checkpoint)
//
// Reference: Kimi K2 0905 config.json
//   kv_lora_rank=512, qk_rope_head_dim=64, qk_nope_head_dim=128, v_head_dim=128
// ============================================================================
#pragma once
#include "KimiK2Config.hpp"
#include "TensorView.hpp"
#include <cstdint>
#include <string>

namespace Deep2 {

// Forward declaration
class GlobalTensorIndex;

// ============================================================================
// MLAWeights — Factorized Multi-head Latent Attention tensors
//
// Q-path:  hidden → q_a → RMSNorm → q_b → Q
// KV-path: hidden → kv_a_mqa → split → [compressed_kv | k_pe]
//           compressed_kv → RMSNorm → kv_b → K_nope + V
//           k_pe → RoPE → K_pe
// ============================================================================
struct MLAWeights {
    // --- Q-path tensors ---
    RawrXD::TensorView attnQ_a;           // [hiddenDim, qLoraRank]      — latent Q projection
    RawrXD::TensorView attnQ_a_norm;      // [qLoraRank]                 — RMSNorm scale
    RawrXD::TensorView attnQ_b;           // [qLoraRank, numHeads * qkNopeHeadDim]
                                          //   OR [qLoraRank, numHeads * (qkNopeHeadDim + qkRopeHeadDim)]

    // --- KV-path tensors ---
    RawrXD::TensorView attnKV_a_mqa;      // [hiddenDim, kvLoraRank + qkRopeHeadDim]
                                          //   = [hiddenDim, 576] for K2 0905
    RawrXD::TensorView attnKV_a_norm;     // [kvLoraRank]                — RMSNorm scale (applied to compressed_kv only)
    RawrXD::TensorView attnK_b;           // [kvLoraRank, numHeads * qkNopeHeadDim] — K_nope projection
    RawrXD::TensorView attnV_b;           // [kvLoraRank, numHeads * vHeadDim]     — V projection

    // --- Attention output ---
    RawrXD::TensorView attnO;             // [numHeads * vHeadDim, hiddenDim]

    // --- Norm tensors ---
    RawrXD::TensorView attnNorm;          // [hiddenDim]                 — pre-attention RMSNorm

    // =========================================================================
    // Validation: check all required tensors are present
    // =========================================================================
    bool Validate(const KimiK2Config& config, std::string& error) const;

    // =========================================================================
    // Resolve tensors from a GlobalTensorIndex for a specific layer
    // =========================================================================
    bool ResolveFromTensorIndex(const GlobalTensorIndex& index, uint32_t layer, std::string& error);

    // =========================================================================
    // Resolve AND load actual tensor data from shards into TensorViews.
    // This is what Execute() needs — metadata-only views will fail.
    // Returns total bytes loaded. On failure, error is set and returns 0.
    // =========================================================================
    uint64_t ResolveAndLoad(const GlobalTensorIndex& index, uint32_t layer,
                            std::string& error);

    // =========================================================================
    // Release all loaded tensor data (free aligned buffers).
    // Call after Execute() to stay under budget.
    // =========================================================================
    void ReleaseAll();

    // =========================================================================
    // Tensor presence detection (for architecture auto-detection)
    // =========================================================================
    static bool DetectMLA(const std::string& tensorName);
};

// ============================================================================
// MLAForward — Standalone MLA operator (NOT forced through generic MatMul)
//
// Inputs:
//   hidden          — [batch, hiddenDim]
//   weights         — MLAWeights (factorized projections)
//   kvCache         — Compressed KV cache (MLA format)
//   position        — Token positions for RoPE
//
// Outputs:
//   output          — [batch, hiddenDim]
//
// Internal:
//   Q  = hidden → q_a → norm → q_b
//   KV = hidden → kv_a_mqa → split → [compressed_kv | k_pe]
//   compressed_kv → norm → kv_b → [K_nope | V]
//   k_pe → RoPE → K_pe
//   K = combine(K_nope, K_pe)
//   output = Attention(Q, K, V) → attnO
// ============================================================================
struct MLAForward {
    // Forward pass — returns false on error with message in error
    bool Execute(const float* hidden, float* output,
                 const MLAWeights& weights,
                 const KimiK2Config& config,
                 std::string& error);

    // Standalone test: compare against deterministic reference fixture
    // Used for K2-003 validation gate
    static bool TestAgainstReference(const std::string& fixturePath,
                                      std::string& error);
};

} // namespace Deep2
