// K2MLA_KvExpand_Fused.hpp — Fused K+V LoRA GEMV for MLA KV expand
// Reads compressedKV once, writes both K_nope and V in a single pass.
// ~2x memory bandwidth reduction vs separate K-expand + V-expand.
//
// Usage:
//   MLA_KvExpand_Fused(kBase, vBase, compressedKV, kOut, vOut,
//                      numHeads, qkNopeHeadDim, vHeadDim, kvLoraRank,
//                      kQuantType, vQuantType);
//
// Compile flags:
//   MSVC: /arch:AVX2 (or /arch:AVX512 for wider path)
//   GCC/Clang: -mavx2 -mfma
// ============================================================================
#pragma once
#include <cstddef>
#include <cstdint>

namespace Deep2 {

// Quant type enum matching RawrXD::QuantType values
enum class KvExpandQuantType : uint8_t {
    F32 = 0,
    Q4_K = 12,
    Q8_0 = 8,
};

// ============================================================================
// Fused K+V expand from compressed KV latent.
//
// Inputs:
//   kWeights, vWeights  — packed quantized weight blocks (per-head contiguous)
//   compressedKV        — [kvLoraRank] FP32 latent (read once)
//   kOut                — [numHeads * qkNopeHeadDim] FP32 output
//   vOut                — [numHeads * vHeadDim] FP32 output
//   numHeads            — number of attention heads
//   qkNopeHeadDim       — per-head K_nope dimension
//   vHeadDim            — per-head V dimension
//   kvLoraRank          — compressed KV rank (input dimension)
//   kQuantType          — quantization type of K weights
//   vQuantType          — quantization type of V weights
//
// Returns:
//   true on success, false on unsupported config
// ============================================================================
bool MLA_KvExpand_Fused(
    const void* kWeights,
    const void* vWeights,
    const float* compressedKV,
    float* kOut,
    float* vOut,
    size_t numHeads,
    size_t qkNopeHeadDim,
    size_t vHeadDim,
    size_t kvLoraRank,
    KvExpandQuantType kQuantType,
    KvExpandQuantType vQuantType);

// ============================================================================
// Fused K+V expand with pre-fused KV weights (DeepSeek-R1 style attn_kv_b).
// Single weight tensor produces both K and V via split.
//
// Inputs:
//   fusedWeights        — packed quantized [kvLoraRank, numHeads*(nope+v)]
//   compressedKV        — [kvLoraRank] FP32 latent
//   kOut                — [numHeads * qkNopeHeadDim] FP32
//   vOut                — [numHeads * vHeadDim] FP32
//   numHeads, qkNopeHeadDim, vHeadDim, kvLoraRank
//   quantType           — quantization type of fused weights
//
// Returns:
//   true on success
// ============================================================================
bool MLA_KvExpand_Fused_SingleWeight(
    const void* fusedWeights,
    const float* compressedKV,
    float* kOut,
    float* vOut,
    size_t numHeads,
    size_t qkNopeHeadDim,
    size_t vHeadDim,
    size_t kvLoraRank,
    KvExpandQuantType quantType);

// ============================================================================
// Runtime capability query
// ============================================================================
bool MLA_KvExpand_Fused_Available();

} // namespace Deep2
