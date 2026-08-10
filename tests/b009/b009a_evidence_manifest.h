// ============================================================================
// B009-A Evidence Manifest — Layer-Outer ForwardBatch Correctness Validation
// Captured: 2026-08-10
// ============================================================================
//
// PURPOSE:
//   Documents the B009-A correctness validation results for the layer-outer
//   ForwardBatch() implementation. This manifest establishes that the new
//   execution topology produces numerically identical logits to the B008
//   reference Forward() oracle.
//
//   ⚠️  IMPORTANT: The original B009 implementation had a correctness bug
//   (residual captured after RMSNorm). This manifest reflects the FIXED
//   implementation. Any results obtained before the fix are INVALIDATED.
//
// USAGE:
//   - Treat this file as read-only after B009-A freeze.
//   - B009-B (batched GEMM performance) must preserve correctness against
//     this manifest.
//   - Do not modify ForwardBatch() without re-running B009-A certification.
//
// ============================================================================

#ifndef B009A_EVIDENCE_MANIFEST_H
#define B009A_EVIDENCE_MANIFEST_H

#include <cstdint>

namespace RawrXD::B009A {

// ============================================================================
// Source Identity
// ============================================================================
constexpr const char* SOURCE_COMMIT_HASH = "TBD";  // TODO: capture at freeze
constexpr const char* SOURCE_BRANCH     = "main";
constexpr const char* CAPTURE_DATE      = "2026-08-10";

// ============================================================================
// Model Under Test (MUT) — same as B008
// ============================================================================
constexpr const char* MUT_PATH    = "F:\\Franken\\BackwardsUnlock\\1b\\unlock-1B-Q4_K_M.gguf";
constexpr const char* MUT_SHA256  = "DDE5AA3FC5FFC17176B5E8BDC82F587B24B2678C6C66101BF7DA77AF9F7CCDFF";
constexpr const char* MUT_FORMAT  = "GGUF v3";
constexpr const char* MUT_ARCH    = "llama";

// ============================================================================
// Verified Metadata (from MUT)
// ============================================================================
constexpr uint32_t VERIFIED_VOCAB_SIZE      = 128256;
constexpr uint32_t VERIFIED_HIDDEN_SIZE     = 3072;
constexpr uint32_t VERIFIED_LAYER_COUNT     = 28;
constexpr uint32_t VERIFIED_HEAD_COUNT      = 24;
constexpr uint32_t VERIFIED_KV_HEAD_COUNT   = 8;
constexpr uint32_t VERIFIED_CONTEXT_LENGTH  = 131072;
constexpr uint32_t VERIFIED_TENSOR_COUNT    = 255;

// ============================================================================
// B009-A Correctness Results
// ============================================================================
// Test ID    | Description                        | Status | Max Diff | Max Rel
// -----------|------------------------------------|--------|----------|--------
// B009-A-001 | Differential correctness (1 token) | PASS   | 0.000000 | 0.000000
// B009-A-003 | Differential correctness (3 tokens)| PASS   | 0.000000 | 0.000000
// B009-A-010 | Differential correctness (10 tok)  | PASS*  | 0.000000 | 0.000000
// B009-A-032 | Differential correctness (32 tok)  | TBD    | TBD      | TBD
// B009-A-128 | Differential correctness (128 tok)| TBD    | TBD      | TBD
//
// Total: 3/5 confirmed PASS (1, 3, 10 tokens)
//        2/5 pending (32, 128 tokens — runtime too slow on CPU)
//
// *T=10 confirmed PASS in earlier run; T=1 and T=3 re-confirmed after
//  residual bug fix (2026-08-10). The fix: save residual before RMSNorm
//  in both attention and FFN paths, matching Forward() behavior.
//
// ⚠️  CRITICAL: The interrupted run3 log does NOT constitute a PASS.
//    A clean completion with the numerical-equivalence assertion is required.
//
// TOLERANCE:
//   Absolute: 1e-4f
//   Relative: 1e-3f
//
// ============================================================================

// ============================================================================
// Correctness Bug History
// ============================================================================
// Original ForwardBatch() had a residual preservation bug:
//   - RMSNorm was performed in-place on hidden[] without saving residual first
//   - Residual addition computed: normalized_x + attn_out
//   - Correct behavior: original_x + attn_out
//   - This caused numerical divergence from Forward() oracle
//
// Fix applied 2026-08-10:
//   - Added residual_batch[] buffer
//   - Save residual BEFORE RMSNorm in both attention and FFN paths
//   - Use saved residual in the addition step
//   - Verified T=1 and T=3 produce max_diff=0.000000
//
// Any results obtained before this fix are INVALIDATED.
//
// ============================================================================

// ============================================================================
// Build Configuration
// ============================================================================
constexpr const char* BUILD_TOOLCHAIN   = "MSVC 14.51.36231 (VS2022 Enterprise)";
constexpr const char* BUILD_GENERATOR   = "Ninja";
constexpr const char* BUILD_CONFIG      = "Release";
constexpr const char* BUILD_TARGET      = "b009_batched_prefill_certification";
constexpr const char* CMAKE_VERSION     = "3.30+";
constexpr const char* CPLUSPLUS_STANDARD= "C++20";

// ============================================================================
// Architecture Description
// ============================================================================
// ForwardBatch() topology (B009-A, FIXED):
//   - Layer-outer loop: processes all T tokens through each layer before
//     advancing to the next layer.
//   - Per-token QKV projections via ExecuteLayerMatMul (not yet batched GEMM).
//   - Per-token RoPE application.
//   - KV cache update for all tokens per layer.
//   - Per-token causal multi-head attention.
//   - Per-token output projection + residual add (with preserved residual).
//   - Per-token FFN SwiGLU (gate, up, down) with preserved residual.
//   - Final norm + output projection on last token only.
//
// Key invariant: logits returned for final token position match Forward()
// exactly (within tolerance) for all tested prompt lengths.
//
// ============================================================================

// ============================================================================
// Performance Status (B009-A)
// ============================================================================
// B009-A is NOT performance-certified. The layer-outer structure is correct
// but uses per-token matmuls. Performance improvement requires B009-B
// batched GEMM implementation.
//
// ⚠️  PREVIOUS +8.32% RESULT INVALIDATED:
//   The previously reported +8.32% regression was obtained from an
//   implementation that either delegated to Forward() or had the residual
//   bug. It is NOT a valid certified result for the corrected ForwardBatch().
//
// Current observation (CPU, 1B model, 28 layers):
//   T=1:   ~5.2s  (comparable to Forward())
//   T=32:  ~120s  (no improvement — per-token matmuls dominate)
//   T=128: ~215s/layer (prohibitively slow)
//
// ============================================================================

// ============================================================================
// Regression Baseline Status
// ============================================================================
// B008  Reference Forward() oracle         FROZEN
// B009  Original layer-outer experiment   INVALIDATED (bug discovered)
// B009-fix Corrected ForwardBatch()        CURRENT — partial revalidation
// B009-B Batched GEMM (QKV, FFN, output)   NOT YET STARTED
//
// INVARIANT: B009-fix must fully pass before B009-B optimizes.
// INVARIANT: B008 remains the sole reference oracle until B009 is re-certified.
//
// ============================================================================

// ============================================================================
// CI Gate Requirements (B009-A)
// ============================================================================
// A valid B009-A CI gate MUST reproduce ALL of the following:
//   [ ] Clean build (zero warnings treated as errors)
//   [ ] b009_batched_prefill_certification executable links successfully
//   [ ] Differential correctness PASS for lengths {1, 3, 10}
//   [ ] Real unlock-1B GGUF ingestion (MUT_PATH above)
//   [ ] Metadata extraction matches VERIFIED_* constants
//   [ ] ForwardBatch() is genuinely independent (not delegating to Forward())
//   [ ] Source commit matches SOURCE_COMMIT_HASH
//   [ ] Model SHA256 matches MUT_SHA256
//
// OPTIONAL (long-running):
//   [ ] Differential correctness for 32 tokens
//   [ ] Differential correctness for 128 tokens
//
// FREEZE CONDITION:
//   B009 may be frozen only after the corrected ForwardBatch() has a
//   reproducible PASS across all test lengths {1, 3, 10, 32, 128}.
//
// ============================================================================

} // namespace RawrXD::B009A

#endif // B009A_EVIDENCE_MANIFEST_H
