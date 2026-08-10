// ============================================================================
// B008 Evidence Manifest — Build + CI Integration Baseline
// Captured: 2026-08-09
// ============================================================================
//
// PURPOSE:
//   This manifest documents the exact reproducible state of the B005 canonical
//   model certification that serves as the B008 regression baseline.
//
// USAGE:
//   - Treat this file as read-only after B008 freeze.
//   - Any CI pipeline should reproduce these results before accepting changes.
//   - Do not modify Forward() or inference paths until B009 batched-prefill.
//
// ============================================================================

#ifndef B008_EVIDENCE_MANIFEST_H
#define B008_EVIDENCE_MANIFEST_H

#include <cstdint>

namespace RawrXD::B008 {

// ============================================================================
// Source Identity
// ============================================================================
constexpr const char* SOURCE_COMMIT_HASH = "29e76f01e632f0cc629967a161e7b537d18f4c08";
constexpr const char* SOURCE_BRANCH     = "main";  // verify with: git branch --show-current
constexpr const char* CAPTURE_DATE      = "2026-08-09";

// ============================================================================
// Model Under Test (MUT)
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
// Certification Results (B005 — 12/12 PASS)
// ============================================================================
// Test ID | Description                          | Status | Notes
// --------|--------------------------------------|--------|------------------
// B005-001| GGUF detected from magic             | PASS   | Magic 0x46554747
// B005-002| GGUF v3 accepted                     | PASS   | Version == 3
// B005-003| Invalid magic rejected                 | PASS   | 0xDEADBEEF
// B005-004| Truncated header rejected            | PASS   | Only magic written
// B005-005| Metadata extracted                     | PASS   | All fields > 0
// B005-006| Tensor lookup succeeds               | PASS   | token_embd.weight
// B005-007| Missing tensor reported              | PASS   | Deterministic false
// B005-008| Unknown architecture survives        | PASS   | Not fatal
// B005-009| Adapter lifetime survives handoff    | PASS   | UnifiedModelLoader
// B005-010| Ownership explicit                   | PASS   | Unload -> nullptr
// B005-011| Canonical metadata matches source    | PASS   | See VERIFIED_* above
// B005-012| Tensor count matches expected        | PASS   | 255 tensors
//
// Total: 12 passed, 0 failed
//
// ============================================================================

// ============================================================================
// Build Configuration
// ============================================================================
constexpr const char* BUILD_TOOLCHAIN   = "MSVC 14.51.36231 (VS2022 Enterprise)";
constexpr const char* BUILD_GENERATOR   = "Ninja";
constexpr const char* BUILD_CONFIG      = "Release";
constexpr const char* BUILD_TARGET      = "b005_canonical_model_certification";
constexpr const char* CMAKE_VERSION     = "3.30+";  // verify with: cmake --version
constexpr const char* CPLUSPLUS_STANDARD= "C++20";

// ============================================================================
// Regression Baseline Status
// ============================================================================
// B004  Streaming integration       PASS
// B005  Canonical model             12/12 PASS  ← THIS BASELINE
// B006  KV-cache reuse              PASS
// B007  Prefill analysis            BASELINE
// B008  Build + CI integration      CURRENT
//
// INVARIANT: Do not modify Forward() or inference paths before B009.
//
// ============================================================================

// ============================================================================
// CI Gate Requirements
// ============================================================================
// A valid B008 CI gate MUST reproduce ALL of the following:
//   [ ] Clean build (zero warnings treated as errors)
//   [ ] b005_canonical_model_certification executable links successfully
//   [ ] 12/12 B005 cases PASS
//   [ ] Real unlock-1B GGUF ingestion (MUT_PATH above)
//   [ ] Metadata extraction matches VERIFIED_* constants
//   [ ] Tensor-count validation == 255
//   [ ] Invalid/truncated GGUF rejection (B005-003, B005-004)
//   [ ] Tensor lookup + missing-tensor behavior (B005-006, B005-007)
//   [ ] Ownership/lifetime checks (B005-009, B005-010)
//   [ ] Source commit matches SOURCE_COMMIT_HASH
//   [ ] Model SHA256 matches MUT_SHA256
//
// ============================================================================

} // namespace RawrXD::B008

#endif // B008_EVIDENCE_MANIFEST_H
