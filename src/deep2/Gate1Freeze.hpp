// ============================================================================
// Gate1Freeze.hpp — Gate 1 CLOSED. Do not reopen tokenizer/chat-render work.
// ============================================================================
#pragma once

namespace Deep2 {
namespace Gate1 {

// Frozen 2026-08-29 after GATE1_CHAT_TEMPLATE_PARITY PASS vs llama --jinja
// (TinyLlama-1.1B-Chat Q4_K_M): byte SHA256 + token IDs + BOS policy.
inline constexpr bool TOKENIZER_CERTIFIED = true;
inline constexpr bool CHAT_RENDER_CERTIFIED = true;
inline constexpr bool CANONICAL_PATH_CERTIFIED = true;

inline constexpr const char* FREEZE_NOTE =
    "GATE1 frozen. L0+L1 attn/FFN CLOSED under clean EXPAND_V. "
    "L1_LAYER_OUT PASS ~6e-8. Sparse tips OPEN (llama L2+ missing). "
    "FINAL_NORM fail NOT localized — FORCE only hit L0+L1. "
    "Next: BATCH2_SPARSE_TIPS_001 (REF_CB_MAX_LAYER>=21).";

} // namespace Gate1
} // namespace Deep2
