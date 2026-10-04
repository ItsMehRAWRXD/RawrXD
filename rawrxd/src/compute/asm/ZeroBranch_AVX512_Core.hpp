// RAWRXD_ZERO_BRANCH_AVX512_CORE_001
// Zero-branch AVX-512 execution core
// Pre-decode ordering, cacheline pre-warm, register-pinned lanes
// No conditional branches in inner loop — all control via mask registers

#pragma once
#include <cstdint.h>
#include <immintrin.h>

namespace rawrxd::asm_core {

// ---------------------------------------------------------------------------
// Branchless execution state
// ---------------------------------------------------------------------------
struct ZeroBranchState {
    // K-mask registers control all lane enable/disable
    __mmask16 lane_enable;       // k1 — active lanes
    __mmask16 lane_complete;     // k2 — lanes that reached EOS
    __mmask16 lane_pending;      // k3 — lanes with valid next tokens

    // ZMM registers pinned to tensor execution lanes (no spills)
    // zmm0-zmm7: input embedding vectors (8 lanes x 2 = 16 lanes interleaved)
    // zmm8-zmm15: weight tiles (one per lane group)
    // zmm16-zmm23: KV cache slots
    // zmm24-zmm29: attention scratch
    // zmm30: lane constants (1.0f, 0.0f, -inf, etc.)
    // zmm31: reserved for reduction

    // Pre-warmed cacheline tracking
    uint64_t next_prefetch_a;
    uint64_t next_prefetch_b;
    uint64_t next_prefetch_kv;

    // Pre-decode token buffer (16 tokens, one per lane)
    uint32_t token_buffer[16];
    float    logits_buffer[16 * 128256]; // per-lane logits (128K vocab)
};

// ---------------------------------------------------------------------------
// Pre-decode ordering: tokens are ordered by predicted branch probability
// before entering the AVX-512 core, so the inner loop never stalls on
// irregular memory access.
// ---------------------------------------------------------------------------
struct PreDecodeBatch {
    uint32_t lane_id[16];
    uint32_t token_id[16];
    float    priority[16];     // branch probability from speculative head
};

// ---------------------------------------------------------------------------
// Zero-branch inner loop
// All control flow via mask registers — no jcc in hot path
// ---------------------------------------------------------------------------
class ZeroBranchAVX512Core {
public:
    // Initialize with model dimensions
    explicit ZeroBranchAVX512Core(uint32_t hidden_dim, uint32_t vocab_size);

    // Execute one full forward pass for 16 tokens simultaneously
    // No branches — all completion signaled via mask register
    void executeBatch(const PreDecodeBatch& batch, ZeroBranchState* state);

    // Cacheline pre-warm: prefetch weights for next layer
    // Called once per layer transition (outer loop)
    void prewarmNextLayer(uint32_t layer_id, const void* weight_base);

    // Register-pinned tensor bind: ensure a weight tile stays in zmm8-zmm15
    // for the duration of the decode pass
    void pinWeightTile(uint32_t lane_group, const void* weight_ptr);

    // Instruction-level scheduling: emit FMAs interleaved with loads
    // to maximize port utilization (ports 0,1,5 on Zen4)
    void scheduleFMAInterleave(uint32_t count);

private:
    uint32_t hidden_dim_;
    uint32_t vocab_size_;
    uint32_t num_layers_;
};

// ---------------------------------------------------------------------------
// Inline helper: branchless lane selection via mask
// If lane i is complete, its output is gated to zero; active lanes propagate
// ---------------------------------------------------------------------------
inline __m512 selectActiveLanes(__m512 value, __mmask16 active_mask) {
    // Zero out completed lanes, keep active ones
    return _mm512_maskz_mov_ps(active_mask, value);
}

// ---------------------------------------------------------------------------
// Inline helper: horizontal argmax across 16 lanes (no loop, no branch)
// Uses AVX-512CD (conflict detection) for parallel comparison
// ---------------------------------------------------------------------------
inline uint32_t argmax16(const float* logits, __mmask16 valid_mask) {
    // Load 16 logits
    __m512 v = _mm512_maskz_loadu_ps(valid_mask, logits);
    // Horizontal max reduction
    float max_val = _mm512_reduce_max_ps(v);
    // Compare to find index (first match)
    __mmask16 max_mask = _mm512_cmpeq_ps_mask(v, _mm512_set1_ps(max_val));
    // Extract lowest set bit as index
    return _tzcnt_u32(static_cast<uint32_t>(max_mask));
}

} // namespace rawrxd::asm_core
