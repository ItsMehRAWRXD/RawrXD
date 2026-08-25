// ============================================================================
// ToroidalKVCache.hpp — Infinite-Context Ring Buffer KV-Cache
// The tokamak vacuum vessel: tokens circulate forever, no wall strikes
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <cstring>
#include <algorithm>

namespace rawrxd {

// ============================================================================
// KVCacheSpan — Descriptor for a contiguous physical span of K/V data
// ============================================================================
struct KVCacheSpan {
    const float* keys   = nullptr;
    const float* values = nullptr;
    size_t       count  = 0;
    size_t       physical_slot = 0;
};

// ============================================================================
// PlasmaToken — A token with thermal properties (confidence = temperature)
// ============================================================================
struct PlasmaToken {
    uint32_t token_id = 0;
    float    temperature = 0.0f;      // confidence = thermal energy
    float    entropy = 0.0f;            // disorder = plasma turbulence
    uint64_t seq_pos = 0;               // absolute position in torus
    bool     fused = false;             // true if this token passed divertor
    uint32_t beam_injection_count = 0;  // how many neutral beams hit before fusion
};

// ============================================================================
// ToroidalKVCache — Ring buffer that never allocates after init
// Tokens circulate through the torus. Old tokens are overwritten, not freed.
// This eliminates the O(n²) KV-cache decay that kills long-context TPS.
// ============================================================================
class ToroidalKVCache {
public:
    // head_dim: dimension of each attention head (e.g., 128)
    // num_heads: number of attention heads (e.g., 32)
    // max_tokens: torus circumference (e.g., 131072 = 128K context)
    // layers: number of transformer layers
    ToroidalKVCache(size_t head_dim, size_t num_heads, size_t max_tokens, size_t layers);
    ~ToroidalKVCache() = default;

    // Disable copy (the torus is a singular physical object)
    ToroidalKVCache(const ToroidalKVCache&) = delete;
    ToroidalKVCache& operator=(const ToroidalKVCache&) = delete;

    // ------------------------------------------------------------------------
    // Plasma injection: write a new token's K/V into the torus
    // Overwrites the oldest token if torus is full (infinite context)
    // ------------------------------------------------------------------------
    bool injectToken(const PlasmaToken& token,
                     const float* key_data,   // [num_heads * head_dim]
                     const float* value_data); // [num_heads * head_dim]

    // ------------------------------------------------------------------------
    // Magnetic field query: retrieve K/V for attention computation
    // Returns pointers into the torus — no copy, no allocation.
    // May return up to 2 spans if the range wraps around the ring buffer.
    // ------------------------------------------------------------------------
    bool queryTokenRange(uint64_t start_seq, uint64_t end_seq,
                         KVCacheSpan& span0,
                         KVCacheSpan& span1) const;

    // Legacy single-span query (kept for backward compatibility)
    bool queryTokenRange(uint64_t start_seq, uint64_t end_seq,
                         const float*& out_keys,
                         const float*& out_values,
                         size_t& out_count) const;

    // ------------------------------------------------------------------------
    // Divertor sweep: remove tokens that failed SM0-DSP clash detection
    // This is not "deletion" — it's magnetic pumping. The slot is marked
    // as available for re-injection.
    // ------------------------------------------------------------------------
    bool divertTokens(const uint64_t* seq_positions, size_t count);

    // ------------------------------------------------------------------------
    // Torus state
    // ------------------------------------------------------------------------
    size_t tokenCount() const { return token_count_; }
    size_t maxTokens() const { return max_tokens_; }
    uint64_t writeHead() const { return write_head_; }
    uint64_t oldestSequence() const {
        return (write_head_ > token_count_) ? (write_head_ - token_count_) : 0;
    }
    bool isFull() const { return token_count_ >= max_tokens_; }

    // Thermal diagnostics: average temperature of plasma in torus
    float plasmaTemperature() const;
    float plasmaTurbulence() const;  // stddev of entropy

    // Magnetic reconnection: shift the torus to align with a new prompt
    // This is O(1): just reset the write head and token count.
    void magneticReconnection();

    // ------------------------------------------------------------------------
    // Memory layout: contiguous block, cache-friendly
    // keys_  : [max_tokens][layers][num_heads][head_dim] float
    // values_: [max_tokens][layers][num_heads][head_dim] float
    // tokens_: [max_tokens] PlasmaToken
    // ------------------------------------------------------------------------
    size_t memoryBytes() const;

private:
    size_t head_dim_;
    size_t num_heads_;
    size_t max_tokens_;
    size_t layers_;
    size_t token_stride_;   // num_heads * head_dim
    size_t layer_stride_;   // token_stride_
    size_t slot_stride_;    // layers_ * layer_stride_

    // The torus itself — one contiguous allocation
    std::vector<float> keys_;     // torus K buffer
    std::vector<float> values_;   // torus V buffer
    std::vector<PlasmaToken> tokens_; // metadata ring

    uint64_t write_head_ = 0;   // next slot to write (modulo max_tokens)
    size_t token_count_ = 0;    // how many slots are occupied

    // Internal: get slot index from absolute seq_pos
    size_t slotIndex(uint64_t seq_pos) const {
        // seq_pos maps to torus via modulo
        // But we also support wrap-around: seq_pos may be < write_head_ - max_tokens_
        if (seq_pos > write_head_) return static_cast<size_t>(seq_pos % max_tokens_);
        uint64_t offset = write_head_ - token_count_;
        if (seq_pos < offset) return static_cast<size_t>((seq_pos + max_tokens_) % max_tokens_);
        return static_cast<size_t>(seq_pos % max_tokens_);
    }

    float* keySlot(size_t slot) { return keys_.data() + slot * slot_stride_; }
    float* valueSlot(size_t slot) { return values_.data() + slot * slot_stride_; }
    const float* keySlot(size_t slot) const { return keys_.data() + slot * slot_stride_; }
    const float* valueSlot(size_t slot) const { return values_.data() + slot * slot_stride_; }
};

} // namespace rawrxd
