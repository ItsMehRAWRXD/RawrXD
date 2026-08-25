// ============================================================================
// ToroidalKVCache.hpp — Infinite-Context Ring Buffer (Production Candidate)
// Two-span API for correct zero-copy attention across wraparound
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstring>
#include <limits>

namespace rawrxd {

// ============================================================================
// PlasmaToken — Metadata for a cached token
// ============================================================================
struct PlasmaToken {
    uint64_t seq_pos = 0;
    float    temperature = 0.0f;
    float    entropy = 0.0f;
    bool     fused = false;
};

// ============================================================================
// KVCacheSpan — One contiguous physical segment of the logical sequence
// ============================================================================
struct KVCacheSpan {
    const float* keys   = nullptr;   // Pointer to key data
    const float* values = nullptr;   // Pointer to value data
    size_t       count  = 0;         // Number of tokens in this span
    size_t       physical_slot = 0;  // Starting physical slot index
};

// ============================================================================
// ToroidalKVCache — Ring-buffer KV storage with explicit logical mapping
//
// Physical layout: [max_tokens][layers][num_heads][head_dim]
// Logical mapping:  physical_slot = seq_pos % max_tokens
//
// The cache exposes at most two contiguous spans for any token range,
// allowing zero-copy attention even across the ring-buffer wrap.
// ============================================================================
class ToroidalKVCache {
public:
    // Constructor validates all dimensions; throws std::invalid_argument on zero
    ToroidalKVCache(size_t head_dim, size_t num_heads, size_t max_tokens, size_t layers);

    // Inject a new token's K/V data for all layers.
    // Returns false on null input.
    bool injectToken(const PlasmaToken& token,
                     const float* key_data,
                     const float* value_data);

    // Query a logical token range [start_seq, end_seq).
    // Returns at most two spans covering the logical sequence.
    // Returns false if the range is empty or outside the cache window.
    bool queryTokenRange(uint64_t start_seq, uint64_t end_seq,
                         KVCacheSpan& out_span0,
                         KVCacheSpan& out_span1) const;

    // Mark specific sequence positions as diverted (impurity ejected).
    // Silently ignores out-of-range positions.
    bool divertTokens(const uint64_t* seq_positions, size_t count);

    // Plasma diagnostics — iterate logical tokens, not physical slots
    float plasmaTemperature() const;
    float plasmaTurbulence() const;

    // O(1) context reset: invalidate all state without zeroing memory
    void magneticReconnection();

    // Total bytes allocated (keys + values + metadata)
    size_t memoryBytes() const;

    // Sequence bookkeeping
    uint64_t oldestSequence() const;
    uint64_t newestSequence() const;
    bool     contains(uint64_t seq) const;
    size_t   physicalSlot(uint64_t seq) const;

    // Cache dimensions
    size_t headDim()      const { return head_dim_; }
    size_t numHeads()     const { return num_heads_; }
    size_t maxTokens()    const { return max_tokens_; }
    size_t layers()       const { return layers_; }
    size_t tokenCount()   const { return token_count_; }
    uint64_t writeHead()  const { return write_head_; }

private:
    // Physical slot access
    float*       keySlot(size_t slot);
    float*       valueSlot(size_t slot);
    const float* keySlot(size_t slot) const;
    const float* valueSlot(size_t slot) const;
    size_t       slotIndex(uint64_t seq) const;

    // Logical token iteration helper
    void forEachLogicalToken(auto&& callback) const;

    size_t head_dim_;
    size_t num_heads_;
    size_t max_tokens_;
    size_t layers_;
    size_t token_stride_;   // num_heads * head_dim
    size_t layer_stride_;   // token_stride_
    size_t slot_stride_;    // layers_ * layer_stride_

    uint64_t write_head_ = 0;
    size_t   token_count_ = 0;

    std::vector<float>       keys_;
    std::vector<float>       values_;
    std::vector<PlasmaToken> tokens_;
};

} // namespace rawrxd
