// ============================================================================
// ToroidalKVCache.cpp — Infinite-Context Ring Buffer Implementation
// The tokamak vacuum vessel: tokens circulate forever, no wall strikes
// ============================================================================

#include "ToroidalKVCache.hpp"
#include <cmath>
#include <limits>

namespace rawrxd {

ToroidalKVCache::ToroidalKVCache(size_t head_dim, size_t num_heads, size_t max_tokens, size_t layers)
    : head_dim_(head_dim)
    , num_heads_(num_heads)
    , max_tokens_(max_tokens)
    , layers_(layers)
    , token_stride_(num_heads * head_dim)
    , layer_stride_(token_stride_)
    , slot_stride_(layers_ * layer_stride_)
    , write_head_(0)
    , token_count_(0)
{
    // One contiguous allocation for the entire torus
    // keys:   [max_tokens][layers][num_heads][head_dim]
    // values: [max_tokens][layers][num_heads][head_dim]
    const size_t total_floats = max_tokens_ * slot_stride_;
    keys_.resize(total_floats);
    values_.resize(total_floats);
    tokens_.resize(max_tokens_);

    // Zero-initialize
    std::fill(keys_.begin(), keys_.end(), 0.0f);
    std::fill(values_.begin(), values_.end(), 0.0f);
}

bool ToroidalKVCache::injectToken(const PlasmaToken& token,
                                  const float* key_data,
                                  const float* value_data)
{
    if (!key_data || !value_data) return false;

    size_t slot = static_cast<size_t>(write_head_ % max_tokens_);

    // Write K/V for all layers
    for (size_t layer = 0; layer < layers_; ++layer) {
        float* k_slot = keySlot(slot) + layer * layer_stride_;
        float* v_slot = valueSlot(slot) + layer * layer_stride_;
        std::memcpy(k_slot, key_data + layer * token_stride_, token_stride_ * sizeof(float));
        std::memcpy(v_slot, value_data + layer * token_stride_, token_stride_ * sizeof(float));
    }

    // Write metadata
    tokens_[slot] = token;
    tokens_[slot].seq_pos = write_head_;

    // Advance write head
    ++write_head_;
    if (token_count_ < max_tokens_) {
        ++token_count_;
    }

    return true;
}

bool ToroidalKVCache::queryTokenRange(uint64_t start_seq, uint64_t end_seq,
                                      KVCacheSpan& span0,
                                      KVCacheSpan& span1) const
{
    span0 = KVCacheSpan{};
    span1 = KVCacheSpan{};

    if (start_seq >= end_seq || token_count_ == 0) {
        return false;
    }

    // Clamp to available range
    uint64_t oldest_seq = (write_head_ > token_count_) ? (write_head_ - token_count_) : 0;
    if (start_seq < oldest_seq) start_seq = oldest_seq;
    if (end_seq > write_head_) end_seq = write_head_;

    size_t total_count = static_cast<size_t>(end_seq - start_seq);
    if (total_count == 0) {
        return false;
    }

    size_t first_slot = slotIndex(start_seq);
    size_t last_slot  = slotIndex(end_seq - 1);

    // If the range does not wrap, return a single span
    if (first_slot <= last_slot) {
        span0.keys   = keySlot(first_slot);
        span0.values = valueSlot(first_slot);
        span0.count  = total_count;
        span0.physical_slot = first_slot;
        return true;
    }

    // Range wraps around the ring buffer: split into two spans
    size_t span0_count = max_tokens_ - first_slot;
    size_t span1_count = total_count - span0_count;

    span0.keys   = keySlot(first_slot);
    span0.values = valueSlot(first_slot);
    span0.count  = span0_count;
    span0.physical_slot = first_slot;

    span1.keys   = keySlot(0);
    span1.values = valueSlot(0);
    span1.count  = span1_count;
    span1.physical_slot = 0;

    return true;
}

bool ToroidalKVCache::queryTokenRange(uint64_t start_seq, uint64_t end_seq,
                                      const float*& out_keys,
                                      const float*& out_values,
                                      size_t& out_count) const
{
    KVCacheSpan s0{}, s1{};
    if (!queryTokenRange(start_seq, end_seq, s0, s1)) {
        out_keys = nullptr;
        out_values = nullptr;
        out_count = 0;
        return false;
    }

    // Legacy single-span: only return the first span (caller must handle wrap manually)
    out_keys   = s0.keys;
    out_values = s0.values;
    out_count  = s0.count;
    return true;
}

bool ToroidalKVCache::divertTokens(const uint64_t* seq_positions, size_t count) {
    if (!seq_positions || count == 0) return false;

    for (size_t i = 0; i < count; ++i) {
        uint64_t seq = seq_positions[i];
        if (seq >= write_head_ || seq < write_head_ - token_count_) continue;

        size_t slot = slotIndex(seq);
        tokens_[slot].fused = false;  // Mark as diverted (impurity ejected)
        // The slot will be overwritten on next wrap-around
    }
    return true;
}

float ToroidalKVCache::plasmaTemperature() const {
    if (token_count_ == 0) return 0.0f;
    float sum = 0.0f;
    size_t count = std::min(token_count_, max_tokens_);
    for (size_t i = 0; i < count; ++i) {
        sum += tokens_[i].temperature;
    }
    return sum / static_cast<float>(count);
}

float ToroidalKVCache::plasmaTurbulence() const {
    if (token_count_ == 0) return 0.0f;
    float mean = plasmaTemperature();
    float sum_sq = 0.0f;
    size_t count = std::min(token_count_, max_tokens_);
    for (size_t i = 0; i < count; ++i) {
        float diff = tokens_[i].entropy - mean;
        sum_sq += diff * diff;
    }
    return std::sqrt(sum_sq / static_cast<float>(count));
}

void ToroidalKVCache::magneticReconnection() {
    // O(1) context switch: just reset the torus
    write_head_ = 0;
    token_count_ = 0;
    // Zero the plasma
    std::fill(keys_.begin(), keys_.end(), 0.0f);
    std::fill(values_.begin(), values_.end(), 0.0f);
    for (auto& t : tokens_) {
        t = PlasmaToken{};
    }
}

size_t ToroidalKVCache::memoryBytes() const {
    return keys_.size() * sizeof(float)
         + values_.size() * sizeof(float)
         + tokens_.size() * sizeof(PlasmaToken);
}

} // namespace rawrxd
