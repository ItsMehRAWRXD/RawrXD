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
                                      const float*& out_keys,
                                      const float*& out_values,
                                      size_t& out_count) const
{
    if (start_seq >= end_seq || token_count_ == 0) {
        out_keys = nullptr;
        out_values = nullptr;
        out_count = 0;
        return false;
    }

    // Clamp to available range
    uint64_t oldest_seq = (write_head_ > token_count_) ? (write_head_ - token_count_) : 0;
    if (start_seq < oldest_seq) start_seq = oldest_seq;
    if (end_seq > write_head_) end_seq = write_head_;

    out_count = static_cast<size_t>(end_seq - start_seq);
    if (out_count == 0) {
        out_keys = nullptr;
        out_values = nullptr;
        return false;
    }

    // Return pointer to first slot's key data
    size_t first_slot = slotIndex(start_seq);
    out_keys = keySlot(first_slot);
    out_values = valueSlot(first_slot);

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
