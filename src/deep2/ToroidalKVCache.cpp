// ============================================================================
// ToroidalKVCache.cpp — Infinite-Context Ring Buffer Implementation
// The tokamak vacuum vessel: tokens circulate forever, no wall strikes
// ============================================================================

#include "ToroidalKVCache.hpp"
#include <cmath>
#include <limits>
#include <cstring>
#include <stdexcept>

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
    // Validate dimensions to prevent division by zero and nonsensical allocation
    if (head_dim_ == 0)       throw std::invalid_argument("ToroidalKVCache: head_dim must be > 0");
    if (num_heads_ == 0)      throw std::invalid_argument("ToroidalKVCache: num_heads must be > 0");
    if (max_tokens_ == 0)     throw std::invalid_argument("ToroidalKVCache: max_tokens must be > 0");
    if (layers_ == 0)         throw std::invalid_argument("ToroidalKVCache: layers must be > 0");

    // Overflow-check before allocation
    constexpr size_t MAX_SIZE_T = std::numeric_limits<size_t>::max();
    if (slot_stride_ > MAX_SIZE_T / max_tokens_) {
        throw std::overflow_error("ToroidalKVCache: total_floats overflow");
    }

    const size_t total_floats = max_tokens_ * slot_stride_;
    if (total_floats > MAX_SIZE_T / sizeof(float)) {
        throw std::overflow_error("ToroidalKVCache: byte allocation overflow");
    }

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
                                      KVCacheSpan& out_span0,
                                      KVCacheSpan& out_span1) const
{
    out_span0 = KVCacheSpan{};
    out_span1 = KVCacheSpan{};

    if (start_seq >= end_seq || token_count_ == 0) {
        return false;
    }

    // Clamp to available range
    uint64_t oldest_seq = (write_head_ > token_count_) ? (write_head_ - token_count_) : 0;
    if (start_seq < oldest_seq) start_seq = oldest_seq;
    if (end_seq > write_head_)   end_seq = write_head_;

    size_t count = static_cast<size_t>(end_seq - start_seq);
    if (count == 0) {
        return false;
    }

    size_t first_slot = slotIndex(start_seq);
    size_t last_slot  = slotIndex(end_seq - 1);  // inclusive

    if (first_slot <= last_slot) {
        // Single contiguous physical block — no wrap in this range
        out_span0.keys          = keySlot(first_slot);
        out_span0.values        = valueSlot(first_slot);
        out_span0.count         = count;
        out_span0.physical_slot = first_slot;
    } else {
        // Range straddles the wrap boundary — split into two spans
        size_t span0_count = max_tokens_ - first_slot;
        size_t span1_count = count - span0_count;

        out_span0.keys          = keySlot(first_slot);
        out_span0.values        = valueSlot(first_slot);
        out_span0.count         = span0_count;
        out_span0.physical_slot = first_slot;

        out_span1.keys          = keySlot(0);
        out_span1.values        = valueSlot(0);
        out_span1.count         = span1_count;
        out_span1.physical_slot = 0;
    }

    return true;
}

bool ToroidalKVCache::divertTokens(const uint64_t* seq_positions, size_t count) {
    if (!seq_positions || count == 0) return false;

    uint64_t oldest_seq = (write_head_ > token_count_) ? (write_head_ - token_count_) : 0;

    for (size_t i = 0; i < count; ++i) {
        uint64_t seq = seq_positions[i];
        if (seq >= write_head_ || seq < oldest_seq) continue;

        size_t slot = slotIndex(seq);
        tokens_[slot].fused = false;  // Mark as diverted (impurity ejected)
        // The slot will be overwritten on next wrap-around
    }
    return true;
}

float ToroidalKVCache::plasmaTemperature() const {
    if (token_count_ == 0) return 0.0f;

    float sum = 0.0f;
    size_t count = 0;

    uint64_t oldest_seq = (write_head_ > token_count_) ? (write_head_ - token_count_) : 0;
    for (uint64_t seq = oldest_seq; seq < write_head_; ++seq) {
        size_t slot = slotIndex(seq);
        sum += tokens_[slot].temperature;
        ++count;
    }

    return (count > 0) ? (sum / static_cast<float>(count)) : 0.0f;
}

float ToroidalKVCache::plasmaTurbulence() const {
    if (token_count_ == 0) return 0.0f;

    // Calculate mean entropy (not temperature)
    float mean_entropy = 0.0f;
    size_t count = 0;

    uint64_t oldest_seq = (write_head_ > token_count_) ? (write_head_ - token_count_) : 0;
    for (uint64_t seq = oldest_seq; seq < write_head_; ++seq) {
        size_t slot = slotIndex(seq);
        mean_entropy += tokens_[slot].entropy;
        ++count;
    }

    if (count == 0) return 0.0f;
    mean_entropy /= static_cast<float>(count);

    // Calculate variance of entropy around its mean
    float sum_sq = 0.0f;
    for (uint64_t seq = oldest_seq; seq < write_head_; ++seq) {
        size_t slot = slotIndex(seq);
        float diff = tokens_[slot].entropy - mean_entropy;
        sum_sq += diff * diff;
    }

    return std::sqrt(sum_sq / static_cast<float>(count));
}

void ToroidalKVCache::magneticReconnection() {
    // O(1): just reset the logical pointers.
    // Old slots are treated as invalid until overwritten.
    write_head_  = 0;
    token_count_ = 0;

    // Optional: if stale-data protection is required, a generation counter
    // can be added here. For now, seq_pos in tokens_ serves as the
    // validity discriminator.
}

size_t ToroidalKVCache::memoryBytes() const {
    return keys_.size()   * sizeof(float)
         + values_.size() * sizeof(float)
         + tokens_.size() * sizeof(PlasmaToken);
}

// ============================================================================
// Sequence bookkeeping
// ============================================================================
uint64_t ToroidalKVCache::oldestSequence() const {
    return (write_head_ > token_count_) ? (write_head_ - token_count_) : 0;
}

uint64_t ToroidalKVCache::newestSequence() const {
    return (write_head_ > 0) ? (write_head_ - 1) : 0;
}

bool ToroidalKVCache::contains(uint64_t seq) const {
    uint64_t oldest = oldestSequence();
    return seq >= oldest && seq < write_head_;
}

size_t ToroidalKVCache::physicalSlot(uint64_t seq) const {
    return slotIndex(seq);
}

// ============================================================================
// Private helpers
// ============================================================================
float* ToroidalKVCache::keySlot(size_t slot) {
    return keys_.data() + slot * slot_stride_;
}

float* ToroidalKVCache::valueSlot(size_t slot) {
    return values_.data() + slot * slot_stride_;
}

const float* ToroidalKVCache::keySlot(size_t slot) const {
    return keys_.data() + slot * slot_stride_;
}

const float* ToroidalKVCache::valueSlot(size_t slot) const {
    return values_.data() + slot * slot_stride_;
}

size_t ToroidalKVCache::slotIndex(uint64_t seq) const {
    return static_cast<size_t>(seq % max_tokens_);
}

} // namespace rawrxd
