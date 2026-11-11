// ============================================================================
// 32K Context Optimized KV Cache Implementation
// ============================================================================
// Memory-efficient KV cache with INT8 quantization for 32k context
// ============================================================================

#include "kv_cache_32k.hpp"
#include <cstring>
#include <cmath>

namespace RawrXD {
namespace Inference {

KVCache32K::KVCache32K(uint32_t num_kv_heads, uint32_t head_dim,
                       uint32_t max_seq_len, uint32_t window_size)
    : num_kv_heads_(num_kv_heads),
      head_dim_(head_dim),
      max_seq_len_(max_seq_len),
      window_size_(window_size),
      cache_len_(0) {
    
    // Initialize heads
    heads_.resize(num_kv_heads);
    for (auto& head : heads_) {
        // Allocate quantized buffers
        head.k_q8 = new int8_t[max_seq_len * head_dim];
        head.v_q8 = new int8_t[max_seq_len * head_dim];
        
        // Allocate recent window buffers (FP32 for accuracy)
        head.k_recent = new float[window_size * head_dim];
        head.v_recent = new float[window_size * head_dim];
        head.recent_start = 0;
        
        // Initialize scales
        head.k_scale = 1.0f;
        head.v_scale = 1.0f;
    }
    
    // Working buffers
    k_dequantized_.resize(head_dim);
    v_dequantized_.resize(head_dim);
}

KVCache32K::~KVCache32K() {
    for (auto& head : heads_) {
        delete[] head.k_q8;
        delete[] head.v_q8;
        delete[] head.k_recent;
        delete[] head.v_recent;
    }
}

void KVCache32K::AppendK(uint32_t head_idx, const float* k_values) {
    if (cache_len_ >= max_seq_len_) return;
    
    auto& head = heads_[head_idx];
    
    // Quantize and store
    QuantizeK(head_idx, cache_len_, k_values);
    
    // Also store in recent window
    uint32_t recent_idx = cache_len_ % window_size_;
    std::memcpy(&head.k_recent[recent_idx * head_dim_], k_values, head_dim_ * sizeof(float));
    
    if (head_idx == num_kv_heads_ - 1) {
        cache_len_++;
    }
}

void KVCache32K::AppendV(uint32_t head_idx, const float* v_values) {
    if (cache_len_ >= max_seq_len_) return;
    
    auto& head = heads_[head_idx];
    
    // Quantize and store
    QuantizeV(head_idx, cache_len_, v_values);
    
    // Also store in recent window
    uint32_t recent_idx = cache_len_ % window_size_;
    std::memcpy(&head.v_recent[recent_idx * head_dim_], v_values, head_dim_ * sizeof(float));
}

const float* KVCache32K::GetK(uint32_t head_idx, uint32_t pos) const {
    if (IsRecent(pos)) {
        // Return from recent window (FP32)
        const auto& head = heads_[head_idx];
        uint32_t recent_idx = GetRecentIndex(pos);
        return &head.k_recent[recent_idx * head_dim_];
    } else {
        // Dequantize on-the-fly
        DequantizeK(head_idx, pos, k_dequantized_.data());
        return k_dequantized_.data();
    }
}

const float* KVCache32K::GetV(uint32_t head_idx, uint32_t pos) const {
    if (IsRecent(pos)) {
        const auto& head = heads_[head_idx];
        uint32_t recent_idx = GetRecentIndex(pos);
        return &head.v_recent[recent_idx * head_dim_];
    } else {
        DequantizeV(head_idx, pos, v_dequantized_.data());
        return v_dequantized_.data();
    }
}

void KVCache32K::QuantizeK(uint32_t head_idx, uint32_t pos, const float* values) {
    auto& head = heads_[head_idx];
    
    // Find max abs for scaling
    float max_abs = 0.0f;
    for (uint32_t i = 0; i < head_dim_; i++) {
        max_abs = std::max(max_abs, std::abs(values[i]));
    }
    
    // Update scale (running average)
    float new_scale = max_abs > 0.0f ? max_abs / 127.0f : 1.0f;
    head.k_scale = head.k_scale * 0.9f + new_scale * 0.1f;
    
    // Quantize
    float inv_scale = 1.0f / head.k_scale;
    for (uint32_t i = 0; i < head_dim_; i++) {
        int32_t q = static_cast<int32_t>(values[i] * inv_scale);
        q = std::max(-127, std::min(127, q));
        head.k_q8[pos * head_dim_ + i] = static_cast<int8_t>(q);
    }
}

void KVCache32K::QuantizeV(uint32_t head_idx, uint32_t pos, const float* values) {
    auto& head = heads_[head_idx];
    
    float max_abs = 0.0f;
    for (uint32_t i = 0; i < head_dim_; i++) {
        max_abs = std::max(max_abs, std::abs(values[i]));
    }
    
    float new_scale = max_abs > 0.0f ? max_abs / 127.0f : 1.0f;
    head.v_scale = head.v_scale * 0.9f + new_scale * 0.1f;
    
    float inv_scale = 1.0f / head.v_scale;
    for (uint32_t i = 0; i < head_dim_; i++) {
        int32_t q = static_cast<int32_t>(values[i] * inv_scale);
        q = std::max(-127, std::min(127, q));
        head.v_q8[pos * head_dim_ + i] = static_cast<int8_t>(q);
    }
}

void KVCache32K::DequantizeK(uint32_t head_idx, uint32_t pos, float* output) const {
    const auto& head = heads_[head_idx];
    for (uint32_t i = 0; i < head_dim_; i++) {
        output[i] = head.k_q8[pos * head_dim_ + i] * head.k_scale;
    }
}

void KVCache32K::DequantizeV(uint32_t head_idx, uint32_t pos, float* output) const {
    const auto& head = heads_[head_idx];
    for (uint32_t i = 0; i < head_dim_; i++) {
        output[i] = head.v_q8[pos * head_dim_ + i] * head.v_scale;
    }
}

bool KVCache32K::IsRecent(uint32_t pos) const {
    return pos >= cache_len_ - window_size_;
}

uint32_t KVCache32K::GetRecentIndex(uint32_t pos) const {
    return pos % window_size_;
}

void KVCache32K::Clear() {
    cache_len_ = 0;
    for (auto& head : heads_) {
        head.recent_start = 0;
        head.k_scale = 1.0f;
        head.v_scale = 1.0f;
    }
}

size_t KVCache32K::GetMemoryUsage() const {
    // INT8 for long history + FP32 for recent window
    size_t quantized = num_kv_heads_ * max_seq_len_ * head_dim_ * 2 * sizeof(int8_t);  // K + V
    size_t recent = num_kv_heads_ * window_size_ * head_dim_ * 2 * sizeof(float);      // K + V
    size_t scales = num_kv_heads_ * 2 * sizeof(float);
    return quantized + recent + scales;
}

size_t KVCache32K::GetFP32MemoryUsage() const {
    // Full FP32 would be:
    return num_kv_heads_ * max_seq_len_ * head_dim_ * 2 * sizeof(float);
}

float KVCache32K::GetCompressionRatio() const {
    return static_cast<float>(GetFP32MemoryUsage()) / static_cast<float>(GetMemoryUsage());
}

// Ring buffer implementation
RingBufferKVCache::RingBufferKVCache(uint32_t num_heads, uint32_t head_dim, uint32_t capacity)
    : num_heads_(num_heads), head_dim_(head_dim), capacity_(capacity), size_(0), head_(0) {
    k_buffer_.resize(num_heads * capacity * head_dim);
    v_buffer_.resize(num_heads * capacity * head_dim);
}

void RingBufferKVCache::Append(const float* k_values, const float* v_values) {
    for (uint32_t h = 0; h < num_heads_; h++) {
        std::memcpy(&k_buffer_[(h * capacity_ + head_) * head_dim_],
                    &k_values[h * head_dim_], head_dim_ * sizeof(float));
        std::memcpy(&v_buffer_[(h * capacity_ + head_) * head_dim_],
                    &v_values[h * head_dim_], head_dim_ * sizeof(float));
    }
    
    head_ = (head_ + 1) % capacity_;
    if (size_ < capacity_) size_++;
}

void RingBufferKVCache::GetKV(uint32_t pos, float* k_out, float* v_out) const {
    uint32_t idx = (head_ + capacity_ - size_ + pos) % capacity_;
    for (uint32_t h = 0; h < num_heads_; h++) {
        std::memcpy(&k_out[h * head_dim_],
                    &k_buffer_[(h * capacity_ + idx) * head_dim_], head_dim_ * sizeof(float));
        std::memcpy(&v_out[h * head_dim_],
                    &v_buffer_[(h * capacity_ + idx) * head_dim_], head_dim_ * sizeof(float));
    }
}

} // namespace Inference
} // namespace RawrXD
