// ============================================================================
// Optimized Transformer Implementation - SREM + AVX2
// ============================================================================

#include "optimized_transformer.hpp"
#include <chrono>
#include <cmath>
#include <algorithm>

namespace rawrxd {
namespace kernels {

// ============================================================================
// SREM KV Cache Implementation
// ============================================================================
bool SREMKVCache::Initialize(size_t max_batch, size_t max_seq,
                              size_t num_kv_heads, size_t head_dim) {
    max_batch_ = max_batch;
    max_seq_ = max_seq;
    num_kv_heads_ = num_kv_heads;
    head_dim_ = head_dim;
    kv_stride_ = num_kv_heads * head_dim;
    
    // Allocate cache: [batch, seq, num_kv_heads, head_dim]
    size_t cache_size = max_batch * max_seq * kv_stride_;
    k_cache_.resize(cache_size, 0.0f);
    v_cache_.resize(cache_size, 0.0f);
    current_length_ = 0;
    
    return true;
}

float* SREMKVCache::GetKWritePtr(size_t batch_idx, size_t seq_idx) {
    return &k_cache_[(batch_idx * max_seq_ + seq_idx) * kv_stride_];
}

float* SREMKVCache::GetVWritePtr(size_t batch_idx, size_t seq_idx) {
    return &v_cache_[(batch_idx * max_seq_ + seq_idx) * kv_stride_];
}

const float* SREMKVCache::GetKReadPtr(size_t batch_idx, size_t start_seq) const {
    return &k_cache_[(batch_idx * max_seq_ + start_seq) * kv_stride_];
}

const float* SREMKVCache::GetVReadPtr(size_t batch_idx, size_t start_seq) const {
    return &v_cache_[(batch_idx * max_seq_ + start_seq) * kv_stride_];
}

void SREMKVCache::Clear() {
    std::fill(k_cache_.begin(), k_cache_.end(), 0.0f);
    std::fill(v_cache_.begin(), v_cache_.end(), 0.0f);
    current_length_ = 0;
}

// ============================================================================
// Optimized Transformer Layer Implementation
// ============================================================================
OptimizedTransformerLayer::OptimizedTransformerLayer() = default;
OptimizedTransformerLayer::~OptimizedTransformerLayer() = default;

bool OptimizedTransformerLayer::Initialize(const OptimizedLayerWeights& weights,
                                           const OptimizedTransformerConfig& config) {
    weights_ = weights;
    config_ = config;
    
    // Pre-allocate working buffers
    size_t max_tokens = config_.tile_size;
    size_t hidden = config_.hidden_size;
    size_t intermediate = config_.intermediate_size;
    
    q_buf_.resize(max_tokens * hidden);
    k_buf_.resize(max_tokens * hidden);
    v_buf_.resize(max_tokens * hidden);
    attn_out_buf_.resize(max_tokens * hidden);
    ffn_gate_buf_.resize(max_tokens * intermediate);
    ffn_up_buf_.resize(max_tokens * intermediate);
    ffn_out_buf_.resize(max_tokens * hidden);
    normed_buf_.resize(max_tokens * hidden);
    
    // Attention scores: [num_heads, seq_len, total_len]
    size_t max_seq = config_.max_seq_len;
    attn_scores_.resize(config_.num_heads * max_seq * max_seq);
    
    initialized_ = true;
    return true;
}

bool OptimizedTransformerLayer::Forward(const float* input,
                                         float* output,
                                         size_t batch_size,
                                         size_t seq_len,
                                         SREMKVCache* kv_cache,
                                         size_t kv_cache_len) {
    if (!initialized_) return false;
    
    auto start = std::chrono::high_resolution_clock::now();
    size_t total_tokens = batch_size * seq_len;
    size_t hidden = config_.hidden_size;
    
    // ========== Attention Block ==========
    auto attn_start = std::chrono::high_resolution_clock::now();
    
    // 1. Input RMS Norm using AVX2
    std::copy(input, input + total_tokens * hidden, normed_buf_.data());
    for (size_t b = 0; b < batch_size; b++) {
        for (size_t s = 0; s < seq_len; s++) {
            size_t offset = (b * seq_len + s) * hidden;
            AVX2_RMSNorm(&normed_buf_[offset], weights_.input_layernorm.data(), 
                        hidden, 1e-6f);
        }
    }
    
    // 2. Q, K, V projections using AVX2 GEMM
    // Q: [total_tokens, hidden] × [hidden, hidden] → [total_tokens, hidden]
    AVX2_Gemm_F32_F32(normed_buf_.data(), weights_.q_proj.data(), q_buf_.data(),
                      total_tokens, hidden, hidden, true);
    
    // K: [total_tokens, hidden] × [hidden, head_dim * num_kv_heads]
    size_t kv_hidden = config_.head_dim * config_.num_kv_heads;
    AVX2_Gemm_F32_F32(normed_buf_.data(), weights_.k_proj.data(), k_buf_.data(),
                      total_tokens, kv_hidden, hidden, true);
    
    // V: [total_tokens, hidden] × [hidden, head_dim * num_kv_heads]
    AVX2_Gemm_F32_F32(normed_buf_.data(), weights_.v_proj.data(), v_buf_.data(),
                      total_tokens, kv_hidden, hidden, true);
    
    // 3. Rotary embeddings
    ApplyRotaryEmbeddings(q_buf_.data(), k_buf_.data(), seq_len, kv_cache_len);
    
    // 4. Update KV cache
    if (kv_cache) {
        for (size_t b = 0; b < batch_size; b++) {
            for (size_t s = 0; s < seq_len; s++) {
                size_t src_idx = (b * seq_len + s) * kv_hidden;
                float* k_dst = kv_cache->GetKWritePtr(b, kv_cache_len + s);
                float* v_dst = kv_cache->GetVWritePtr(b, kv_cache_len + s);
                std::memcpy(k_dst, &k_buf_[src_idx], kv_hidden * sizeof(float));
                std::memcpy(v_dst, &v_buf_[src_idx], kv_hidden * sizeof(float));
            }
        }
    }
    
    // 5. Attention computation
    size_t total_len = kv_cache_len + seq_len;
    ComputeAttention(q_buf_.data(), k_buf_.data(), v_buf_.data(),
                     attn_out_buf_.data(), batch_size, seq_len, total_len);
    
    // 6. Output projection
    AVX2_Gemm_F32_F32(attn_out_buf_.data(), weights_.o_proj.data(), 
                      attn_out_buf_.data(), total_tokens, hidden, hidden, true);
    
    // 7. Residual connection
    for (size_t i = 0; i < total_tokens * hidden; i++) {
        attn_out_buf_[i] = input[i] + attn_out_buf_[i];
    }
    
    auto attn_end = std::chrono::high_resolution_clock::now();
    attention_time_ms_ = std::chrono::duration<double, std::milli>(attn_end - attn_start).count();
    
    // ========== FFN Block ==========
    auto ffn_start = std::chrono::high_resolution_clock::now();
    
    // 8. Post-attention RMS Norm
    std::copy(attn_out_buf_.data(), attn_out_buf_.data() + total_tokens * hidden, 
              normed_buf_.data());
    for (size_t b = 0; b < batch_size; b++) {
        for (size_t s = 0; s < seq_len; s++) {
            size_t offset = (b * seq_len + s) * hidden;
            AVX2_RMSNorm(&normed_buf_[offset], weights_.post_attention_layernorm.data(),
                        hidden, 1e-6f);
        }
    }
    
    // 9. FFN projections
    AVX2_Gemm_F32_F32(normed_buf_.data(), weights_.gate_proj.data(),
                      ffn_gate_buf_.data(), total_tokens, config_.intermediate_size, 
                      hidden, true);
    AVX2_Gemm_F32_F32(normed_buf_.data(), weights_.up_proj.data(),
                      ffn_up_buf_.data(), total_tokens, config_.intermediate_size,
                      hidden, true);
    
    // 10. SiLU activation and multiply
    AVX2_SiLU(ffn_gate_buf_.data(), total_tokens * config_.intermediate_size);
    for (size_t i = 0; i < total_tokens * config_.intermediate_size; i++) {
        ffn_up_buf_[i] = ffn_gate_buf_[i] * ffn_up_buf_[i];
    }
    
    // 11. Down projection
    AVX2_Gemm_F32_F32(ffn_up_buf_.data(), weights_.down_proj.data(),
                      ffn_out_buf_.data(), total_tokens, hidden, 
                      config_.intermediate_size, true);
    
    // 12. Residual connection
    for (size_t i = 0; i < total_tokens * hidden; i++) {
        output[i] = attn_out_buf_[i] + ffn_out_buf_[i];
    }
    
    auto ffn_end = std::chrono::high_resolution_clock::now();
    ffn_time_ms_ = std::chrono::duration<double, std::milli>(ffn_end - ffn_start).count();
    
    auto end = std::chrono::high_resolution_clock::now();
    last_forward_time_ms_ = std::chrono::duration<double, std::milli>(end - start).count();
    
    return true;
}

bool OptimizedTransformerLayer::ComputeAttention(const float* q, const float* k, 
                                                  const float* v,
                                                  float* output,
                                                  size_t batch_size, 
                                                  size_t seq_len, 
                                                  size_t total_len) {
    size_t num_heads = config_.num_heads;
    size_t head_dim = config_.head_dim;
    size_t num_kv_heads = config_.num_kv_heads;
    size_t hidden = config_.hidden_size;
    
    float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    
    // Multi-head attention with GQA support
    for (size_t b = 0; b < batch_size; b++) {
        for (size_t h = 0; h < num_heads; h++) {
            // Map query head to KV head (GQA)
            size_t kv_h = h * num_kv_heads / num_heads;
            
            for (size_t q_pos = 0; q_pos < seq_len; q_pos++) {
                // Compute attention scores: Q @ K^T
                for (size_t k_pos = 0; k_pos < total_len; k_pos++) {
                    float dot = 0.0f;
                    
                    for (size_t d = 0; d < head_dim; d++) {
                        size_t q_idx = ((b * seq_len + q_pos) * num_heads + h) * head_dim + d;
                        size_t k_idx = ((b * total_len + k_pos) * num_kv_heads + kv_h) * head_dim + d;
                        
                        dot += q[q_idx] * k[k_idx];
                    }
                    
                    size_t score_idx = (h * seq_len + q_pos) * total_len + k_pos;
                    attn_scores_[score_idx] = dot * scale;
                }
            }
            
            // Softmax per query position
            for (size_t q_pos = 0; q_pos < seq_len; q_pos++) {
                size_t score_offset = (h * seq_len + q_pos) * total_len;
                AVX2_Softmax(&attn_scores_[score_offset], total_len);
            }
        }
        
        // Attention @ V
        for (size_t q_pos = 0; q_pos < seq_len; q_pos++) {
            for (size_t h = 0; h < num_heads; h++) {
                size_t kv_h = h * num_kv_heads / num_heads;
                
                for (size_t d = 0; d < head_dim; d++) {
                    float sum = 0.0f;
                    
                    for (size_t k_pos = 0; k_pos < total_len; k_pos++) {
                        size_t score_idx = (h * seq_len + q_pos) * total_len + k_pos;
                        size_t v_idx = ((b * total_len + k_pos) * num_kv_heads + kv_h) * head_dim + d;
                        
                        sum += attn_scores_[score_idx] * v[v_idx];
                    }
                    
                    size_t out_idx = ((b * seq_len + q_pos) * num_heads + h) * head_dim + d;
                    output[out_idx] = sum;
                }
            }
        }
    }
    
    return true;
}

bool OptimizedTransformerLayer::ApplyRotaryEmbeddings(float* q, float* k,
                                                       size_t seq_len, 
                                                       size_t offset) {
    size_t num_heads = config_.num_heads;
    size_t num_kv_heads = config_.num_kv_heads;
    size_t head_dim = config_.head_dim;
    float theta = 10000.0f;
    
    // Apply RoPE to Q
    for (size_t pos = 0; pos < seq_len; pos++) {
        for (size_t h = 0; h < num_heads; h++) {
            for (size_t d = 0; d < head_dim; d += 2) {
                size_t idx = (pos * num_heads + h) * head_dim + d;
                
                float angle = (pos + offset) / std::pow(theta, (2.0f * d) / head_dim);
                float cos_a = std::cos(angle);
                float sin_a = std::sin(angle);
                
                float q0 = q[idx];
                float q1 = q[idx + 1];
                q[idx] = q0 * cos_a - q1 * sin_a;
                q[idx + 1] = q0 * sin_a + q1 * cos_a;
            }
        }
    }
    
    // Apply RoPE to K
    for (size_t pos = 0; pos < seq_len; pos++) {
        for (size_t h = 0; h < num_kv_heads; h++) {
            for (size_t d = 0; d < head_dim; d += 2) {
                size_t idx = (pos * num_kv_heads + h) * head_dim + d;
                
                float angle = (pos + offset) / std::pow(theta, (2.0f * d) / head_dim);
                float cos_a = std::cos(angle);
                float sin_a = std::sin(angle);
                
                float k0 = k[idx];
                float k1 = k[idx + 1];
                k[idx] = k0 * cos_a - k1 * sin_a;
                k[idx + 1] = k0 * sin_a + k1 * cos_a;
            }
        }
    }
    
    return true;
}

// ============================================================================
// Optimized Model Implementation
// ============================================================================
OptimizedModel::OptimizedModel() = default;
OptimizedModel::~OptimizedModel() = default;

bool OptimizedModel::Initialize(const OptimizedTransformerConfig& config) {
    config_ = config;
    
    // Initialize KV cache
    kv_cache_ = std::make_unique<SREMKVCache>();
    if (!kv_cache_->Initialize(1, config.max_seq_len, 
                               config.num_kv_heads, config.head_dim)) {
        return false;
    }
    
    return true;
}

bool OptimizedModel::Forward(const std::vector<int32_t>& tokens,
                              std::vector<float>& logits,
                              size_t batch_size) {
    auto start = std::chrono::high_resolution_clock::now();
    
    size_t seq_len = tokens.size() / batch_size;
    size_t hidden = config_.hidden_size;
    
    // Embedding lookup
    std::vector<float> hidden_states(batch_size * seq_len * hidden);
    for (size_t b = 0; b < batch_size; b++) {
        for (size_t s = 0; s < seq_len; s++) {
            int32_t token_id = tokens[b * seq_len + s];
            size_t offset = (b * seq_len + s) * hidden;
            
            // Copy embedding for this token
            if (token_id >= 0 && token_id < static_cast<int32_t>(vocab_size_)) {
                std::copy(&token_embeddings_[token_id * hidden],
                         &token_embeddings_[(token_id + 1) * hidden],
                         &hidden_states[offset]);
            }
        }
    }
    
    // Pass through transformer layers
    std::vector<float> layer_output(batch_size * seq_len * hidden);
    
    for (size_t layer_idx = 0; layer_idx < layers_.size(); layer_idx++) {
        auto& layer = layers_[layer_idx];
        
        if (!layer->Forward(hidden_states.data(), layer_output.data(),
                           batch_size, seq_len, kv_cache_.get(),
                           kv_cache_->GetCurrentLength())) {
            return false;
        }
        
        std::swap(hidden_states, layer_output);
        kv_cache_->Advance(seq_len);
    }
    
    // Final RMS norm
    for (size_t b = 0; b < batch_size; b++) {
        for (size_t s = 0; s < seq_len; s++) {
            size_t offset = (b * seq_len + s) * hidden;
            AVX2_RMSNorm(&hidden_states[offset], output_norm_.data(), hidden, 1e-6f);
        }
    }
    
    // LM head projection
    logits.resize(batch_size * seq_len * vocab_size_);
    for (size_t b = 0; b < batch_size; b++) {
        for (size_t s = 0; s < seq_len; s++) {
            size_t hidden_offset = (b * seq_len + s) * hidden;
            size_t logits_offset = (b * seq_len + s) * vocab_size_;
            
            AVX2_Gemm_F32_F32(&hidden_states[hidden_offset], lm_head_.data(),
                             &logits[logits_offset], 1, vocab_size_, hidden, true);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    last_latency_ms_ = std::chrono::duration<double, std::milli>(end - start).count();
    total_tokens_generated_ += batch_size * seq_len;
    
    return true;
}

double OptimizedModel::GetTokensPerSecond() const {
    if (last_latency_ms_ <= 0.0) return 0.0;
    return 1000.0 / last_latency_ms_;
}

} // namespace kernels
} // namespace rawrxd
