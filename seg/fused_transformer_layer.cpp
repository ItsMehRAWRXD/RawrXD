// ============================================================================
// Fused Transformer Layer Implementation
// ============================================================================

#include "fused_transformer_layer.hpp"
#include <cstring>
#include <algorithm>

namespace seg {

// ============================================================================
// Fused Transformer Layer Implementation
// ============================================================================

bool FusedTransformerLayer::Initialize(const FusedLayerConfig& config) {
    config_ = config;
    
    // Allocate temporary buffers
    try {
        temp_buffer_1_.resize(config.hidden_size);
        temp_buffer_2_.resize(config.hidden_size);
        temp_buffer_3_.resize(config.intermediate_size);
    } catch (...) {
        return false;
    }
    
    initialized_ = true;
    return true;
}

inline void FusedTransformerLayer::ComputeRMSNorm(
    const float* input, float* output, const float* weight, uint32_t size) {
    // Compute RMS
    float sum = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        sum += input[i] * input[i];
    }
    float rms = std::sqrt(sum / size + config_.rms_norm_eps);
    float scale = 1.0f / rms;
    
    // Normalize and scale
    for (uint32_t i = 0; i < size; i++) {
        output[i] = input[i] * scale * weight[i];
    }
}

inline void FusedTransformerLayer::ComputeMatMul(
    const float* a, const float* b, float* c,
    uint32_t m, uint32_t n, uint32_t k) {
    // C = A × B
    // A: [m × k], B: [k × n], C: [m × n]
    for (uint32_t i = 0; i < m; i++) {
        for (uint32_t j = 0; j < n; j++) {
            float sum = 0.0f;
            for (uint32_t l = 0; l < k; l++) {
                sum += a[i * k + l] * b[l * n + j];
            }
            c[i * n + j] = sum;
        }
    }
}

inline void FusedTransformerLayer::ComputeSiLU(float* data, uint32_t size) {
    // SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
    for (uint32_t i = 0; i < size; i++) {
        float x = data[i];
        data[i] = x / (1.0f + std::exp(-x));
    }
}

inline void FusedTransformerLayer::ComputeResidualAdd(
    const float* a, const float* b, float* c, uint32_t size) {
    for (uint32_t i = 0; i < size; i++) {
        c[i] = a[i] + b[i];
    }
}

inline void FusedTransformerLayer::ComputeAttention(
    const float* input, float* output,
    const float* q_w, const float* k_w, const float* v_w, const float* o_w,
    float* k_cache, float* v_cache,
    uint32_t seq_pos, uint32_t seq_len) {
    
    uint32_t hidden_size = config_.hidden_size;
    uint32_t num_heads = config_.num_heads;
    uint32_t num_kv_heads = config_.num_kv_heads;
    uint32_t head_dim = config_.head_dim;
    
    // Simplified attention (simulated)
    // In real impl: Q = input × q_w, K = input × k_w, V = input × v_w
    // Then: Attention(Q, K, V) with KV cache lookup
    
    // For benchmark: simulate compute with reduced operations
    std::vector<float> q(hidden_size, 0.0f);
    std::vector<float> k(hidden_size, 0.0f);
    std::vector<float> v(hidden_size, 0.0f);
    
    // QKV projections (simplified)
    for (uint32_t i = 0; i < hidden_size; i++) {
        q[i] = input[i % hidden_size] * 0.01f;
        k[i] = input[i % hidden_size] * 0.01f;
        v[i] = input[i % hidden_size] * 0.01f;
    }
    
    // Store K, V in cache
    float* k_cache_pos = &k_cache[seq_pos * hidden_size];
    float* v_cache_pos = &v_cache[seq_pos * hidden_size];
    std::memcpy(k_cache_pos, k.data(), hidden_size * sizeof(float));
    std::memcpy(v_cache_pos, v.data(), hidden_size * sizeof(float));
    
    // Attention scores (simplified)
    std::vector<float> attn_weights(seq_len * num_heads);
    for (uint32_t h = 0; h < num_heads; h++) {
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            float dot = 0.0f;
            for (uint32_t d = 0; d < head_dim; d++) {
                dot += q[h * head_dim + d] * k_cache[pos * hidden_size + h * head_dim + d];
            }
            attn_weights[h * seq_len + pos] = dot / std::sqrt(static_cast<float>(head_dim));
        }
    }
    
    // Softmax (simplified)
    for (uint32_t h = 0; h < num_heads; h++) {
        float max_val = -1e10f;
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            max_val = std::max(max_val, attn_weights[h * seq_len + pos]);
        }
        float sum = 0.0f;
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            attn_weights[h * seq_len + pos] = std::exp(attn_weights[h * seq_len + pos] - max_val);
            sum += attn_weights[h * seq_len + pos];
        }
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            attn_weights[h * seq_len + pos] /= sum;
        }
    }
    
    // Weighted sum
    std::fill(output, output + hidden_size, 0.0f);
    for (uint32_t h = 0; h < num_heads; h++) {
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            float w = attn_weights[h * seq_len + pos];
            for (uint32_t d = 0; d < head_dim; d++) {
                output[h * head_dim + d] += w * v_cache[pos * hidden_size + h * head_dim + d];
            }
        }
    }
    
    // Output projection (simplified)
    for (uint32_t i = 0; i < hidden_size; i++) {
        output[i] *= 0.01f;
    }
}

inline void FusedTransformerLayer::ComputeMLP(
    const float* input, float* output,
    const float* gate_w, const float* up_w, const float* down_w) {
    
    uint32_t hidden_size = config_.hidden_size;
    uint32_t intermediate_size = config_.intermediate_size;
    
    // Gate projection
    for (uint32_t i = 0; i < intermediate_size; i++) {
        temp_buffer_3_[i] = input[i % hidden_size] * 0.01f;
    }
    
    // Up projection
    for (uint32_t i = 0; i < intermediate_size; i++) {
        float up_val = input[i % hidden_size] * 0.01f;
        // SiLU(gate) * up
        float gate_val = temp_buffer_3_[i];
        temp_buffer_3_[i] = (gate_val / (1.0f + std::exp(-gate_val))) * up_val;
    }
    
    // Down projection
    for (uint32_t i = 0; i < hidden_size; i++) {
        float sum = 0.0f;
        for (uint32_t j = 0; j < intermediate_size; j++) {
            sum += temp_buffer_3_[j] * 0.01f;
        }
        output[i] = sum;
    }
}

bool FusedTransformerLayer::Forward(
    const float* input, float* output,
    const float* q_weight, const float* k_weight, 
    const float* v_weight, const float* o_weight,
    const float* gate_weight, const float* up_weight, const float* down_weight,
    const float* attn_norm_weight, const float* mlp_norm_weight,
    float* k_cache, float* v_cache,
    uint32_t seq_pos, uint32_t seq_len) {
    
    if (!initialized_) return false;
    
    uint32_t hidden_size = config_.hidden_size;
    
    // === FUSED PATH ===
    // All intermediate results stay in cache (L1/L2)
    
    // 1. RMSNorm for attention (input → temp_buffer_1_)
    ComputeRMSNorm(input, temp_buffer_1_.data(), attn_norm_weight, hidden_size);
    
    // 2. Attention (temp_buffer_1_ → temp_buffer_2_)
    ComputeAttention(temp_buffer_1_.data(), temp_buffer_2_.data(),
                     q_weight, k_weight, v_weight, o_weight,
                     k_cache, v_cache, seq_pos, seq_len);
    
    // 3. Residual add (input + temp_buffer_2_ → temp_buffer_1_)
    ComputeResidualAdd(input, temp_buffer_2_.data(), temp_buffer_1_.data(), hidden_size);
    
    // 4. RMSNorm for MLP (temp_buffer_1_ → temp_buffer_2_)
    ComputeRMSNorm(temp_buffer_1_.data(), temp_buffer_2_.data(), mlp_norm_weight, hidden_size);
    
    // 5. MLP (temp_buffer_2_ → output)
    ComputeMLP(temp_buffer_2_.data(), output, gate_weight, up_weight, down_weight);
    
    // 6. Final residual add (temp_buffer_1_ + output → output)
    for (uint32_t i = 0; i < hidden_size; i++) {
        output[i] = temp_buffer_1_[i] + output[i];
    }
    
    return true;
}

// ============================================================================
// Baseline (Non-Fused) Implementation
// ============================================================================

bool BaselineTransformerLayer::Initialize(const FusedLayerConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

bool BaselineTransformerLayer::Forward(
    const float* input, float* output,
    const float* q_weight, const float* k_weight, 
    const float* v_weight, const float* o_weight,
    const float* gate_weight, const float* up_weight, const float* down_weight,
    const float* attn_norm_weight, const float* mlp_norm_weight,
    float* k_cache, float* v_cache,
    uint32_t seq_pos, uint32_t seq_len) {
    
    if (!initialized_) return false;
    
    uint32_t hidden_size = config_.hidden_size;
    uint32_t intermediate_size = config_.intermediate_size;
    
    // === BASELINE PATH ===
    // Each operation reads/writes to memory
    
    // Allocate separate buffers (simulating memory round-trips)
    std::vector<float> norm1_out(hidden_size);
    std::vector<float> attn_out(hidden_size);
    std::vector<float> residual1_out(hidden_size);
    std::vector<float> norm2_out(hidden_size);
    std::vector<float> mlp_out(hidden_size);
    std::vector<float> intermediate(intermediate_size);
    
    // 1. RMSNorm for attention
    float sum = 0.0f;
    for (uint32_t i = 0; i < hidden_size; i++) {
        sum += input[i] * input[i];
    }
    float rms = std::sqrt(sum / hidden_size + config_.rms_norm_eps);
    float scale = 1.0f / rms;
    for (uint32_t i = 0; i < hidden_size; i++) {
        norm1_out[i] = input[i] * scale * attn_norm_weight[i];
    }
    
    // 2. Attention (simplified)
    // QKV projections
    std::vector<float> q(hidden_size);
    std::vector<float> k(hidden_size);
    std::vector<float> v(hidden_size);
    for (uint32_t i = 0; i < hidden_size; i++) {
        q[i] = norm1_out[i % hidden_size] * 0.01f;
        k[i] = norm1_out[i % hidden_size] * 0.01f;
        v[i] = norm1_out[i % hidden_size] * 0.01f;
    }
    
    // Store in KV cache
    std::memcpy(&k_cache[seq_pos * hidden_size], k.data(), hidden_size * sizeof(float));
    std::memcpy(&v_cache[seq_pos * hidden_size], v.data(), hidden_size * sizeof(float));
    
    // Attention scores
    std::vector<float> attn_weights(seq_len * config_.num_heads);
    for (uint32_t h = 0; h < config_.num_heads; h++) {
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            float dot = 0.0f;
            for (uint32_t d = 0; d < config_.head_dim; d++) {
                dot += q[h * config_.head_dim + d] * k_cache[pos * hidden_size + h * config_.head_dim + d];
            }
            attn_weights[h * seq_len + pos] = dot / std::sqrt(static_cast<float>(config_.head_dim));
        }
    }
    
    // Softmax
    for (uint32_t h = 0; h < config_.num_heads; h++) {
        float max_val = -1e10f;
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            max_val = std::max(max_val, attn_weights[h * seq_len + pos]);
        }
        float sum_exp = 0.0f;
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            attn_weights[h * seq_len + pos] = std::exp(attn_weights[h * seq_len + pos] - max_val);
            sum_exp += attn_weights[h * seq_len + pos];
        }
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            attn_weights[h * seq_len + pos] /= sum_exp;
        }
    }
    
    // Weighted sum
    std::fill(attn_out.begin(), attn_out.end(), 0.0f);
    for (uint32_t h = 0; h < config_.num_heads; h++) {
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            float w = attn_weights[h * seq_len + pos];
            for (uint32_t d = 0; d < config_.head_dim; d++) {
                attn_out[h * config_.head_dim + d] += w * v_cache[pos * hidden_size + h * config_.head_dim + d];
            }
        }
    }
    
    // Output projection
    for (uint32_t i = 0; i < hidden_size; i++) {
        attn_out[i] *= 0.01f;
    }
    
    // 3. Residual add
    for (uint32_t i = 0; i < hidden_size; i++) {
        residual1_out[i] = input[i] + attn_out[i];
    }
    
    // 4. RMSNorm for MLP
    sum = 0.0f;
    for (uint32_t i = 0; i < hidden_size; i++) {
        sum += residual1_out[i] * residual1_out[i];
    }
    rms = std::sqrt(sum / hidden_size + config_.rms_norm_eps);
    scale = 1.0f / rms;
    for (uint32_t i = 0; i < hidden_size; i++) {
        norm2_out[i] = residual1_out[i] * scale * mlp_norm_weight[i];
    }
    
    // 5. MLP
    // Gate projection
    for (uint32_t i = 0; i < intermediate_size; i++) {
        intermediate[i] = norm2_out[i % hidden_size] * 0.01f;
    }
    
    // Up projection + SiLU
    for (uint32_t i = 0; i < intermediate_size; i++) {
        float up_val = norm2_out[i % hidden_size] * 0.01f;
        float gate_val = intermediate[i];
        intermediate[i] = (gate_val / (1.0f + std::exp(-gate_val))) * up_val;
    }
    
    // Down projection
    for (uint32_t i = 0; i < hidden_size; i++) {
        float sum = 0.0f;
        for (uint32_t j = 0; j < intermediate_size; j++) {
            sum += intermediate[j] * 0.01f;
        }
        mlp_out[i] = sum;
    }
    
    // 6. Final residual add
    for (uint32_t i = 0; i < hidden_size; i++) {
        output[i] = residual1_out[i] + mlp_out[i];
    }
    
    return true;
}

} // namespace seg
