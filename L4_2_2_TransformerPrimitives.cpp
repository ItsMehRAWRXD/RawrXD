// L4_2_2_TransformerPrimitives.cpp
// L4.2.2 Transformer Block Primitives - Reference Implementation

#include "L4_2_2_TransformerPrimitives.h"
#include <iostream>
#include <cmath>
#include <algorithm>

namespace RawrXD {
namespace L4 {

// ============================================================================
// RMS Normalization
// ============================================================================

void RMSNorm_Reference(
    const float* x,
    const float* weight,
    float* output,
    const RMSNormConfig& config
) {
    // Compute RMS: sqrt(mean(x^2) + epsilon)
    float sum_sq = 0.0f;
    for (size_t i = 0; i < config.hidden_size; i++) {
        sum_sq += x[i] * x[i];
    }
    float mean_sq = sum_sq / config.hidden_size;
    float rms = std::sqrt(mean_sq + config.epsilon);
    float inv_rms = 1.0f / rms;
    
    // Normalize and apply learned weights
    for (size_t i = 0; i < config.hidden_size; i++) {
        output[i] = x[i] * inv_rms * weight[i];
    }
}

// ============================================================================
// RoPE (Rotary Positional Embedding)
// ============================================================================

RoPETables PrecomputeRoPE(const RoPEConfig& config) {
    RoPETables tables;
    tables.cos_table.resize(config.max_position * config.head_dim);
    tables.sin_table.resize(config.max_position * config.head_dim);
    
    // Precompute frequencies for each dimension pair
    // theta_i = base^(2i / head_dim) for i in [0, head_dim/2)
    std::vector<float> theta(config.head_dim / 2);
    for (size_t i = 0; i < config.head_dim / 2; i++) {
        theta[i] = std::pow(config.theta_base, -2.0f * i / config.head_dim);
    }
    
    // Precompute cos and sin for all positions
    for (size_t pos = 0; pos < config.max_position; pos++) {
        for (size_t i = 0; i < config.head_dim / 2; i++) {
            float angle = pos * theta[i];
            size_t idx = pos * config.head_dim + i;
            tables.cos_table[idx] = std::cos(angle);
            tables.sin_table[idx] = std::sin(angle);
            // Duplicate for the paired dimension
            tables.cos_table[idx + config.head_dim / 2] = std::cos(angle);
            tables.sin_table[idx + config.head_dim / 2] = std::sin(angle);
        }
    }
    
    return tables;
}

void ApplyRoPE_Reference(
    float* q,
    float* k,
    size_t position,
    const RoPEConfig& config,
    const RoPETables& tables
) {
    // Apply RoPE to each head
    for (size_t h = 0; h < config.num_heads; h++) {
        float* q_head = &q[h * config.head_dim];
        
        // Apply to query
        for (size_t i = 0; i < config.head_dim / 2; i++) {
            size_t idx = position * config.head_dim + i;
            float cos_val = tables.cos_table[idx];
            float sin_val = tables.sin_table[idx];
            
            float x0 = q_head[i];
            float x1 = q_head[i + config.head_dim / 2];
            
            // Rotation: [x0, x1] * [[cos, -sin], [sin, cos]]
            q_head[i] = x0 * cos_val - x1 * sin_val;
            q_head[i + config.head_dim / 2] = x0 * sin_val + x1 * cos_val;
        }
    }
    
    // Apply to keys (may have fewer heads for GQA)
    size_t num_kv_heads = config.num_heads;  // Simplified - should come from config
    for (size_t h = 0; h < num_kv_heads; h++) {
        float* k_head = &k[h * config.head_dim];
        
        for (size_t i = 0; i < config.head_dim / 2; i++) {
            size_t idx = position * config.head_dim + i;
            float cos_val = tables.cos_table[idx];
            float sin_val = tables.sin_table[idx];
            
            float x0 = k_head[i];
            float x1 = k_head[i + config.head_dim / 2];
            
            k_head[i] = x0 * cos_val - x1 * sin_val;
            k_head[i + config.head_dim / 2] = x0 * sin_val + x1 * cos_val;
        }
    }
}

// ============================================================================
// Attention
// ============================================================================

void Softmax_Reference(
    float* data,
    size_t num_heads,
    size_t seq_len
) {
    for (size_t h = 0; h < num_heads; h++) {
        float* scores = &data[h * seq_len];
        
        // Find max for numerical stability
        float max_val = scores[0];
        for (size_t i = 1; i < seq_len; i++) {
            max_val = std::max(max_val, scores[i]);
        }
        
        // Compute exp and sum
        float sum = 0.0f;
        for (size_t i = 0; i < seq_len; i++) {
            scores[i] = std::exp(scores[i] - max_val);
            sum += scores[i];
        }
        
        // Normalize
        float inv_sum = 1.0f / sum;
        for (size_t i = 0; i < seq_len; i++) {
            scores[i] *= inv_sum;
        }
    }
}

void Attention_Reference(
    const float* q,
    const float* k_cache,
    const float* v_cache,
    float* output,
    size_t seq_len,
    const AttentionConfig& config
) {
    float scale = config.scale > 0 ? config.scale : 1.0f / std::sqrt(config.head_dim);
    
    // Allocate attention scores buffer
    std::vector<float> scores(config.num_heads * seq_len);
    
    // For each head
    for (size_t h = 0; h < config.num_heads; h++) {
        const float* q_head = &q[h * config.head_dim];
        
        // Compute Q @ K^T for all positions
        for (size_t pos = 0; pos < seq_len; pos++) {
            // Map head to KV head (for GQA)
            size_t kv_head = h % config.num_kv_heads;
            const float* k_head = &k_cache[(kv_head * seq_len + pos) * config.head_dim];
            
            float dot = 0.0f;
            for (size_t d = 0; d < config.head_dim; d++) {
                dot += q_head[d] * k_head[d];
            }
            scores[h * seq_len + pos] = dot * scale;
        }
    }
    
    // Apply softmax
    Softmax_Reference(scores.data(), config.num_heads, seq_len);
    
    // Compute attention output: softmax(QK^T) @ V
    for (size_t h = 0; h < config.num_heads; h++) {
        float* out_head = &output[h * config.head_dim];
        const float* attn_weights = &scores[h * seq_len];
        
        // Initialize output to zero
        for (size_t d = 0; d < config.head_dim; d++) {
            out_head[d] = 0.0f;
        }
        
        // Weighted sum of values
        for (size_t pos = 0; pos < seq_len; pos++) {
            size_t kv_head = h % config.num_kv_heads;
            const float* v_head = &v_cache[(kv_head * seq_len + pos) * config.head_dim];
            float weight = attn_weights[pos];
            
            for (size_t d = 0; d < config.head_dim; d++) {
                out_head[d] += weight * v_head[d];
            }
        }
    }
}

// ============================================================================
// FFN (Feed-Forward Network)
// ============================================================================

float SiLU(float x) {
    // SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
    return x / (1.0f + std::exp(-x));
}

void FFN_Reference(
    const float* x,
    const float* w_gate,
    const float* w_up,
    const float* w_down,
    float* output,
    const FFNConfig& config
) {
    // Temporary buffers
    std::vector<float> gate(config.intermediate_size);
    std::vector<float> up(config.intermediate_size);
    std::vector<float> hidden(config.intermediate_size);
    
    // Compute gate and up projections
    // gate = W_gate @ x
    // up = W_up @ x
    for (size_t i = 0; i < config.intermediate_size; i++) {
        float gate_sum = 0.0f;
        float up_sum = 0.0f;
        for (size_t j = 0; j < config.hidden_size; j++) {
            gate_sum += w_gate[i * config.hidden_size + j] * x[j];
            up_sum += w_up[i * config.hidden_size + j] * x[j];
        }
        gate[i] = gate_sum;
        up[i] = up_sum;
    }
    
    // Apply SiLU to gate and multiply with up
    // hidden = SiLU(gate) * up
    for (size_t i = 0; i < config.intermediate_size; i++) {
        hidden[i] = SiLU(gate[i]) * up[i];
    }
    
    // Compute down projection
    // output = W_down @ hidden
    for (size_t i = 0; i < config.hidden_size; i++) {
        float sum = 0.0f;
        for (size_t j = 0; j < config.intermediate_size; j++) {
            sum += w_down[i * config.intermediate_size + j] * hidden[j];
        }
        output[i] = sum;
    }
}

// ============================================================================
// Validation Helpers
// ============================================================================

TensorComparisonResult CompareTensors(
    const float* reference,
    const float* actual,
    size_t count,
    float tolerance
) {
    TensorComparisonResult result = {};
    result.passed = true;
    result.max_error = 0.0f;
    result.mean_error = 0.0f;
    result.first_mismatch_idx = count;  // Initialize to "no mismatch"
    
    double sum_error = 0.0;
    
    for (size_t i = 0; i < count; i++) {
        float error = std::abs(reference[i] - actual[i]);
        
        if (error > result.max_error) {
            result.max_error = error;
        }
        
        sum_error += error;
        
        if (error > tolerance && result.first_mismatch_idx == count) {
            result.first_mismatch_idx = i;
            result.passed = false;
        }
    }
    
    result.mean_error = static_cast<float>(sum_error / count);
    result.rmse = static_cast<float>(std::sqrt(sum_error / count));
    
    return result;
}

} // namespace L4
} // namespace RawrXD
