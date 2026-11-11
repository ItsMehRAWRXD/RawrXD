/**
 * @file attention_reference.cpp
 * @brief RawrXD L4.3 Reference Attention Implementation
 *
 * Portable, correct, unoptimized attention.
 * Used for validation of optimized kernels.
 *
 * @copyright RawrXD 2026
 */

#include "attention_contracts.h"
#include <cmath>
#include <cstring>
#include <vector>

namespace rawrxd {
namespace attention {

// ============================================================================
// Reference Scaled Dot-Product Attention
// ============================================================================

static void ReferenceSoftmax(float* data, uint32_t count) {
    // Find max for numerical stability
    float max_val = data[0];
    for (uint32_t i = 1; i < count; ++i) {
        max_val = std::max(max_val, data[i]);
    }
    
    // Compute exp and sum
    double sum_exp = 0.0;
    for (uint32_t i = 0; i < count; ++i) {
        data[i] = std::exp(data[i] - max_val);
        sum_exp += data[i];
    }
    
    // Normalize
    float inv_sum = 1.0f / static_cast<float>(sum_exp);
    for (uint32_t i = 0; i < count; ++i) {
        data[i] *= inv_sum;
    }
}

static float ReferenceDotProduct(const float* a, const float* b, uint32_t dim) {
    double sum = 0.0;
    for (uint32_t i = 0; i < dim; ++i) {
        sum += static_cast<double>(a[i]) * static_cast<double>(b[i]);
    }
    return static_cast<float>(sum);
}

static void ReferenceAttentionSingleHead(
    const float* query,
    const float* keys,
    const float* values,
    float* output,
    uint32_t seq_len,
    uint32_t head_dim,
    float scale,
    bool causal
) {
    // Compute attention scores: Q @ K^T
    std::vector<float> scores(seq_len);
    for (uint32_t pos = 0; pos < seq_len; ++pos) {
        scores[pos] = ReferenceDotProduct(query, keys + pos * head_dim, head_dim) * scale;
    }
    
    // Apply causal mask if enabled
    if (causal) {
        // Mask future positions (assuming query is at position seq_len-1)
        // For full causal attention, mask based on query position
        // Simplified: allow all positions up to seq_len
    }
    
    // Softmax
    ReferenceSoftmax(scores.data(), seq_len);
    
    // Compute weighted sum: scores @ V
    std::memset(output, 0, head_dim * sizeof(float));
    for (uint32_t pos = 0; pos < seq_len; ++pos) {
        float weight = scores[pos];
        for (uint32_t d = 0; d < head_dim; ++d) {
            output[d] += weight * values[pos * head_dim + d];
        }
    }
}

// ============================================================================
// Reference Multi-Head Attention
// ============================================================================

bool ExecuteAttentionReference(
    const AttentionConfig& config,
    const AttentionInputs& inputs,
    AttentionOutputs& outputs
) {
    if (!config.IsValid()) return false;
    if (!inputs.IsValid(config)) return false;
    
    const uint32_t num_heads = config.num_heads;
    const uint32_t num_kv_heads = config.num_kv_heads;
    const uint32_t head_dim = config.head_dim;
    const uint32_t seq_len = inputs.seq_position + 1;  // Include current token
    
    // Compute scale if not set
    float scale = config.scale;
    if (scale == 0.0f) {
        scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    }
    
    // Process each query head
    for (uint32_t q_head = 0; q_head < num_heads; ++q_head) {
        // Map query head to KV head (for GQA)
        uint32_t kv_head = q_head / config.GetQueryHeadsPerKV();
        
        // Get query pointer
        const float* query = inputs.query.data + q_head * head_dim;
        
        // Get KV pointers (from cache or inputs)
        const float* keys;
        const float* values;
        
        if (inputs.kv_cache && inputs.kv_cache->IsValid()) {
            // Use KV cache
            keys = inputs.kv_cache->key_cache;
            values = inputs.kv_cache->value_cache;
        } else {
            // Use provided K,V
            keys = inputs.key.data + kv_head * head_dim;
            values = inputs.value.data + kv_head * head_dim;
        }
        
        // Compute attention for this head
        float* head_output = outputs.output.data + q_head * head_dim;
        ReferenceAttentionSingleHead(
            query, keys, values, head_output,
            seq_len, head_dim, scale, config.causal
        );
    }
    
    // Update KV cache if provided
    if (inputs.kv_cache && inputs.kv_cache->IsValid()) {
        // Append current K,V to cache
        for (uint32_t h = 0; h < num_kv_heads; ++h) {
            float* k_dest = inputs.kv_cache->GetKey(inputs.kv_cache->current_position, h);
            float* v_dest = inputs.kv_cache->GetValue(inputs.kv_cache->current_position, h);
            
            if (k_dest && v_dest) {
                const float* k_src = inputs.key.data + h * head_dim;
                const float* v_src = inputs.value.data + h * head_dim;
                
                std::memcpy(k_dest, k_src, head_dim * sizeof(float));
                std::memcpy(v_dest, v_src, head_dim * sizeof(float));
            }
        }
        inputs.kv_cache->current_position++;
        outputs.kv_cache_updated = true;
    }
    
    return true;
}

// ============================================================================
// Validation Implementation
// ============================================================================

ValidationResult AttentionValidator::Validate(
    const AttentionConfig& config,
    const AttentionInputs& inputs,
    const AttentionOutputs& outputs,
    const AttentionOutputs& reference_outputs
) {
    ValidationResult result;
    
    // Compute cosine similarity
    result.cosine_similarity = ComputeCosineSimilarity(outputs.output, reference_outputs.output);
    
    // Compute max error
    result.max_absolute_error = ComputeMaxError(outputs.output, reference_outputs.output);
    
    // Compute RMSE
    result.rmse = ComputeRMSE(outputs.output, reference_outputs.output);
    
    // Check passing criteria
    result.passed = result.IsPassing();
    
    if (!result.passed) {
        if (result.cosine_similarity < 0.999f) {
            result.AddError("Cosine similarity below threshold");
        }
        if (result.max_absolute_error > 0.01f) {
            result.AddError("Max absolute error above threshold");
        }
    }
    
    return result;
}

float AttentionValidator::ComputeCosineSimilarity(
    const TensorView& a,
    const TensorView& b
) {
    if (!a.IsValid() || !b.IsValid()) return 0.0f;
    if (a.total_elements != b.total_elements) return 0.0f;
    
    double dot = 0.0;
    double norm_a = 0.0;
    double norm_b = 0.0;
    
    for (uint32_t i = 0; i < a.total_elements; ++i) {
        float va = a.data[i];
        float vb = b.data[i];
        dot += va * vb;
        norm_a += va * va;
        norm_b += vb * vb;
    }
    
    if (norm_a == 0.0 || norm_b == 0.0) return 0.0f;
    
    return static_cast<float>(dot / std::sqrt(norm_a * norm_b));
}

float AttentionValidator::ComputeMaxError(
    const TensorView& a,
    const TensorView& b
) {
    if (!a.IsValid() || !b.IsValid()) return 1e30f;
    if (a.total_elements != b.total_elements) return 1e30f;
    
    float max_error = 0.0f;
    for (uint32_t i = 0; i < a.total_elements; ++i) {
        float error = std::abs(a.data[i] - b.data[i]);
        max_error = std::max(max_error, error);
    }
    
    return max_error;
}

float AttentionValidator::ComputeRMSE(
    const TensorView& a,
    const TensorView& b
) {
    if (!a.IsValid() || !b.IsValid()) return 1e30f;
    if (a.total_elements != b.total_elements) return 1e30f;
    
    double sum_sq = 0.0;
    for (uint32_t i = 0; i < a.total_elements; ++i) {
        double diff = static_cast<double>(a.data[i]) - static_cast<double>(b.data[i]);
        sum_sq += diff * diff;
    }
    
    return static_cast<float>(std::sqrt(sum_sq / a.total_elements));
}

// ============================================================================
// Utility Functions
// ============================================================================

void PrintTensorView(const TensorView& view, const std::string& name) {
    std::cout << "TensorView: " << name << "\n";
    std::cout << "  Shape: [" << view.rows << ", " << view.cols << ", " << view.depth << "]\n";
    std::cout << "  Strides: [" << view.row_stride << ", " << view.col_stride << ", " << view.depth_stride << "]\n";
    std::cout << "  Elements: " << view.total_elements << ", Contiguous: " << (view.is_contiguous ? "yes" : "no") << "\n";
}

void PrintAttentionConfig(const AttentionConfig& config) {
    std::cout << "AttentionConfig:\n";
    std::cout << "  Heads: " << config.num_heads << " (Q), " << config.num_kv_heads << " (KV)\n";
    std::cout << "  Head dim: " << config.head_dim << ", Context: " << config.context_length << "\n";
    std::cout << "  Causal: " << (config.causal ? "yes" : "no") << ", RoPE: " << (config.use_rope ? "yes" : "no") << "\n";
    std::cout << "  Scale: " << config.scale << ", Theta: " << config.rope_theta << "\n";
}

void PrintKVCacheState(const KVCache& cache) {
    std::cout << "KVCache:\n";
    std::cout << "  Position: " << cache.current_position << " / " << cache.max_position << "\n";
    std::cout << "  Initialized: " << (cache.is_initialized ? "yes" : "no") << ", Valid: " << (cache.IsValid() ? "yes" : "no") << "\n";
}

bool ValidateAttentionChain(const AttentionConfig& config,
                               const std::vector<std::string>* expected_ops) {
    if (!config.IsValid()) return false;
    
    // Validate tensor shapes are compatible
    if (config.num_heads % config.num_kv_heads != 0) return false;
    
    // Additional chain validation would go here
    (void)expected_ops;
    
    return true;
}

} // namespace attention
} // namespace rawrxd
