// ═══════════════════════════════════════════════════════════════════════════════
// VAL-038: Fused Tree Attention - Scalar Reference Implementation
// ═══════════════════════════════════════════════════════════════════════════════
// Pure C++ scalar reference for correctness validation
// Target: Validate algorithm before AVX-512 optimization
// ═══════════════════════════════════════════════════════════════════════════════

#include <cstdint>
#include <cstddef>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <vector>

namespace RawrXD {

// ═══════════════════════════════════════════════════════════════════════════════
// Scalar Dot Product
// ═══════════════════════════════════════════════════════════════════════════════
static float ScalarDotProduct(
    const float* a,
    const float* b,
    uint32_t dim
) {
    float sum = 0.0f;
    for (uint32_t i = 0; i < dim; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Scalar Softmax
// ═══════════════════════════════════════════════════════════════════════════════
static void ScalarSoftmax(
    float* scores,
    uint32_t count,
    const uint8_t* mask
) {
    // Find max for numerical stability
    float maxScore = -1e38f;
    for (uint32_t i = 0; i < count; i++) {
        if (mask[i]) {
            maxScore = std::max(maxScore, scores[i]);
        }
    }
    
    // Compute exp and sum
    float sumExp = 0.0f;
    for (uint32_t i = 0; i < count; i++) {
        if (mask[i]) {
            scores[i] = std::exp(scores[i] - maxScore);
            sumExp += scores[i];
        } else {
            scores[i] = 0.0f;
        }
    }
    
    // Normalize
    if (sumExp > 0.0f) {
        for (uint32_t i = 0; i < count; i++) {
            scores[i] /= sumExp;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TreeAttention_Fused_VAL038_Reference
// ═══════════════════════════════════════════════════════════════════════════════
// Pure scalar reference implementation
// ═══════════════════════════════════════════════════════════════════════════════
void TreeAttention_Fused_VAL038_Reference(
    float* output,              // [num_q, head_dim]
    const float* Q,             // [num_q, head_dim]
    const float* K,             // [num_k, head_dim]
    const float* V,             // [num_k, head_dim]
    uint32_t num_q,             // Number of queries
    uint32_t num_k,             // Number of keys
    const uint8_t* tree_mask,   // [num_q, num_k] causal mask
    uint32_t head_dim           // Head dimension (typically 64)
) {
    const float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    
    // Temporary buffer for scores
    std::vector<float> scores(num_k);
    
    // Process each query
    for (uint32_t q_idx = 0; q_idx < num_q; q_idx++) {
        const float* q_row = Q + q_idx * head_dim;
        
        // Compute Q@K^T for this query
        for (uint32_t k_idx = 0; k_idx < num_k; k_idx++) {
            const float* k_row = K + k_idx * head_dim;
            
            // Check mask
            if (!tree_mask[q_idx * num_k + k_idx]) {
                scores[k_idx] = -1e38f;  // Masked out
                continue;
            }
            
            // Compute scaled dot product
            scores[k_idx] = ScalarDotProduct(q_row, k_row, head_dim) * scale;
        }
        
        // Apply softmax
        ScalarSoftmax(scores.data(), num_k, tree_mask + q_idx * num_k);
        
        // Compute weighted sum of V (A@V)
        float* out_row = output + q_idx * head_dim;
        std::memset(out_row, 0, head_dim * sizeof(float));
        
        for (uint32_t k_idx = 0; k_idx < num_k; k_idx++) {
            if (scores[k_idx] == 0.0f) continue;
            
            const float* v_row = V + k_idx * head_dim;
            for (uint32_t d = 0; d < head_dim; d++) {
                out_row[d] += scores[k_idx] * v_row[d];
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Validation Helper: Compare outputs
// ═══════════════════════════════════════════════════════════════════════════════
struct ValidationResult {
    float maxError;
    float avgError;
    uint32_t maxErrorIndex;
    bool passed;
};

ValidationResult ValidateAttentionOutput(
    const float* actual,
    const float* expected,
    uint32_t num_q,
    uint32_t head_dim,
    float tolerance = 0.001f
) {
    ValidationResult result = {};
    result.maxError = 0.0f;
    result.avgError = 0.0f;
    result.maxErrorIndex = 0;
    result.passed = true;
    
    uint32_t totalElements = num_q * head_dim;
    double totalError = 0.0;
    
    for (uint32_t i = 0; i < totalElements; i++) {
        float error = std::abs(actual[i] - expected[i]);
        totalError += error;
        
        if (error > result.maxError) {
            result.maxError = error;
            result.maxErrorIndex = i;
        }
        
        if (error > tolerance) {
            result.passed = false;
        }
    }
    
    result.avgError = static_cast<float>(totalError / totalElements);
    return result;
}

} // namespace RawrXD
