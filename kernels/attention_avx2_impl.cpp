/**
 * @file attention_avx2_impl.cpp
 * @brief RawrXD L4.3.1 AVX2 Optimized Attention Implementation
 *
 * SIMD-accelerated attention using AVX2/FMA intrinsics.
 * Validates against reference implementation.
 *
 * @copyright RawrXD 2026
 */

#include "attention_contracts.h"
#include "attention_avx2.h"
#include <immintrin.h>
#include <cmath>
#include <cstring>

namespace rawrxd {
namespace attention {

// ============================================================================
// AVX2 Vectorized Operations
// ============================================================================

float AttentionAVX2::DotProductAVX2(const float* a, const float* b, uint32_t dim) {
    __m256 sum_vec = _mm256_setzero_ps();
    uint32_t i = 0;

    // Process 8 floats at a time
    for (; i + 8 <= dim; i += 8) {
        __m256 a_vec = _mm256_loadu_ps(&a[i]);
        __m256 b_vec = _mm256_loadu_ps(&b[i]);
        sum_vec = _mm256_fmadd_ps(a_vec, b_vec, sum_vec);
    }

    // Horizontal sum
    float sum_arr[8];
    _mm256_storeu_ps(sum_arr, sum_vec);
    float sum = sum_arr[0] + sum_arr[1] + sum_arr[2] + sum_arr[3] +
                sum_arr[4] + sum_arr[5] + sum_arr[6] + sum_arr[7];

    // Remainder
    for (; i < dim; ++i) {
        sum += a[i] * b[i];
    }

    return sum;
}

void AttentionAVX2::SoftmaxAVX2(float* data, uint32_t count) {
    // Find max for numerical stability
    __m256 max_vec = _mm256_set1_ps(-1e30f);
    uint32_t i = 0;

    for (; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        max_vec = _mm256_max_ps(max_vec, vec);
    }

    float max_arr[8];
    _mm256_storeu_ps(max_arr, max_vec);
    float max_val = max_arr[0];
    for (int j = 1; j < 8; ++j) {
        max_val = std::max(max_val, max_arr[j]);
    }

    for (; i < count; ++i) {
        max_val = std::max(max_val, data[i]);
    }

    // Compute exp(x - max) and sum
    __m256 max_broadcast = _mm256_set1_ps(max_val);
    __m256 sum_vec = _mm256_setzero_ps();

    for (i = 0; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        vec = _mm256_sub_ps(vec, max_broadcast);
        // Approximate exp using fast method
        vec = _mm256_exp_ps(vec);  // Requires SVML or use polynomial approx
        sum_vec = _mm256_add_ps(sum_vec, vec);
        _mm256_storeu_ps(&data[i], vec);
    }

    float sum_arr[8];
    _mm256_storeu_ps(sum_arr, sum_vec);
    double sum_exp = 0.0;
    for (int j = 0; j < 8; ++j) sum_exp += sum_arr[j];

    for (; i < count; ++i) {
        data[i] = std::exp(data[i] - max_val);
        sum_exp += data[i];
    }

    // Normalize
    float inv_sum = 1.0f / static_cast<float>(sum_exp);
    __m256 inv_sum_vec = _mm256_set1_ps(inv_sum);

    for (i = 0; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        vec = _mm256_mul_ps(vec, inv_sum_vec);
        _mm256_storeu_ps(&data[i], vec);
    }

    for (; i < count; ++i) {
        data[i] *= inv_sum;
    }
}

void AttentionAVX2::WeightedSumAVX2(
    float* output,
    const float* scores,
    const float* values,
    uint32_t seq_len,
    uint32_t head_dim
) {
    // Initialize output to zero
    std::memset(output, 0, head_dim * sizeof(float));

    // Accumulate weighted values
    for (uint32_t pos = 0; pos < seq_len; ++pos) {
        float weight = scores[pos];
        __m256 weight_vec = _mm256_set1_ps(weight);

        uint32_t d = 0;
        for (; d + 8 <= head_dim; d += 8) {
            __m256 out_vec = _mm256_loadu_ps(&output[d]);
            __m256 val_vec = _mm256_loadu_ps(&values[pos * head_dim + d]);
            out_vec = _mm256_fmadd_ps(weight_vec, val_vec, out_vec);
            _mm256_storeu_ps(&output[d], out_vec);
        }

        // Remainder
        for (; d < head_dim; ++d) {
            output[d] += weight * values[pos * head_dim + d];
        }
    }
}

// ============================================================================
// Attention Computation
// ============================================================================

void AttentionAVX2::ComputeAttentionSingleHead(
    const float* query,
    const float* keys,
    const float* values,
    float* output,
    uint32_t seq_len,
    uint32_t head_dim,
    float scale,
    bool causal
) {
    // Allocate scores buffer
    std::vector<float> scores(seq_len);

    // Compute Q @ K^T for each position
    for (uint32_t pos = 0; pos < seq_len; ++pos) {
        float dot = DotProductAVX2(query, keys + pos * head_dim, head_dim);
        scores[pos] = dot * scale;
    }

    // Apply causal mask if enabled
    // For decode mode, query is at position seq_len-1, so all positions are valid
    // For training/prefill, would mask future positions
    (void)causal;  // Decode mode doesn't need masking

    // Softmax
    SoftmaxAVX2(scores.data(), seq_len);

    // Weighted sum
    WeightedSumAVX2(output, scores.data(), values, seq_len, head_dim);
}

// ============================================================================
// Public Interface
// ============================================================================

bool AttentionAVX2::Execute(
    const AttentionConfig& config,
    const AttentionInputs& inputs,
    AttentionOutputs& outputs,
    KVCache* cache
) {
    if (!config.IsValid()) return false;
    if (!inputs.IsValid(config)) return false;
    if (!outputs.output.IsValid()) return false;

    const uint32_t num_heads = config.num_heads;
    const uint32_t num_kv_heads = config.num_kv_heads;
    const uint32_t head_dim = config.head_dim;
    const uint32_t seq_len = inputs.seq_position + 1;

    // Compute scale
    float scale = config.scale;
    if (scale == 0.0f) {
        scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    }

    // Process each query head
    for (uint32_t q_head = 0; q_head < num_heads; ++q_head) {
        uint32_t kv_head = q_head / config.GetQueryHeadsPerKV();

        const float* query = inputs.query.data + q_head * head_dim;
        float* head_output = outputs.output.data + q_head * head_dim;

        // Get K, V from cache or inputs
        const float* keys;
        const float* values;

        if (cache && cache->IsValid()) {
            keys = cache->key_cache;
            values = cache->value_cache;
        } else if (inputs.kv_cache && inputs.kv_cache->IsValid()) {
            keys = inputs.kv_cache->key_cache;
            values = inputs.kv_cache->value_cache;
        } else {
            keys = inputs.key.data + kv_head * head_dim;
            values = inputs.value.data + kv_head * head_dim;
        }

        ComputeAttentionSingleHead(
            query, keys, values, head_output,
            seq_len, head_dim, scale, config.causal
        );
    }

    // Update KV cache if provided
    if (cache && cache->IsValid() && cache->HasCapacity()) {
        for (uint32_t h = 0; h < num_kv_heads; ++h) {
            float* k_dest = cache->GetKey(cache->current_position, h);
            float* v_dest = cache->GetValue(cache->current_position, h);

            if (k_dest && v_dest) {
                const float* k_src = inputs.key.data + h * head_dim;
                const float* v_src = inputs.value.data + h * head_dim;

                std::memcpy(k_dest, k_src, head_dim * sizeof(float));
                std::memcpy(v_dest, v_src, head_dim * sizeof(float));
            }
        }
        cache->current_position++;
        outputs.kv_cache_updated = true;
    }

    return true;
}

bool AttentionAVX2::ExecuteValidated(
    const AttentionConfig& config,
    const AttentionInputs& inputs,
    AttentionOutputs& outputs,
    KVCache* cache,
    ValidationResult* out_validation
) {
    // Allocate reference output buffer
    std::vector<float> ref_output_data(outputs.output.total_elements);
    AttentionOutputs ref_outputs;
    ref_outputs.output = TensorView::CreateContiguous(
        ref_output_data.data(),
        outputs.output.rows,
        outputs.output.cols
    );

    // Run reference implementation
    bool ref_success = ExecuteAttentionReference(config, inputs, ref_outputs);
    if (!ref_success) return false;

    // Run AVX2 implementation
    bool avx2_success = Execute(config, inputs, outputs, cache);
    if (!avx2_success) return false;

    // Validate
    ValidationResult validation = AttentionValidator::Validate(
        config, inputs, outputs, ref_outputs
    );

    if (out_validation) {
        *out_validation = validation;
    }

    // If validation fails, fall back to reference
    if (!validation.passed) {
        std::memcpy(outputs.output.data, ref_outputs.output.data,
                    outputs.output.total_elements * sizeof(float));
        outputs.kv_cache_updated = ref_outputs.kv_cache_updated;
    }

    return true;
}

bool AttentionAVX2::IsAvailable() {
    // Check CPU features
    int cpu_info[4] = {0};
    __cpuid(cpu_info, 1);
    bool has_avx = (cpu_info[2] & (1 << 28)) != 0;
    bool has_fma = (cpu_info[2] & (1 << 12)) != 0;

    __cpuidex(cpu_info, 7, 0);
    bool has_avx2 = (cpu_info[1] & (1 << 5)) != 0;

    return has_avx && has_avx2 && has_fma;
}

} // namespace attention
} // namespace rawrxd
