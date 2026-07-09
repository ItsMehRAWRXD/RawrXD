// ============================================================================
// KV Cache Implementation — Key-Value cache for transformer attention
// ============================================================================

#include "kv_cache.hpp"
#include <cmath>
#include <algorithm>
#include <cstring>

namespace RawrXD {
namespace CLI {

// ============================================================================
// KV Cache Implementation
// ============================================================================

void KVCache::Resize(size_t maxLen, size_t heads, size_t dim) {
    max_seq_len = maxLen;
    num_heads = heads;
    head_dim = dim;
    current_len = 0;

    const size_t total = max_seq_len * num_heads * head_dim;
    k_cache.assign(total, 0.0f);
    v_cache.assign(total, 0.0f);
}

void KVCache::Append(const float* k_row, const float* v_row) {
    const size_t t = current_len;
    if (t >= max_seq_len) return;  // Cache full

    // Copy k_row and v_row for all heads
    // Layout: [num_heads, head_dim] for this token
    for (size_t h = 0; h < num_heads; ++h) {
        for (size_t d = 0; d < head_dim; ++d) {
            size_t src_idx = h * head_dim + d;
            size_t dst_idx = Index(t, h, d);
            k_cache[dst_idx] = k_row[src_idx];
            v_cache[dst_idx] = v_row[src_idx];
        }
    }

    ++current_len;
}

void KVCache::GetKey(size_t t, size_t h, float* dst) const {
    if (t >= current_len || h >= num_heads) return;
    size_t idx = Index(t, h, 0);
    std::memcpy(dst, &k_cache[idx], head_dim * sizeof(float));
}

void KVCache::GetValue(size_t t, size_t h, float* dst) const {
    if (t >= current_len || h >= num_heads) return;
    size_t idx = Index(t, h, 0);
    std::memcpy(dst, &v_cache[idx], head_dim * sizeof(float));
}

// ============================================================================
// Single-Head Attention
// ============================================================================

void AttentionSingleHead(
    const float* query,
    const KVCache& cache,
    size_t head_index,
    float* output
) {
    const size_t seq_len = cache.current_len;
    const size_t head_dim = cache.head_dim;

    if (seq_len == 0 || head_dim == 0) return;

    // 1. Compute attention scores: q · k_t for all t
    std::vector<float> scores(seq_len);
    float max_score = -INFINITY;

    for (size_t t = 0; t < seq_len; ++t) {
        const float* k = cache.GetKeyPtr(t, head_index);

        float dot = 0.0f;
        for (size_t d = 0; d < head_dim; ++d) {
            dot += query[d] * k[d];
        }

        // Scale by sqrt(head_dim) for stability
        scores[t] = dot / std::sqrt(static_cast<float>(head_dim));
        if (scores[t] > max_score) max_score = scores[t];
    }

    // 2. Softmax: exp(score - max) / sum(exp)
    float sum_exp = 0.0f;
    for (size_t t = 0; t < seq_len; ++t) {
        scores[t] = std::exp(scores[t] - max_score);
        sum_exp += scores[t];
    }

    // Normalize
    for (size_t t = 0; t < seq_len; ++t) {
        scores[t] /= sum_exp;
    }

    // 3. Weighted sum of values: sum_t(weight_t * v_t)
    std::memset(output, 0, head_dim * sizeof(float));

    for (size_t t = 0; t < seq_len; ++t) {
        const float* v = cache.GetValuePtr(t, head_index);
        const float weight = scores[t];

        for (size_t d = 0; d < head_dim; ++d) {
            output[d] += weight * v[d];
        }
    }
}

// ============================================================================
// Multi-Head Attention
// ============================================================================

void AttentionMultiHead(
    const float* query,
    const KVCache& cache,
    float* output
) {
    const size_t num_heads = cache.num_heads;
    const size_t head_dim = cache.head_dim;

    // Process each head independently
    for (size_t h = 0; h < num_heads; ++h) {
        const float* q_head = &query[h * head_dim];
        float* out_head = &output[h * head_dim];

        AttentionSingleHead(q_head, cache, h, out_head);
    }
}

} // namespace CLI
} // namespace RawrXD
