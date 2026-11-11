// ============================================================================
// Flash Attention Simple Test
// ============================================================================

#include "flash_attention_avx512.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>

using namespace SEG;

// Standard attention for comparison
void StandardAttention(const float* q, const float* k_cache, const float* v_cache,
                       float* output, size_t cache_len, size_t head_dim) {
    std::vector<float> scores(cache_len);
    
    // Compute scores
    float max_score = -INFINITY;
    for (size_t pos = 0; pos < cache_len; pos++) {
        const float* k_vec = k_cache + pos * head_dim;
        float dot = 0.0f;
        for (size_t d = 0; d < head_dim; d++) {
            dot += q[d] * k_vec[d];
        }
        float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
        scores[pos] = dot * scale;
        max_score = std::max(max_score, scores[pos]);
    }
    
    // Softmax
    float sum = 0.0f;
    for (size_t pos = 0; pos < cache_len; pos++) {
        scores[pos] = std::exp(scores[pos] - max_score);
        sum += scores[pos];
    }
    for (size_t pos = 0; pos < cache_len; pos++) {
        scores[pos] /= sum;
    }
    
    // Weighted sum
    for (size_t d = 0; d < head_dim; d++) {
        output[d] = 0.0f;
    }
    for (size_t pos = 0; pos < cache_len; pos++) {
        const float* v_vec = v_cache + pos * head_dim;
        for (size_t d = 0; d < head_dim; d++) {
            output[d] += scores[pos] * v_vec[d];
        }
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Flash Attention Simple Test\n";
    std::cout << "========================================\n\n";
    
    size_t head_dim = 128;
    std::vector<size_t> cache_lengths = {64, 128, 256, 512, 1024};
    
    for (size_t cache_len : cache_lengths) {
        std::cout << "Cache length: " << cache_len << ", Head dim: " << head_dim << "\n";
        
        // Allocate data
        std::vector<float> q(head_dim, 0.01f);
        std::vector<float> k_cache(cache_len * head_dim, 0.01f);
        std::vector<float> v_cache(cache_len * head_dim, 0.01f);
        std::vector<float> output_flash(head_dim, 0.0f);
        std::vector<float> output_standard(head_dim, 0.0f);
        
        // Warmup
        FlashAttentionCachedF32(q.data(), k_cache.data(), v_cache.data(),
                               output_flash.data(), cache_len, head_dim);
        StandardAttention(q.data(), k_cache.data(), v_cache.data(),
                         output_standard.data(), cache_len, head_dim);
        
        // Benchmark Flash Attention
        const int iterations = 1000;
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) {
            FlashAttentionCachedF32(q.data(), k_cache.data(), v_cache.data(),
                                   output_flash.data(), cache_len, head_dim);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto flash_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f / iterations;
        
        // Benchmark Standard Attention
        start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) {
            StandardAttention(q.data(), k_cache.data(), v_cache.data(),
                             output_standard.data(), cache_len, head_dim);
        }
        end = std::chrono::high_resolution_clock::now();
        auto standard_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f / iterations;
        
        // Verify
        float max_diff = 0.0f;
        for (size_t d = 0; d < head_dim; d++) {
            max_diff = std::max(max_diff, std::abs(output_flash[d] - output_standard[d]));
        }
        
        float speedup = standard_time / flash_time;
        
        std::cout << "  Flash:    " << flash_time << " ms\n";
        std::cout << "  Standard: " << standard_time << " ms\n";
        std::cout << "  Speedup:  " << speedup << "x\n";
        std::cout << "  Max diff: " << max_diff << "\n\n";
    }
    
    std::cout << "Done!\n";
    return 0;
}
