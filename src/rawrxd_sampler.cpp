#include "rawrxd_sampler.h"
#include <cmath>
#include <algorithm>
#include <numeric>

extern "C" void SoftMax_AVX512(float* x, int size);

RawrXDSampler::RawrXDSampler() : rng(std::random_device{}()) {}

uint32_t RawrXDSampler::Sample(float* logits, int vocab_size, const std::vector<uint32_t>& history) {
    // 1. Temperature scaling
    if (temperature > 0.0f && temperature != 1.0f) {
        float inv_temp = 1.0f / temperature;
        for (int i = 0; i < vocab_size; ++i) logits[i] *= inv_temp;
    }
    
    // 2. Softmax (stable: subtract max first)
    float max_val = -1e30f;
    for (int i = 0; i < vocab_size; i++) if (logits[i] > max_val) max_val = logits[i];
    
    float sum = 0.0f;
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = std::exp(logits[i] - max_val);
        sum += logits[i];
    }
    float inv_sum = 1.0f / sum;
    for (int i = 0; i < vocab_size; i++) logits[i] *= inv_sum;

    // 3. Top-K filtering
    int effective_k = (top_k > 0 && top_k < vocab_size) ? top_k : vocab_size;
    if (effective_k < vocab_size) {
        // Find K-th largest probability via nth_element (O(n) average)
        std::vector<float> probs_copy(logits, logits + vocab_size);
        std::nth_element(probs_copy.begin(), probs_copy.begin() + effective_k - 1, probs_copy.end(), std::greater<float>());
        float kth_prob = probs_copy[effective_k - 1];
        for (int i = 0; i < vocab_size; i++) {
            if (logits[i] < kth_prob) logits[i] = 0.0f;
        }
        // Renormalize
        sum = 0.0f;
        for (int i = 0; i < vocab_size; i++) sum += logits[i];
        if (sum > 0.0f) {
            inv_sum = 1.0f / sum;
            for (int i = 0; i < vocab_size; i++) logits[i] *= inv_sum;
        }
    }

    // 4. Top-P (nucleus) filtering
    if (top_p > 0.0f && top_p < 1.0f) {
        // Sort probabilities descending
        std::vector<std::pair<float, int>> sorted;
        sorted.reserve(vocab_size);
        for (int i = 0; i < vocab_size; i++) sorted.push_back({logits[i], i});
        std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
        
        float cumsum = 0.0f;
        float cutoff = 0.0f;
        for (const auto& p : sorted) {
            cumsum += p.first;
            if (cumsum > top_p) {
                cutoff = p.first;
                break;
            }
        }
        for (int i = 0; i < vocab_size; i++) {
            if (logits[i] < cutoff) logits[i] = 0.0f;
        }
        // Renormalize
        sum = 0.0f;
        for (int i = 0; i < vocab_size; i++) sum += logits[i];
        if (sum > 0.0f) {
            inv_sum = 1.0f / sum;
            for (int i = 0; i < vocab_size; i++) logits[i] *= inv_sum;
        }
    }

    // 5. Fast sampling: cumulative sum + binary search (O(log n))
    // Build prefix sum array
    std::vector<float> prefix(vocab_size);
    prefix[0] = logits[0];
    for (int i = 1; i < vocab_size; i++) prefix[i] = prefix[i-1] + logits[i];
    
    // Ensure probabilities sum to 1.0 (guard against FP error)
    float total = prefix[vocab_size - 1];
    if (total > 0.0f && std::abs(total - 1.0f) > 1e-5f) {
        for (int i = 0; i < vocab_size; i++) prefix[i] /= total;
    }
    
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(rng);
    
    // Binary search on prefix sum
    int lo = 0, hi = vocab_size - 1;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (prefix[mid] < r) lo = mid + 1;
        else hi = mid;
    }
    return static_cast<uint32_t>(lo);
}
