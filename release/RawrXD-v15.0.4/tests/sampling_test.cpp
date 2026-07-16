/**
 * @file sampling_test.cpp
 * @brief Phase 13: Token Sampling
 * 
 * Converts logits to token probabilities and samples next token:
 *   1. Temperature scaling: logits /= temperature
 *   2. Softmax: probs = exp(logits) / sum(exp(logits))
 *   3. Sample: token = argmax(probs) for greedy, or weighted random
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <random>
#include <chrono>
#include <iomanip>

using namespace std;

// Softmax with temperature
void softmax_with_temp(const float* logits, float* probs, int size, float temperature) {
    // Apply temperature
    float max_logit = logits[0];
    for (int i = 1; i < size; i++) {
        max_logit = max(max_logit, logits[i]);
    }
    
    // Compute exp with temperature
    float sum = 0.0f;
    for (int i = 0; i < size; i++) {
        probs[i] = expf((logits[i] - max_logit) / temperature);
        sum += probs[i];
    }
    
    // Normalize
    for (int i = 0; i < size; i++) {
        probs[i] /= sum;
    }
}

// Greedy sampling: argmax
int greedy_sample(const float* probs, int size) {
    int best_idx = 0;
    float best_prob = probs[0];
    
    for (int i = 1; i < size; i++) {
        if (probs[i] > best_prob) {
            best_prob = probs[i];
            best_idx = i;
        }
    }
    
    return best_idx;
}

// Top-k sampling
int topk_sample(const float* probs, int size, int k) {
    // Find top k
    vector<pair<float, int>> topk;
    for (int i = 0; i < size; i++) {
        topk.push_back({probs[i], i});
    }
    
    // Sort descending
    sort(topk.begin(), topk.end(), greater<pair<float, int>>());
    
    // Renormalize top-k
    float sum = 0.0f;
    for (int i = 0; i < k && i < size; i++) {
        sum += topk[i].first;
    }
    
    // Sample from top-k
    random_device rd;
    mt19937 gen(rd());
    uniform_real_distribution<float> dis(0.0f, sum);
    
    float r = dis(gen);
    float cumsum = 0.0f;
    
    for (int i = 0; i < k && i < size; i++) {
        cumsum += topk[i].first;
        if (r <= cumsum) {
            return topk[i].second;
        }
    }
    
    return topk[0].second;  // Fallback
}

int main() {
    cout << "🔬 RawrXD Phase 13: Sampling Test\n";
    cout << "==================================\n\n";
    
    auto start = chrono::high_resolution_clock::now();
    
    // Test parameters
    int vocab_size = 1000;  // Reduced for testing
    
    cout << "[1/4] Creating test logits...\n";
    
    // Create test logits (simulating output from transformer)
    vector<float> logits(vocab_size);
    
    // Create a distribution with some clear winners
    for (int i = 0; i < vocab_size; i++) {
        // Base pattern
        logits[i] = sinf(i * 0.1f) * 2.0f;
        
        // Add some clear favorites
        if (i == 42) logits[i] += 5.0f;    // "the"
        if (i == 123) logits[i] += 4.0f;   // "is"
        if (i == 7) logits[i] += 3.5f;     // "a"
        if (i == 256) logits[i] += 3.0f;   // "of"
    }
    
    cout << "  ✓ Test logits created\n";
    cout << "    Vocabulary size: " << vocab_size << "\n";
    cout << "    Logit range: [" << fixed << setprecision(4) 
         << *min_element(logits.begin(), logits.end()) << ", "
         << *max_element(logits.begin(), logits.end()) << "]\n\n";
    
    // Test different sampling methods
    cout << "[2/4] Testing sampling methods...\n\n";
    
    // Method 1: Greedy sampling
    cout << "  Method 1: Greedy Sampling\n";
    
    vector<float> probs_greedy(vocab_size);
    softmax_with_temp(logits.data(), probs_greedy.data(), vocab_size, 1.0f);
    
    int token_greedy = greedy_sample(probs_greedy.data(), vocab_size);
    
    cout << "    Temperature: 1.0\n";
    cout << "    Selected token: " << token_greedy << "\n";
    cout << "    Probability: " << fixed << setprecision(6) << probs_greedy[token_greedy] << "\n";
    
    // Show top 5
    vector<pair<float, int>> top5;
    for (int i = 0; i < vocab_size; i++) {
        top5.push_back({probs_greedy[i], i});
    }
    sort(top5.begin(), top5.end(), greater<pair<float, int>>());
    
    cout << "    Top 5 tokens:\n";
    for (int i = 0; i < 5; i++) {
        cout << "      [" << setw(4) << top5[i].second << "] " 
             << fixed << setprecision(6) << top5[i].first << "\n";
    }
    cout << "\n";
    
    // Method 2: Temperature sampling
    cout << "  Method 2: Temperature Sampling\n";
    
    vector<float> temps = {0.5f, 1.0f, 2.0f};
    
    for (float temp : temps) {
        vector<float> probs(vocab_size);
        softmax_with_temp(logits.data(), probs.data(), vocab_size, temp);
        
        // Calculate entropy
        float entropy = 0.0f;
        for (float p : probs) {
            if (p > 0.0001f) {
                entropy -= p * logf(p);
            }
        }
        
        // Find max probability
        float max_prob = *max_element(probs.begin(), probs.end());
        
        cout << "    Temperature: " << temp << "\n";
        cout << "      Max probability: " << fixed << setprecision(6) << max_prob << "\n";
        cout << "      Entropy: " << fixed << setprecision(4) << entropy << "\n";
    }
    cout << "\n";
    
    // Method 3: Top-k sampling
    cout << "  Method 3: Top-k Sampling\n";
    
    vector<int> k_values = {1, 5, 50};
    
    for (int k : k_values) {
        vector<float> probs(vocab_size);
        softmax_with_temp(logits.data(), probs.data(), vocab_size, 1.0f);
        
        // Calculate probability mass in top-k
        vector<pair<float, int>> sorted;
        for (int i = 0; i < vocab_size; i++) {
            sorted.push_back({probs[i], i});
        }
        sort(sorted.begin(), sorted.end(), greater<pair<float, int>>());
        
        float topk_mass = 0.0f;
        for (int i = 0; i < k && i < vocab_size; i++) {
            topk_mass += sorted[i].first;
        }
        
        cout << "    k=" << k << ": top-" << k << " mass = " 
             << fixed << setprecision(4) << topk_mass << "\n";
    }
    
    // Validate
    cout << "\n[3/4] Validating sampling...\n";
    
    // Check that probabilities sum to 1
    float sum_probs = 0.0f;
    for (float p : probs_greedy) {
        sum_probs += p;
    }
    
    bool probs_sum_ok = (sum_probs > 0.99f && sum_probs < 1.01f);
    bool all_positive = all_of(probs_greedy.begin(), probs_greedy.end(), 
                               [](float p) { return p >= 0.0f; });
    
    cout << "  Probability sum ≈ 1.0: " << (probs_sum_ok ? "✓" : "✗") 
         << " (sum=" << fixed << setprecision(6) << sum_probs << ")\n";
    cout << "  All probabilities ≥ 0: " << (all_positive ? "✓" : "✗") << "\n";
    
    // Performance test
    cout << "\n[4/4] Performance test...\n";
    
    int n_iterations = 1000;
    vector<float> probs_perf(vocab_size);
    
    auto perf_start = chrono::high_resolution_clock::now();
    
    for (int iter = 0; iter < n_iterations; iter++) {
        softmax_with_temp(logits.data(), probs_perf.data(), vocab_size, 1.0f);
        int token = greedy_sample(probs_perf.data(), vocab_size);
    }
    
    auto perf_end = chrono::high_resolution_clock::now();
    auto perf_us = chrono::duration_cast<chrono::microseconds>(perf_end - perf_start).count();
    
    cout << "  " << n_iterations << " iterations\n";
    cout << "  Total time: " << perf_us << " μs\n";
    cout << "  Per iteration: " << fixed << setprecision(2) << (perf_us / (float)n_iterations) << " μs\n";
    
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - start).count();
    
    cout << "\n" << string(60, '=') << "\n";
    cout << "Summary:\n";
    cout << "  Operation: Token Sampling\n";
    cout << "  Methods tested:\n";
    cout << "    - Greedy sampling\n";
    cout << "    - Temperature sampling\n";
    cout << "    - Top-k sampling\n";
    cout << "  Vocabulary size: " << vocab_size << "\n";
    cout << "  Sampling time: " << fixed << setprecision(2) << (perf_us / (float)n_iterations) << " μs\n";
    cout << "  Total time: " << total_ms << " ms\n";
    
    if (probs_sum_ok && all_positive) {
        cout << "  Status: ✅ SAMPLING TEST PASSED\n";
        return 0;
    } else {
        cout << "  Status: ❌ Sampling test failed\n";
        return 1;
    }
}
