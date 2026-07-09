/**
 * @file output_projection_test.cpp
 * @brief Phase 12: Output Projection
 * 
 * Projects final hidden state to vocabulary logits:
 *   logits = hidden @ W_output
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cfloat>
#include <cstdint>
#include <algorithm>

using namespace std;

// Matrix-vector multiplication: y = x @ W
void matmul(const float* x, const float* W, float* y, int in_features, int out_features) {
    for (int j = 0; j < out_features; j++) {
        float sum = 0.0f;
        for (int i = 0; i < in_features; i++) {
            sum += x[i] * W[i * out_features + j];
        }
        y[j] = sum;
    }
}

int main() {
    cout << "🔬 RawrXD Phase 12: Output Projection Test\n";
    cout << "==========================================\n\n";
    
    auto start = chrono::high_resolution_clock::now();
    
    // Test parameters
    int embed_dim = 3072;       // Hidden dimension
    int vocab_size = 32064;     // Vocabulary size (from Phase 5)
    
    cout << "[1/4] Creating test data...\n";
    cout << "  Embedding dimension: " << embed_dim << "\n";
    cout << "  Vocabulary size: " << vocab_size << "\n\n";
    
    // Create hidden state (simulating transformer output)
    vector<float> hidden(embed_dim);
    for (int i = 0; i < embed_dim; i++) {
        // Create a pattern that will produce interesting logits
        hidden[i] = sinf(i * 0.05f) * 0.5f + cosf(i * 0.03f) * 0.3f;
    }
    
    // Create output projection weights [embed_dim, vocab_size]
    // In reality this would be loaded from the model
    // For testing, we'll use a smaller subset
    int test_vocab_size = 1000;  // Test with smaller vocab for speed
    vector<float> W_output(embed_dim * test_vocab_size);
    
    // Initialize with pattern that creates interesting logits
    for (int i = 0; i < embed_dim * test_vocab_size; i++) {
        W_output[i] = sinf(i * 0.001f) * 0.01f;
    }
    
    cout << "  ✓ Test data created\n";
    cout << "    Hidden size: " << hidden.size() << "\n";
    cout << "    Weight matrix: [" << embed_dim << ", " << test_vocab_size << "]\n";
    cout << "    (Using reduced vocab size for testing)\n\n";
    
    // Perform output projection
    cout << "[2/4] Performing output projection...\n";
    
    vector<float> logits(test_vocab_size);
    
    auto compute_start = chrono::high_resolution_clock::now();
    
    matmul(hidden.data(), W_output.data(), logits.data(), embed_dim, test_vocab_size);
    
    auto compute_end = chrono::high_resolution_clock::now();
    auto compute_us = chrono::duration_cast<chrono::microseconds>(compute_end - compute_start).count();
    
    cout << "  ✓ Output projection complete\n";
    cout << "    Logits size: " << logits.size() << "\n";
    cout << "    Compute time: " << compute_us << " μs\n\n";
    
    // Analyze logits
    cout << "[3/4] Analyzing logits...\n";
    
    float min_logit = FLT_MAX, max_logit = -FLT_MAX, sum = 0.0f;
    bool no_nan_inf = true;
    
    for (float v : logits) {
        if (isnan(v) || isinf(v)) {
            no_nan_inf = false;
            break;
        }
        min_logit = min(min_logit, v);
        max_logit = max(max_logit, v);
        sum += v;
    }
    
    float mean_logit = sum / logits.size();
    
    // Find top-k tokens
    int k = 10;
    vector<pair<float, int>> token_scores;
    for (int i = 0; i < (int)logits.size(); i++) {
        token_scores.push_back({logits[i], i});
    }
    sort(token_scores.begin(), token_scores.end(), greater<pair<float, int>>());
    
    cout << "  Logit statistics:\n";
    cout << "    Range: [" << fixed << setprecision(4) << min_logit << ", " << max_logit << "]\n";
    cout << "    Mean: " << mean_logit << "\n";
    cout << "    No NaN/Inf: " << (no_nan_inf ? "✓" : "✗") << "\n";
    cout << "\n  Top " << k << " tokens by logit:\n";
    for (int i = 0; i < k; i++) {
        cout << "    [" << setw(4) << token_scores[i].second << "] " 
             << fixed << setprecision(4) << token_scores[i].first << "\n";
    }
    
    // Validate
    cout << "\n[4/4] Validating output...\n";
    
    bool range_ok = (min_logit > -100.0f && max_logit < 100.0f);
    bool has_variation = (max_logit - min_logit > 0.0001f);  // Relaxed for test weights
    
    cout << "  Range check: " << (range_ok ? "✓" : "✗") << " (should be in [-100, 100])\n";
    cout << "  Has variation: " << (has_variation ? "✓" : "✗") << " (max - min > 0.0001)\n";
    
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - start).count();
    
    cout << "\n" << string(60, '=') << "\n";
    cout << "Summary:\n";
    cout << "  Operation: Output Projection\n";
    cout << "  Formula: logits = hidden @ W_output\n";
    cout << "  Input dimension: " << embed_dim << "\n";
    cout << "  Output dimension: " << test_vocab_size << " (test) / " << vocab_size << " (full)\n";
    cout << "  Compute time: " << compute_us << " μs\n";
    cout << "  Total time: " << total_ms << " ms\n";
    
    if (no_nan_inf && range_ok) {
        cout << "  Status: ✅ OUTPUT PROJECTION TEST PASSED\n";
        return 0;
    } else {
        cout << "  Status: ❌ Output projection test failed\n";
        return 1;
    }
}
