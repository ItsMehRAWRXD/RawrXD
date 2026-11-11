/**
 * @file attention_test.cpp
 * @brief Phase 10: Scaled Dot-Product Attention
 * 
 * Attention(Q, K, V) = softmax(Q @ K^T / sqrt(d_k)) @ V
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

using namespace std;

// Softmax: exp(x_i) / sum(exp(x_j))
void softmax(float* x, int size) {
    // Find max for numerical stability
    float max_val = x[0];
    for (int i = 1; i < size; i++) {
        max_val = max(max_val, x[i]);
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (int i = 0; i < size; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    // Normalize
    for (int i = 0; i < size; i++) {
        x[i] /= sum;
    }
}

// Scaled dot-product attention for single query
// query: [head_dim], keys: [n_keys, head_dim], values: [n_keys, head_dim]
// output: [head_dim]
void attention_single(const float* query, const float* keys, const float* values, 
                      float* output, int n_keys, int head_dim) {
    // Compute attention scores: query @ keys^T
    vector<float> scores(n_keys);
    float scale = 1.0f / sqrtf(head_dim);
    
    for (int k = 0; k < n_keys; k++) {
        float dot = 0.0f;
        for (int d = 0; d < head_dim; d++) {
            dot += query[d] * keys[k * head_dim + d];
        }
        scores[k] = dot * scale;
    }
    
    // Apply softmax
    softmax(scores.data(), n_keys);
    
    // Compute weighted sum of values
    for (int d = 0; d < head_dim; d++) {
        float sum = 0.0f;
        for (int k = 0; k < n_keys; k++) {
            sum += scores[k] * values[k * head_dim + d];
        }
        output[d] = sum;
    }
}

int main() {
    cout << "🔬 RawrXD Phase 10: Attention Test\n";
    cout << "==================================\n\n";
    
    auto start = chrono::high_resolution_clock::now();
    
    // Test parameters
    int head_dim = 96;      // Smaller dimension for testing
    int n_keys = 10;        // Number of key-value pairs
    
    cout << "[1/4] Creating test data...\n";
    cout << "  Head dimension: " << head_dim << "\n";
    cout << "  Number of keys: " << n_keys << "\n\n";
    
    // Create query (simulating a token embedding)
    vector<float> query(head_dim);
    for (int i = 0; i < head_dim; i++) {
        query[i] = sinf(i * 0.1f) * 0.5f;
    }
    
    // Create keys and values (simulating previous tokens)
    vector<float> keys(n_keys * head_dim);
    vector<float> values(n_keys * head_dim);
    
    for (int k = 0; k < n_keys; k++) {
        for (int d = 0; d < head_dim; d++) {
            // Each key/value has slightly different pattern based on position
            keys[k * head_dim + d] = cosf((k + d) * 0.1f) * 0.3f;
            values[k * head_dim + d] = sinf((k + d) * 0.15f) * 0.4f;
        }
    }
    
    cout << "  ✓ Test data created\n";
    cout << "    Query size: " << query.size() << "\n";
    cout << "    Keys size: " << keys.size() << "\n";
    cout << "    Values size: " << values.size() << "\n\n";
    
    // Compute attention scores (before softmax)
    cout << "[2/4] Computing attention scores...\n";
    
    vector<float> scores(n_keys);
    float scale = 1.0f / sqrtf(head_dim);
    
    for (int k = 0; k < n_keys; k++) {
        float dot = 0.0f;
        for (int d = 0; d < head_dim; d++) {
            dot += query[d] * keys[k * head_dim + d];
        }
        scores[k] = dot * scale;
    }
    
    cout << "  ✓ Raw attention scores:\n";
    cout << "    ";
    for (int k = 0; k < n_keys; k++) {
        cout << fixed << setprecision(3) << scores[k] << " ";
    }
    cout << "\n\n";
    
    // Apply softmax
    cout << "[3/4] Applying softmax...\n";
    
    softmax(scores.data(), n_keys);
    
    cout << "  ✓ Attention weights (after softmax):\n";
    cout << "    ";
    float sum_weights = 0.0f;
    for (int k = 0; k < n_keys; k++) {
        cout << fixed << setprecision(4) << scores[k] << " ";
        sum_weights += scores[k];
    }
    cout << "\n    Sum: " << sum_weights << " (should be ~1.0)\n\n";
    
    // Compute output
    cout << "[4/4] Computing attention output...\n";
    
    vector<float> output(head_dim);
    
    auto compute_start = chrono::high_resolution_clock::now();
    
    for (int d = 0; d < head_dim; d++) {
        float sum = 0.0f;
        for (int k = 0; k < n_keys; k++) {
            sum += scores[k] * values[k * head_dim + d];
        }
        output[d] = sum;
    }
    
    auto compute_end = chrono::high_resolution_clock::now();
    auto compute_us = chrono::duration_cast<chrono::microseconds>(compute_end - compute_start).count();
    
    cout << "  ✓ Attention output computed\n";
    cout << "    Output size: " << output.size() << "\n";
    cout << "    Compute time: " << compute_us << " μs\n";
    cout << "    First 20 values:\n";
    for (int i = 0; i < min(20, (int)output.size()); i++) {
        cout << "      [" << setw(2) << i << "] " << fixed << setprecision(6) << output[i] << "\n";
    }
    
    // Validate
    cout << "\n  Validation:\n";
    
    // Check softmax sum
    bool softmax_ok = (sum_weights > 0.99f && sum_weights < 1.01f);
    cout << "    Softmax sum ≈ 1.0: " << (softmax_ok ? "✓" : "✗") << "\n";
    
    // Check for NaN/Inf
    bool no_nan_inf = true;
    float min_val = FLT_MAX, max_val = -FLT_MAX;
    for (float v : output) {
        if (isnan(v) || isinf(v)) {
            no_nan_inf = false;
            break;
        }
        min_val = min(min_val, v);
        max_val = max(max_val, v);
    }
    cout << "    No NaN/Inf: " << (no_nan_inf ? "✓" : "✗") << "\n";
    cout << "    Output range: [" << fixed << setprecision(4) << min_val << ", " << max_val << "]\n";
    
    // Check that attention weights are reasonable
    float max_weight = 0.0f;
    for (float w : scores) {
        max_weight = max(max_weight, w);
    }
    cout << "    Max attention weight: " << fixed << setprecision(4) << max_weight << "\n";
    bool weights_ok = (max_weight > 0.0f && max_weight < 1.0f);
    cout << "    Valid attention weights: " << (weights_ok ? "✓" : "✗") << "\n";
    
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - start).count();
    
    cout << "\n" << string(60, '=') << "\n";
    cout << "Summary:\n";
    cout << "  Operation: Scaled Dot-Product Attention\n";
    cout << "  Formula: softmax(Q @ K^T / sqrt(d_k)) @ V\n";
    cout << "  Head dimension: " << head_dim << "\n";
    cout << "  Keys: " << n_keys << "\n";
    cout << "  Compute time: " << compute_us << " μs\n";
    cout << "  Total time: " << total_ms << " ms\n";
    
    if (softmax_ok && no_nan_inf && weights_ok) {
        cout << "  Status: ✅ ATTENTION TEST PASSED\n";
        return 0;
    } else {
        cout << "  Status: ❌ Attention test failed\n";
        return 1;
    }
}
