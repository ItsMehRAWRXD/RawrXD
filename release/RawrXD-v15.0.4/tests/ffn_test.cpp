/**
 * @file ffn_test.cpp
 * @brief Phase 11: FFN/SwiGLU Feed-Forward Network
 * 
 * SwiGLU activation: Swish(x) = x * sigmoid(x)
 * FFN(x) = (Swish(x @ W_gate) * (x @ W_up)) @ W_down
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

// Sigmoid function
float sigmoid(float x) {
    return 1.0f / (1.0f + expf(-x));
}

// Swish activation: x * sigmoid(x)
float swish(float x) {
    return x * sigmoid(x);
}

// SwiGLU: Swish(gate) * up
// gate and up are same size
void swiglu(const float* gate, const float* up, float* output, int size) {
    for (int i = 0; i < size; i++) {
        output[i] = swish(gate[i]) * up[i];
    }
}

// Matrix-vector multiplication: y = x @ W
// x: [1, in_features], W: [in_features, out_features], y: [1, out_features]
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
    cout << "🔬 RawrXD Phase 11: FFN/SwiGLU Test\n";
    cout << "====================================\n\n";
    
    auto start = chrono::high_resolution_clock::now();
    
    // Test parameters (simplified for testing)
    int embed_dim = 3072;      // Input/output dimension
    int hidden_dim = 8192;     // Hidden dimension (typically 4x embed or 8/3x for SwiGLU)
    
    cout << "[1/5] Creating test data...\n";
    cout << "  Embedding dimension: " << embed_dim << "\n";
    cout << "  Hidden dimension: " << hidden_dim << "\n\n";
    
    // Create input
    vector<float> input(embed_dim);
    for (int i = 0; i < embed_dim; i++) {
        input[i] = sinf(i * 0.01f) * 0.1f;
    }
    
    // Create weight matrices (simulated)
    // W_gate: [embed_dim, hidden_dim]
    // W_up: [embed_dim, hidden_dim]
    // W_down: [hidden_dim, embed_dim]
    vector<float> W_gate(embed_dim * hidden_dim);
    vector<float> W_up(embed_dim * hidden_dim);
    vector<float> W_down(hidden_dim * embed_dim);
    
    // Initialize with small random values
    for (int i = 0; i < embed_dim * hidden_dim; i++) {
        W_gate[i] = ((i % 7) - 3) * 0.001f;
        W_up[i] = ((i % 5) - 2) * 0.001f;
    }
    for (int i = 0; i < hidden_dim * embed_dim; i++) {
        W_down[i] = ((i % 11) - 5) * 0.0005f;
    }
    
    cout << "  ✓ Test data created\n";
    cout << "    Input size: " << input.size() << "\n";
    cout << "    W_gate size: " << W_gate.size() << "\n";
    cout << "    W_up size: " << W_up.size() << "\n";
    cout << "    W_down size: " << W_down.size() << "\n\n";
    
    // Step 1: Project to gate and up
    cout << "[2/5] Projecting to gate and up...\n";
    
    vector<float> gate(hidden_dim);
    vector<float> up(hidden_dim);
    
    auto proj_start = chrono::high_resolution_clock::now();
    
    matmul(input.data(), W_gate.data(), gate.data(), embed_dim, hidden_dim);
    matmul(input.data(), W_up.data(), up.data(), embed_dim, hidden_dim);
    
    auto proj_end = chrono::high_resolution_clock::now();
    auto proj_us = chrono::duration_cast<chrono::microseconds>(proj_end - proj_start).count();
    
    cout << "  ✓ Projected to hidden dimension\n";
    cout << "    Gate size: " << gate.size() << "\n";
    cout << "    Up size: " << up.size() << "\n";
    cout << "    Projection time: " << proj_us << " μs\n";
    cout << "    Gate[0:5]: ";
    for (int i = 0; i < min(5, (int)gate.size()); i++) {
        cout << fixed << setprecision(4) << gate[i] << " ";
    }
    cout << "\n    Up[0:5]: ";
    for (int i = 0; i < min(5, (int)up.size()); i++) {
        cout << fixed << setprecision(4) << up[i] << " ";
    }
    cout << "\n\n";
    
    // Step 2: Apply SwiGLU
    cout << "[3/5] Applying SwiGLU activation...\n";
    
    vector<float> swiglu_out(hidden_dim);
    
    auto swiglu_start = chrono::high_resolution_clock::now();
    
    swiglu(gate.data(), up.data(), swiglu_out.data(), hidden_dim);
    
    auto swiglu_end = chrono::high_resolution_clock::now();
    auto swiglu_us = chrono::duration_cast<chrono::microseconds>(swiglu_end - swiglu_start).count();
    
    cout << "  ✓ SwiGLU applied\n";
    cout << "    Time: " << swiglu_us << " μs\n";
    cout << "    SwiGLU[0:5]: ";
    for (int i = 0; i < min(5, (int)swiglu_out.size()); i++) {
        cout << fixed << setprecision(4) << swiglu_out[i] << " ";
    }
    cout << "\n\n";
    
    // Step 3: Project back down
    cout << "[4/5] Projecting back to embedding dimension...\n";
    
    vector<float> output(embed_dim);
    
    auto down_start = chrono::high_resolution_clock::now();
    
    matmul(swiglu_out.data(), W_down.data(), output.data(), hidden_dim, embed_dim);
    
    auto down_end = chrono::high_resolution_clock::now();
    auto down_us = chrono::duration_cast<chrono::microseconds>(down_end - down_start).count();
    
    cout << "  ✓ Projected back\n";
    cout << "    Output size: " << output.size() << "\n";
    cout << "    Projection time: " << down_us << " μs\n\n";
    
    // Validate
    cout << "[5/5] Validating FFN output...\n";
    
    bool no_nan_inf = true;
    float min_val = FLT_MAX, max_val = -FLT_MAX, sum = 0.0f;
    
    for (float v : output) {
        if (isnan(v) || isinf(v)) {
            no_nan_inf = false;
            break;
        }
        min_val = min(min_val, v);
        max_val = max(max_val, v);
        sum += v;
    }
    
    float mean = sum / output.size();
    
    cout << "  Output statistics:\n";
    cout << "    Range: [" << fixed << setprecision(6) << min_val << ", " << max_val << "]\n";
    cout << "    Mean: " << mean << "\n";
    cout << "    No NaN/Inf: " << (no_nan_inf ? "✓" : "✗") << "\n";
    
    // Check that output is in reasonable range
    bool range_ok = (min_val > -10.0f && max_val < 10.0f);
    cout << "    Range check: " << (range_ok ? "✓" : "✗") << " (should be in [-10, 10])\n";
    
    cout << "\n  First 20 output values:\n";
    for (int i = 0; i < min(20, (int)output.size()); i++) {
        cout << "    [" << setw(4) << i << "] " << fixed << setprecision(6) << output[i] << "\n";
    }
    
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - start).count();
    
    auto total_compute_us = proj_us + swiglu_us + down_us;
    
    cout << "\n" << string(60, '=') << "\n";
    cout << "Summary:\n";
    cout << "  Operation: FFN with SwiGLU\n";
    cout << "  Formula: (Swish(x @ W_gate) * (x @ W_up)) @ W_down\n";
    cout << "  Input dimension: " << embed_dim << "\n";
    cout << "  Hidden dimension: " << hidden_dim << "\n";
    cout << "  Projection time: " << proj_us << " μs\n";
    cout << "  SwiGLU time: " << swiglu_us << " μs\n";
    cout << "  Down projection time: " << down_us << " μs\n";
    cout << "  Total compute time: " << total_compute_us << " μs\n";
    cout << "  Total time: " << total_ms << " ms\n";
    
    if (no_nan_inf && range_ok) {
        cout << "  Status: ✅ FFN/SWIGLU TEST PASSED\n";
        return 0;
    } else {
        cout << "  Status: ❌ FFN test failed\n";
        return 1;
    }
}
