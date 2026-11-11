// ============================================================================
// Simple Fused Layer Benchmark
// ============================================================================
// Standalone benchmark comparing fused vs non-fused operations
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <cmath>

using namespace std;

// Configuration
constexpr uint32_t HIDDEN_SIZE = 2048;
constexpr uint32_t INTERMEDIATE_SIZE = 5504;
constexpr uint32_t NUM_ITERATIONS = 10000;

// Non-fused: separate passes with memory writes
void NonFusedLayer(const float* input, float* output) {
    // Pass 1: RMSNorm (write to temp)
    float temp1[HIDDEN_SIZE];
    float sum = 0.0f;
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) sum += input[i] * input[i];
    float rms = sqrtf(sum / HIDDEN_SIZE + 1e-5f);
    float scale = 1.0f / rms;
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) temp1[i] = input[i] * scale;
    
    // Pass 2: Attention simulation (write to temp)
    float temp2[HIDDEN_SIZE];
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) temp2[i] = temp1[i] * 0.5f;
    
    // Pass 3: Residual (write to temp)
    float temp3[HIDDEN_SIZE];
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) temp3[i] = input[i] + temp2[i];
    
    // Pass 4: RMSNorm (write to temp)
    sum = 0.0f;
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) sum += temp3[i] * temp3[i];
    rms = sqrtf(sum / HIDDEN_SIZE + 1e-5f);
    scale = 1.0f / rms;
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) temp1[i] = temp3[i] * scale;
    
    // Pass 5: MLP gate (write to temp)
    float temp4[INTERMEDIATE_SIZE];
    for (uint32_t i = 0; i < INTERMEDIATE_SIZE; i++) {
        float x = temp1[i % HIDDEN_SIZE] * 0.01f;
        temp4[i] = x / (1.0f + expf(-x));
    }
    
    // Pass 6: MLP up (write to temp)
    float temp5[INTERMEDIATE_SIZE];
    for (uint32_t i = 0; i < INTERMEDIATE_SIZE; i++) {
        temp5[i] = temp1[i % HIDDEN_SIZE] * 0.01f;
    }
    
    // Pass 7: Multiply (write to temp)
    for (uint32_t i = 0; i < INTERMEDIATE_SIZE; i++) temp5[i] *= temp4[i];
    
    // Pass 8: Down proj (write to output)
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) {
        float sum = 0.0f;
        for (uint32_t j = 0; j < INTERMEDIATE_SIZE; j++) sum += temp5[j] * 0.001f;
        output[i] = sum;
    }
    
    // Pass 9: Residual
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) output[i] += temp3[i];
}

// Fused: single pass, cache-resident
void FusedLayer(const float* input, float* output) {
    // Stack-allocated buffers (L1 cache resident)
    float norm1[HIDDEN_SIZE];
    float attn_out[HIDDEN_SIZE];
    float residual1[HIDDEN_SIZE];
    float gate[INTERMEDIATE_SIZE];
    float up[INTERMEDIATE_SIZE];
    
    // Fused Pass 1: RMSNorm + Attention + Residual
    float sum = 0.0f;
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) sum += input[i] * input[i];
    float rms = sqrtf(sum / HIDDEN_SIZE + 1e-5f);
    float scale = 1.0f / rms;
    
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) {
        norm1[i] = input[i] * scale;
        attn_out[i] = norm1[i] * 0.5f;
        residual1[i] = input[i] + attn_out[i];
    }
    
    // Fused Pass 2: RMSNorm + MLP
    sum = 0.0f;
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) sum += residual1[i] * residual1[i];
    rms = sqrtf(sum / HIDDEN_SIZE + 1e-5f);
    scale = 1.0f / rms;
    
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) norm1[i] = residual1[i] * scale;
    
    // Fused MLP: gate + up + multiply
    for (uint32_t i = 0; i < INTERMEDIATE_SIZE; i++) {
        float x = norm1[i % HIDDEN_SIZE] * 0.01f;
        gate[i] = x / (1.0f + expf(-x));
        up[i] = norm1[i % HIDDEN_SIZE] * 0.01f;
        up[i] *= gate[i];
    }
    
    // Fused down + residual
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) {
        float down = 0.0f;
        for (uint32_t j = 0; j < INTERMEDIATE_SIZE; j++) down += up[j] * 0.001f;
        output[i] = residual1[i] + down;
    }
}

int main() {
    cout << "========================================\n";
    cout << "Simple Fused Layer Benchmark\n";
    cout << "========================================\n\n";
    
    cout << "Configuration:\n";
    cout << "  Hidden size: " << HIDDEN_SIZE << "\n";
    cout << "  Intermediate: " << INTERMEDIATE_SIZE << "\n";
    cout << "  Iterations: " << NUM_ITERATIONS << "\n\n";
    
    // Allocate buffers
    alignas(64) float input[HIDDEN_SIZE];
    alignas(64) float output[HIDDEN_SIZE];
    
    // Initialize input
    for (uint32_t i = 0; i < HIDDEN_SIZE; i++) input[i] = 0.1f;
    
    // Warmup
    cout << "Warming up...\n";
    for (uint32_t i = 0; i < 1000; i++) {
        NonFusedLayer(input, output);
        FusedLayer(input, output);
    }
    
    // Benchmark non-fused
    cout << "Running non-fused benchmark...\n";
    auto start = chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < NUM_ITERATIONS; i++) {
        NonFusedLayer(input, output);
    }
    auto end = chrono::high_resolution_clock::now();
    double non_fused_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    
    // Benchmark fused
    cout << "Running fused benchmark...\n";
    start = chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < NUM_ITERATIONS; i++) {
        FusedLayer(input, output);
    }
    end = chrono::high_resolution_clock::now();
    double fused_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    
    // Results
    cout << "\n========================================\n";
    cout << "Results\n";
    cout << "========================================\n";
    cout << fixed << setprecision(2);
    cout << "  Non-fused: " << non_fused_ms << " ms\n";
    cout << "  Fused:     " << fused_ms << " ms\n";
    cout << "  Speedup:   " << (non_fused_ms / fused_ms) << "x\n";
    cout << "  Improvement: " << ((non_fused_ms - fused_ms) / non_fused_ms * 100) << "%\n\n";
    
    // Per-layer stats
    double non_fused_per_layer = non_fused_ms / NUM_ITERATIONS;
    double fused_per_layer = fused_ms / NUM_ITERATIONS;
    cout << "Per-layer latency:\n";
    cout << "  Non-fused: " << (non_fused_per_layer * 1000) << " us\n";
    cout << "  Fused:     " << (fused_per_layer * 1000) << " us\n\n";
    
    // Projected tokens/sec (24 layers)
    double non_fused_tok_s = 1000.0 / (non_fused_per_layer * 24);
    double fused_tok_s = 1000.0 / (fused_per_layer * 24);
    cout << "Projected tokens/sec (24 layers):\n";
    cout << "  Non-fused: " << non_fused_tok_s << " tok/s\n";
    cout << "  Fused:     " << fused_tok_s << " tok/s\n\n";
    
    return 0;
}
