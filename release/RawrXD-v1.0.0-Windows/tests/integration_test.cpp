/**
 * @file integration_test.cpp
 * @brief Phase 21: System Integration Test
 *
 * Validates the AVX2 kernel library with end-to-end inference simulation.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cfloat>
#include <algorithm>

#include "../kernels/gemm_avx2.h"
#include "../kernels/attention_avx2.h"

using namespace std;
using namespace rawrxd::kernels;

using Clock = chrono::high_resolution_clock;

// Configuration matching Phi-3-mini
const int HIDDEN_DIM = 3072;
const int FFN_DIM = 8192;
const int NUM_HEADS = 32;
const int HEAD_DIM = 96;
const int NUM_LAYERS = 32;
const int NUM_ITERATIONS = 5;
const int NUM_THREADS = 8;

// ============================================================================
// Utility Functions
// ============================================================================

void initialize_random(float* data, int size, unsigned int seed) {
    srand(seed);
    for (int i = 0; i < size; i++) {
        data[i] = ((float)rand() / RAND_MAX - 0.5f) * 0.1f;
    }
}

float compute_max_error(const float* a, const float* b, int size) {
    float max_error = 0.0f;
    for (int i = 0; i < size; i++) {
        float error = fabs(a[i] - b[i]);
        if (error > max_error) max_error = error;
    }
    return max_error;
}

// ============================================================================
// Scalar reference implementations
// ============================================================================

void gemv_scalar(const float* weights, const float* input, float* output,
                 int rows, int cols) {
    for (int i = 0; i < rows; i++) {
        float sum = 0.0f;
        for (int j = 0; j < cols; j++) {
            sum += weights[i * cols + j] * input[j];
        }
        output[i] = sum;
    }
}

inline float silu(float x) {
    return x / (1.0f + expf(-x));
}

void ffn_scalar(const float* input,
                const float* w_gate, const float* w_up, const float* w_down,
                float* output, int hidden_dim, int ffn_dim) {
    vector<float> gate(ffn_dim);
    vector<float> up(ffn_dim);
    vector<float> fused(ffn_dim);

    // Gate projection
    gemv_scalar(w_gate, input, gate.data(), ffn_dim, hidden_dim);
    for (int i = 0; i < ffn_dim; i++) gate[i] = silu(gate[i]);

    // Up projection
    gemv_scalar(w_up, input, up.data(), ffn_dim, hidden_dim);

    // Multiply
    for (int i = 0; i < ffn_dim; i++) fused[i] = gate[i] * up[i];

    // Down projection
    gemv_scalar(w_down, fused.data(), output, hidden_dim, ffn_dim);
}

// ============================================================================
// Integration Test
// ============================================================================

int main() {
    cout << "🔬 RawrXD Phase 21: System Integration Test\n";
    cout << "=============================================\n\n";

    cout << "Configuration:\n";
    cout << "  Hidden dim: " << HIDDEN_DIM << "\n";
    cout << "  FFN dim: " << FFN_DIM << "\n";
    cout << "  Num heads: " << NUM_HEADS << "\n";
    cout << "  Head dim: " << HEAD_DIM << "\n";
    cout << "  Num layers: " << NUM_LAYERS << "\n";
    cout << "  Threads: " << NUM_THREADS << "\n\n";

    // Allocate memory
    cout << "[1/4] Allocating memory...\n";
    vector<float> input(HIDDEN_DIM);
    vector<float> w_gate(FFN_DIM * HIDDEN_DIM);
    vector<float> w_up(FFN_DIM * HIDDEN_DIM);
    vector<float> w_down(HIDDEN_DIM * FFN_DIM);
    vector<float> output_scalar(HIDDEN_DIM);
    vector<float> output_avx2(HIDDEN_DIM);

    // Initialize weights
    initialize_random(input.data(), HIDDEN_DIM, 42);
    initialize_random(w_gate.data(), FFN_DIM * HIDDEN_DIM, 43);
    initialize_random(w_up.data(), FFN_DIM * HIDDEN_DIM, 44);
    initialize_random(w_down.data(), HIDDEN_DIM * FFN_DIM, 45);
    cout << "  ✓ Memory allocated\n\n";

    // Test 1: FFN SwiGLU
    cout << "[2/4] Testing FFN SwiGLU...\n";

    // Scalar reference
    ffn_scalar(input.data(), w_gate.data(), w_up.data(), w_down.data(),
               output_scalar.data(), HIDDEN_DIM, FFN_DIM);

    // AVX2 optimized
    ffn_swiglu_avx2_mt(input.data(), w_gate.data(), w_up.data(), w_down.data(),
                       output_avx2.data(), HIDDEN_DIM, FFN_DIM, NUM_THREADS);

    // Validate
    float ffn_error = compute_max_error(output_scalar.data(), output_avx2.data(), HIDDEN_DIM);
    cout << "  Max error: " << fixed << setprecision(6) << ffn_error << "\n";
    cout << "  Status: " << (ffn_error < 0.001 ? "✅ PASSED" : "❌ FAILED") << "\n\n";

    // Test 2: GEMV
    cout << "[3/4] Testing GEMV...\n";

    vector<float> gemv_input(HIDDEN_DIM);
    vector<float> gemv_weights(FFN_DIM * HIDDEN_DIM);
    vector<float> gemv_scalar_out(FFN_DIM);
    vector<float> gemv_avx2_out(FFN_DIM);

    initialize_random(gemv_input.data(), HIDDEN_DIM, 46);
    initialize_random(gemv_weights.data(), FFN_DIM * HIDDEN_DIM, 47);

    gemv_scalar(gemv_weights.data(), gemv_input.data(), gemv_scalar_out.data(),
                FFN_DIM, HIDDEN_DIM);
    gemv_avx2_mt(gemv_weights.data(), gemv_input.data(), gemv_avx2_out.data(),
                 FFN_DIM, HIDDEN_DIM, NUM_THREADS);

    float gemv_error = compute_max_error(gemv_scalar_out.data(), gemv_avx2_out.data(), FFN_DIM);
    cout << "  Max error: " << fixed << setprecision(6) << gemv_error << "\n";
    cout << "  Status: " << (gemv_error < 0.001 ? "✅ PASSED" : "❌ FAILED") << "\n\n";

    // Test 3: Performance Benchmark
    cout << "[4/4] Performance benchmark...\n\n";

    // Warmup
    for (int i = 0; i < 3; i++) {
        ffn_swiglu_avx2_mt(input.data(), w_gate.data(), w_up.data(), w_down.data(),
                           output_avx2.data(), HIDDEN_DIM, FFN_DIM, NUM_THREADS);
    }

    // Benchmark scalar
    auto start_scalar = Clock::now();
    for (int iter = 0; iter < NUM_ITERATIONS; iter++) {
        for (int layer = 0; layer < NUM_LAYERS; layer++) {
            ffn_scalar(input.data(), w_gate.data(), w_up.data(), w_down.data(),
                      output_scalar.data(), HIDDEN_DIM, FFN_DIM);
        }
    }
    auto end_scalar = Clock::now();

    // Benchmark AVX2
    auto start_avx2 = Clock::now();
    for (int iter = 0; iter < NUM_ITERATIONS; iter++) {
        for (int layer = 0; layer < NUM_LAYERS; layer++) {
            ffn_swiglu_avx2_mt(input.data(), w_gate.data(), w_up.data(), w_down.data(),
                              output_avx2.data(), HIDDEN_DIM, FFN_DIM, NUM_THREADS);
        }
    }
    auto end_avx2 = Clock::now();

    double scalar_ms = chrono::duration_cast<chrono::microseconds>(end_scalar - start_scalar).count() / 1000.0 / NUM_ITERATIONS;
    double avx2_ms = chrono::duration_cast<chrono::microseconds>(end_avx2 - start_avx2).count() / 1000.0 / NUM_ITERATIONS;
    double speedup = scalar_ms / avx2_ms;

    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "PERFORMANCE RESULTS (" << NUM_LAYERS << " layers)\n";
    cout << "═══════════════════════════════════════════════════════════\n\n";

    cout << left << setw(20) << "Implementation";
    cout << right << setw(15) << "Time (ms)";
    cout << setw(15) << "Speedup" << "\n";
    cout << string(50, '-') << "\n";

    cout << left << setw(20) << "Scalar";
    cout << right << fixed << setprecision(2) << setw(15) << scalar_ms;
    cout << setw(15) << "1.00x" << "\n";

    cout << left << setw(20) << "AVX2 + MT";
    cout << right << fixed << setprecision(2) << setw(15) << avx2_ms;
    cout << setw(14) << fixed << setprecision(2) << speedup << "x" << "\n";

    cout << "\n" << string(50, '=') << "\n";

    // Summary
    cout << "\nSUMMARY\n";
    cout << "=======\n";
    cout << "FFN SwiGLU:        " << (ffn_error < 0.001 ? "✅ PASSED" : "❌ FAILED") << "\n";
    cout << "GEMV:              " << (gemv_error < 0.001 ? "✅ PASSED" : "❌ FAILED") << "\n";
    cout << "Speedup:           " << fixed << setprecision(2) << speedup << "x\n";

    if (ffn_error < 0.001 && gemv_error < 0.001 && speedup > 1.0) {
        cout << "\n✅ PHASE 21: INTEGRATION SUCCESSFUL\n";
        cout << "\nKernels are ready for production use.\n";
        return 0;
    } else {
        cout << "\n❌ Integration test failed\n";
        return 1;
    }
}
