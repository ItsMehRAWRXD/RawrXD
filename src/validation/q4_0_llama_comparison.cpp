// ============================================================================
// q4_0_llama_comparison.cpp - Numerical Comparison Against llama.cpp Reference
// ============================================================================
//
// PURPOSE: Validate MASM Q4_0 kernel against llama.cpp's reference implementation
//
// This test:
//   1. Generates fixed-seed test corpus (reproducible)
//   2. Quantizes using llama.cpp's ggml_quantize_q4_0
//   3. Dequantizes using both llama.cpp's dequantize_row_q4_0 and MASM kernel
//   4. Compares numerical output with tight tolerance (1e-5)
//
// Success Criteria:
//   - Max error < 1e-5 (FP32 rounding tolerance)
//   - Mean error < 1e-6
//   - Zero mismatches across entire corpus
//
// Build:
//   cl /std:c++17 /EHsc /O2 /I..\..\3rdparty\ggml\include /I..\..\3rdparty\ggml\src /Fe:q4_0_llama_comparison.exe q4_0_llama_comparison.cpp ..\..\3rdparty\ggml\src\ggml-quants.c ..\..\3rdparty\ggml\src\ggml.c
//
// ============================================================================

#define GGML_VERSION "1.0.0"
#define GGML_COMMIT "abc123"

#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <cstdint>

// GGML includes
extern "C" {
#include "ggml.h"
#include "ggml-quants.h"
}

// MASM kernel declaration
extern "C" int MASM_Q4_0_Dequantize(const void* input, float* output, size_t num_blocks);

// ============================================================================
// Test Configuration
// ============================================================================
constexpr int RANDOM_SEED = 42;           // Fixed seed for reproducibility
constexpr size_t TEST_CORPUS_SIZE = 10000; // Number of blocks to test
constexpr double ERROR_TOLERANCE = 1e-5;    // Max acceptable error
constexpr double MEAN_TOLERANCE = 1e-6;   // Mean error tolerance

// ============================================================================
// Test Result Structure
// ============================================================================
struct ComparisonResult {
    size_t blocks_tested;
    size_t floats_compared;
    double max_error;
    double mean_error;
    double rmse;
    size_t mismatches;
    bool passed;
    
    void print() const {
        std::cout << "\n========================================\n";
        std::cout << "Q4_0 Numerical Comparison Results\n";
        std::cout << "========================================\n";
        std::cout << "Blocks tested:    " << blocks_tested << "\n";
        std::cout << "Floats compared:  " << floats_compared << "\n";
        std::cout << "Max error:        " << std::scientific << max_error;
        if (max_error < ERROR_TOLERANCE) {
            std::cout << " ✅ (< " << ERROR_TOLERANCE << ")\n";
        } else {
            std::cout << " ❌ (>= " << ERROR_TOLERANCE << ")\n";
        }
        std::cout << "Mean error:       " << std::scientific << mean_error;
        if (mean_error < MEAN_TOLERANCE) {
            std::cout << " ✅ (< " << MEAN_TOLERANCE << ")\n";
        } else {
            std::cout << " ❌ (>= " << MEAN_TOLERANCE << ")\n";
        }
        std::cout << "RMSE:             " << std::scientific << rmse << "\n";
        std::cout << "Mismatches:       " << mismatches;
        if (mismatches == 0) {
            std::cout << " ✅\n";
        } else {
            std::cout << " ❌\n";
        }
        std::cout << "Overall:          " << (passed ? "✅ PASSED" : "❌ FAILED") << "\n";
        std::cout << "========================================\n";
    }
};

// ============================================================================
// Generate Fixed-Seed Test Corpus
// ============================================================================
std::vector<float> generate_test_corpus(size_t num_elements, int seed) {
    std::mt19937 gen(seed);
    
    // Distribution matching typical neural network weight distributions
    // Mix of normal distributions with different scales
    std::normal_distribution<float> dist1(0.0f, 0.1f);   // Small weights
    std::normal_distribution<float> dist2(0.0f, 0.5f);   // Medium weights
    std::normal_distribution<float> dist3(0.0f, 1.0f);   // Large weights
    std::uniform_real_distribution<float> uniform(-2.0f, 2.0f);
    std::uniform_int_distribution<int> mode_dist(0, 3);
    
    std::vector<float> corpus;
    corpus.reserve(num_elements);
    
    for (size_t i = 0; i < num_elements; ++i) {
        int mode = mode_dist(gen);
        float value;
        switch (mode) {
            case 0: value = dist1(gen); break;
            case 1: value = dist2(gen); break;
            case 2: value = dist3(gen); break;
            case 3: value = uniform(gen); break;
            default: value = 0.0f;
        }
        corpus.push_back(value);
    }
    
    return corpus;
}

// ============================================================================
// Compare Outputs
// ============================================================================
ComparisonResult compare_outputs(
    const float* llama_output,
    const float* masm_output,
    size_t count,
    size_t num_blocks
) {
    ComparisonResult result = {};
    result.blocks_tested = num_blocks;
    result.floats_compared = count;
    result.max_error = 0.0;
    result.mean_error = 0.0;
    result.mismatches = 0;
    
    double sum_error = 0.0;
    double sum_error_sq = 0.0;
    
    for (size_t i = 0; i < count; ++i) {
        double error = std::abs(static_cast<double>(llama_output[i]) - static_cast<double>(masm_output[i]));
        sum_error += error;
        sum_error_sq += error * error;
        result.max_error = std::max(result.max_error, error);
        
        if (error > ERROR_TOLERANCE) {
            result.mismatches++;
            if (result.mismatches <= 5) {
                std::cout << "  Mismatch at index " << i << ":\n";
                std::cout << "    llama.cpp: " << std::setprecision(10) << llama_output[i] << "\n";
                std::cout << "    MASM:      " << std::setprecision(10) << masm_output[i] << "\n";
                std::cout << "    Error:     " << std::scientific << error << "\n";
            }
        }
    }
    
    result.mean_error = sum_error / count;
    result.rmse = std::sqrt(sum_error_sq / count);
    result.passed = (result.mismatches == 0) && 
                    (result.max_error < ERROR_TOLERANCE) && 
                    (result.mean_error < MEAN_TOLERANCE);
    
    return result;
}

// ============================================================================
// Main Test
// ============================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "Q4_0 Numerical Comparison Test\n";
    std::cout << "MASM Kernel vs llama.cpp Reference\n";
    std::cout << "========================================\n";
    std::cout << "Random seed:      " << RANDOM_SEED << "\n";
    std::cout << "Corpus size:      " << TEST_CORPUS_SIZE << " blocks\n";
    std::cout << "Error tolerance:  " << ERROR_TOLERANCE << "\n";
    std::cout << "Mean tolerance:   " << MEAN_TOLERANCE << "\n";
    std::cout << "========================================\n\n";
    
    // Initialize GGML
    struct ggml_init_params params;
    params.mem_size = 1024 * 1024 * 1024;  // 1GB
    params.mem_buffer = nullptr;
    params.no_alloc = false;
    struct ggml_context* ctx = ggml_init(params);
    if (!ctx) {
        std::cerr << "Failed to initialize GGML context\n";
        return 1;
    }
    
    // Generate test corpus
    std::cout << "[1/5] Generating fixed-seed test corpus...\n";
    size_t num_elements = TEST_CORPUS_SIZE * 32;  // 32 floats per Q4_0 block
    std::vector<float> test_data = generate_test_corpus(num_elements, RANDOM_SEED);
    std::cout << "      Generated " << test_data.size() << " floats\n\n";
    
    // Allocate buffers for quantized data
    std::cout << "[2/5] Allocating buffers...\n";
    size_t quantized_size = TEST_CORPUS_SIZE * sizeof(block_q4_0);
    std::vector<uint8_t> quantized_data(quantized_size);
    std::vector<float> llama_output(num_elements);
    std::vector<float> masm_output(num_elements);
    std::cout << "      Allocated " << quantized_size << " bytes for quantized data\n\n";
    
    // Quantize using llama.cpp
    std::cout << "[3/5] Quantizing with llama.cpp ggml_quantize_q4_0...\n";
    int64_t hist[16] = {0};
    size_t quantized_bytes = ggml_quantize_q4_0(
        test_data.data(),
        quantized_data.data(),
        num_elements,
        32,  // k
        hist
    );
    std::cout << "      Quantized to " << quantized_bytes << " bytes\n";
    std::cout << "      Histogram: ";
    for (int i = 0; i < 16; ++i) {
        if (hist[i] > 0) {
            std::cout << "[" << i << "]=" << hist[i] << " ";
        }
    }
    std::cout << "\n\n";
    
    // Dequantize using llama.cpp reference
    std::cout << "[4/5] Dequantizing with llama.cpp reference...\n";
    dequantize_row_q4_0(
        reinterpret_cast<const block_q4_0*>(quantized_data.data()),
        llama_output.data(),
        num_elements
    );
    std::cout << "      Complete\n\n";
    
    // Dequantize using MASM kernel
    std::cout << "[5/5] Dequantizing with MASM kernel...\n";
    int ret = MASM_Q4_0_Dequantize(
        quantized_data.data(),
        masm_output.data(),
        TEST_CORPUS_SIZE
    );
    if (ret != 0) {
        std::cerr << "MASM kernel returned error code: " << ret << "\n";
        ggml_free(ctx);
        return 1;
    }
    std::cout << "      Complete\n\n";
    
    // Compare results
    std::cout << "Comparing outputs...\n";
    ComparisonResult result = compare_outputs(
        llama_output.data(),
        masm_output.data(),
        num_elements,
        TEST_CORPUS_SIZE
    );
    
    result.print();
    
    // Cleanup
    ggml_free(ctx);
    
    return result.passed ? 0 : 1;
}
