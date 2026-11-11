// ============================================================================
// q4_0_simple_test.cpp - Simple Q4_0 Kernel Validation
// ============================================================================
//
// Standalone test that validates the MASM Q4_0 kernel against a simple
// reference implementation without requiring full GGML integration.
//
// Build:
//   cl /std:c++17 /EHsc /O2 /Fe:q4_0_simple_test.exe q4_0_simple_test.cpp kernels\masm\q4_0_dequant.obj /link
//
// ============================================================================

#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <cstdint>

// MASM kernel declaration
extern "C" int MASM_Q4_0_Dequantize(const void* input, float* output, size_t num_blocks);

// ============================================================================
// Q4_0 Block Structure (18 bytes total)
// ============================================================================
#pragma pack(push, 1)
struct block_q4_0 {
    float d;              // scale (4 bytes)
    uint8_t qs[8];        // 16 nibbles packed into 8 bytes
    uint8_t padding[6];    // Padding to 18 bytes
};
#pragma pack(pop)

static_assert(sizeof(block_q4_0) == 18, "block_q4_0 must be 18 bytes");

// ============================================================================
// Reference Implementation (C++)
// ============================================================================
void dequantize_q4_0_scalar(const block_q4_0* blocks, float* output, size_t num_blocks) {
    for (size_t b = 0; b < num_blocks; ++b) {
        const block_q4_0& block = blocks[b];
        float scale = block.d;
        
        for (int i = 0; i < 8; ++i) {
            uint8_t byte = block.qs[i];
            
            // Low nibble (bits 0-3)
            int low_nibble = byte & 0x0F;
            float low_weight = (low_nibble - 8) * scale;
            output[b * 16 + i * 2] = low_weight;
            
            // High nibble (bits 4-7)
            int high_nibble = (byte >> 4) & 0x0F;
            float high_weight = (high_nibble - 8) * scale;
            output[b * 16 + i * 2 + 1] = high_weight;
        }
    }
}

// ============================================================================
// Test Configuration
// ============================================================================
constexpr int RANDOM_SEED = 42;
constexpr size_t TEST_BLOCKS = 1000;
constexpr double ERROR_TOLERANCE = 1e-5;

// ============================================================================
// Generate Test Data
// ============================================================================
std::vector<block_q4_0> generate_test_blocks(size_t num_blocks, int seed) {
    std::mt19937 gen(seed);
    std::uniform_real_distribution<float> scale_dist(0.001f, 1.0f);
    std::uniform_int_distribution<int> nibble_dist(0, 15);
    
    std::vector<block_q4_0> blocks(num_blocks);
    
    for (size_t b = 0; b < num_blocks; ++b) {
        blocks[b].d = scale_dist(gen);
        
        for (int i = 0; i < 8; ++i) {
            int low_nibble = nibble_dist(gen);
            int high_nibble = nibble_dist(gen);
            blocks[b].qs[i] = (high_nibble << 4) | low_nibble;
        }
        
        std::memset(blocks[b].padding, 0, sizeof(blocks[b].padding));
    }
    
    return blocks;
}

// ============================================================================
// Compare Results
// ============================================================================
struct TestResult {
    double max_error;
    double mean_error;
    size_t mismatches;
    bool passed;
};

TestResult compare_results(const float* expected, const float* actual, size_t count) {
    TestResult result = {0.0, 0.0, 0, true};
    
    double sum_error = 0.0;
    
    for (size_t i = 0; i < count; ++i) {
        double error = std::abs(static_cast<double>(expected[i]) - static_cast<double>(actual[i]));
        sum_error += error;
        result.max_error = std::max(result.max_error, error);
        
        if (error > ERROR_TOLERANCE) {
            result.mismatches++;
            if (result.mismatches <= 5) {
                std::cout << "  Mismatch at index " << i << ": expected " 
                          << std::setprecision(10) << expected[i] << ", got " 
                          << actual[i] << " (error: " << std::scientific << error << ")\n";
            }
        }
    }
    
    result.mean_error = sum_error / count;
    result.passed = (result.mismatches == 0);
    
    return result;
}

// ============================================================================
// Main Test
// ============================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "Q4_0 MASM Kernel Validation Test\n";
    std::cout << "========================================\n";
    std::cout << "Random seed:      " << RANDOM_SEED << "\n";
    std::cout << "Test blocks:      " << TEST_BLOCKS << "\n";
    std::cout << "Error tolerance:  " << ERROR_TOLERANCE << "\n";
    std::cout << "========================================\n\n";
    
    // Generate test data
    std::cout << "[1/4] Generating test blocks...\n";
    std::vector<block_q4_0> blocks = generate_test_blocks(TEST_BLOCKS, RANDOM_SEED);
    std::cout << "      Generated " << blocks.size() << " blocks\n\n";
    
    // Allocate output buffers
    std::cout << "[2/4] Allocating output buffers...\n";
    size_t num_floats = TEST_BLOCKS * 16;
    std::vector<float> scalar_output(num_floats);
    std::vector<float> masm_output(num_floats);
    std::cout << "      Allocated " << num_floats << " floats\n\n";
    
    // Run scalar reference
    std::cout << "[3/4] Running scalar reference...\n";
    dequantize_q4_0_scalar(blocks.data(), scalar_output.data(), TEST_BLOCKS);
    std::cout << "      Complete\n\n";
    
    // Run MASM kernel
    std::cout << "[4/4] Running MASM kernel...\n";
    int ret = MASM_Q4_0_Dequantize(blocks.data(), masm_output.data(), TEST_BLOCKS);
    if (ret != 0) {
        std::cerr << "ERROR: MASM kernel returned " << ret << "\n";
        return 1;
    }
    std::cout << "      Complete\n\n";
    
    // Compare results
    std::cout << "Comparing results...\n";
    TestResult result = compare_results(scalar_output.data(), masm_output.data(), num_floats);
    
    // Print results
    std::cout << "\n========================================\n";
    std::cout << "Test Results\n";
    std::cout << "========================================\n";
    std::cout << "Floats compared:  " << num_floats << "\n";
    std::cout << "Max error:        " << std::scientific << result.max_error;
    if (result.max_error < ERROR_TOLERANCE) {
        std::cout << " ✅ (< " << ERROR_TOLERANCE << ")\n";
    } else {
        std::cout << " ❌ (>= " << ERROR_TOLERANCE << ")\n";
    }
    std::cout << "Mean error:       " << std::scientific << result.mean_error << "\n";
    std::cout << "Mismatches:       " << result.mismatches;
    if (result.mismatches == 0) {
        std::cout << " ✅\n";
    } else {
        std::cout << " ❌\n";
    }
    std::cout << "Overall:          " << (result.passed ? "✅ PASSED" : "❌ FAILED") << "\n";
    std::cout << "========================================\n";
    
    return result.passed ? 0 : 1;
}
