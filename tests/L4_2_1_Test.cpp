// L4_2_1_Test.cpp
// L4.2.1 Fused Kernel Validation Test
// Tests the validation framework with a reference implementation

#include "L4_2_1_FusedKernelValidator.h"
#include <iostream>
#include <cstdlib>

using namespace RawrXD::L4;

// ============================================================================
// Test Fused Kernel (Reference Implementation)
// ============================================================================
// This is the "fused" kernel under test - for initial validation,
// we use the reference implementation itself to verify the framework works.
// In production, this would be replaced with an optimized kernel.

void TestFusedQ4_0_Gemv(
    const uint8_t* q4_weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    // For testing: use reference implementation
    // In production, this would be the optimized fused kernel
    ReferenceQ4_0_Gemv(q4_weights, input, output, rows, cols);
}

// ============================================================================
// Main Test
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "L4.2.1 Fused Kernel Validation Test" << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << std::endl;
    
    // Test configuration
    GemvTestConfig config;
    config.rows = 128;  // Small test for speed
    config.cols = 4096;
    config.quant_type = GemvTestConfig::Q4_0;
    config.random_seed = 42;
    config.min_cosine_similarity = 0.9999f;
    config.max_rmse = 1e-4f;
    config.max_absolute_error = 1e-3f;
    
    std::cout << "Test Configuration:" << std::endl;
    std::cout << "  Rows: " << config.rows << std::endl;
    std::cout << "  Cols: " << config.cols << std::endl;
    std::cout << "  Quantization: Q4_0" << std::endl;
    std::cout << "  Random Seed: " << config.random_seed << std::endl;
    std::cout << std::endl;
    
    std::cout << "Generating random test data..." << std::endl;
    
    // Generate test data
    uint8_t* weights = GenerateRandomQ4_0_Weights(config.rows, config.cols, config.random_seed);
    std::vector<float> input(config.cols);
    GenerateRandomVector(input.data(), config.cols, config.random_seed + 1);
    
    std::cout << "  ✓ Test data generated" << std::endl;
    std::cout << std::endl;
    
    // Run validation
    std::cout << "Running validation..." << std::endl;
    
    KernelValidationResult result = ValidateFusedGemv(
        TestFusedQ4_0_Gemv,
        weights,
        input.data(),
        config.rows,
        config.cols,
        config
    );
    
    // Print results
    PrintValidationResult(result);
    
    // Cleanup
    delete[] weights;
    
    // Return appropriate exit code
    return result.passed ? 0 : 1;
}
