// L4_2_1_AVX2_Test.cpp
// Test AVX2 fused kernel against reference implementation

#include "L4_2_1_FusedKernelValidator.h"
#include <iostream>

// Declare the AVX2 kernel
namespace RawrXD {
namespace L4 {
    void FusedQ4_0_Gemv_AVX2_Simple(
        const uint8_t* q4_weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
}
}

using namespace RawrXD::L4;

int main() {
    std::cout << "L4.2.1 AVX2 Kernel Validation Test" << std::endl;
    std::cout << "=================================" << std::endl;
    std::cout << std::endl;
    
    // Test configuration
    GemvTestConfig config;
    config.rows = 128;
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
    std::cout << std::endl;
    
    // Generate test data
    std::cout << "Generating test data..." << std::endl;
    uint8_t* weights = GenerateRandomQ4_0_Weights(config.rows, config.cols, config.random_seed);
    std::vector<float> input(config.cols);
    GenerateRandomVector(input.data(), config.cols, config.random_seed + 1);
    std::cout << "  ✓ Test data generated" << std::endl;
    std::cout << std::endl;
    
    // Validate AVX2 kernel
    std::cout << "Validating AVX2 kernel..." << std::endl;
    KernelValidationResult result = ValidateFusedGemv(
        FusedQ4_0_Gemv_AVX2_Simple,
        weights,
        input.data(),
        config.rows,
        config.cols,
        config
    );
    
    PrintValidationResult(result);
    
    delete[] weights;
    
    return result.passed ? 0 : 1;
}
