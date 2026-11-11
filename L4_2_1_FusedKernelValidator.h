// L4_2_1_FusedKernelValidator.h
// L4.2.1 Fused Kernel Validation - Compute Contract Hardening
//
// Validates that fused Q4_0 GEMV kernels produce numerically equivalent output
// to reference (dequantize-then-GEMV) implementation.

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace RawrXD {
namespace L4 {

// ============================================================================
// Validation Result Structure
// ============================================================================

struct KernelValidationResult {
    bool passed;
    
    // Similarity metrics
    float cosine_similarity;
    float rmse;
    float max_error;
    float mean_error;
    
    // Test metadata
    size_t elements_tested;
    size_t rows_tested;
    size_t cols_tested;
    
    // Failure details (if any)
    size_t first_mismatch_index;
    float first_mismatch_expected;
    float first_mismatch_actual;
    
    // Timing (optional)
    double reference_time_ms;
    double fused_time_ms;
    float speedup;
};

// ============================================================================
// Test Configuration
// ============================================================================

struct GemvTestConfig {
    // Matrix dimensions
    size_t rows;
    size_t cols;
    
    // Quantization type
    enum QuantType { Q4_0, Q4_K, Q8_0 } quant_type;
    
    // Random seed for reproducibility
    uint32_t random_seed;
    
    // Validation thresholds
    float min_cosine_similarity;
    float max_rmse;
    float max_absolute_error;
    
    // Constructor with defaults
    GemvTestConfig(
        size_t r = 4096,
        size_t c = 4096,
        QuantType qt = Q4_0,
        uint32_t seed = 42,
        float min_cos = 0.9999f,
        float max_r = 1e-4f,
        float max_err = 1e-3f
    ) : rows(r), cols(c), quant_type(qt), random_seed(seed),
        min_cosine_similarity(min_cos), max_rmse(max_r), max_absolute_error(max_err) {}
};

// ============================================================================
// Reference Implementation (Slow, Unoptimized, Correct)
// ============================================================================

// Reference GEMV: y = A * x
// A: rows x cols matrix (row-major)
// x: cols vector
// y: rows vector
void ReferenceGemv(
    const float* A,      // rows x cols matrix
    const float* x,      // cols vector
    float* y,            // rows output
    size_t rows,
    size_t cols
);

// Reference Q4_0 dequantize + GEMV
// Dequantizes Q4_0 weights to FP32 buffer, then runs reference GEMV
void ReferenceQ4_0_Gemv(
    const uint8_t* q4_weights,  // Q4_0 encoded weights (18 bytes per 32 values)
    const float* input,         // cols vector
    float* output,              // rows output
    size_t rows,
    size_t cols
);

// ============================================================================
// Fused Kernel Interface (Production Path)
// ============================================================================

// Fused Q4_0 GEMV kernel signature
// Implementations should match this ABI
using FusedQ4_0_Gemv_Func = void(*) (
    const uint8_t* q4_weights,  // Q4_0 encoded weights
    const float* input,         // cols vector
    float* output,              // rows output
    size_t rows,
    size_t cols
);

// ============================================================================
// Validation Functions
// ============================================================================

// Validate a fused kernel against reference implementation
// Returns detailed validation result
KernelValidationResult ValidateFusedGemv(
    FusedQ4_0_Gemv_Func fused_kernel,    // Kernel under test
    const uint8_t* q4_weights,            // Test weights (Q4_0 encoded)
    const float* input,                   // Test input vector
    size_t rows,
    size_t cols,
    const GemvTestConfig& config
);

// High-level validation with random test data generation
KernelValidationResult ValidateFusedGemvRandom(
    FusedQ4_0_Gemv_Func fused_kernel,
    const GemvTestConfig& config
);

// Validate against known-good reference file
KernelValidationResult ValidateFusedGemvAgainstFile(
    FusedQ4_0_Gemv_Func fused_kernel,
    const std::string& gguf_path,         // Source GGUF file
    const std::string& tensor_name,        // Tensor to test
    uint32_t token_id,                    // Row to use as weights
    const GemvTestConfig& config
);

// ============================================================================
// Utility Functions
// ============================================================================

// Generate random FP32 values in range [-1, 1]
void GenerateRandomVector(float* data, size_t count, uint32_t seed);

// Generate random Q4_0 weights
// Returns allocated buffer (caller must free)
uint8_t* GenerateRandomQ4_0_Weights(size_t rows, size_t cols, uint32_t seed);

// Compare two output vectors
KernelValidationResult CompareOutputs(
    const float* reference,
    const float* actual,
    size_t count,
    const GemvTestConfig& config
);

// Print validation result
void PrintValidationResult(const KernelValidationResult& result);

// Check if result passes acceptance criteria
bool IsValidationPassed(const KernelValidationResult& result);

} // namespace L4
} // namespace RawrXD
