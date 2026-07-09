// L4_2_1_FusedKernelValidator.cpp
// L4.2.1 Fused Kernel Validation Implementation
//
// Reference implementations are deliberately unoptimized for clarity.
// Fused kernels are expected to match these reference outputs.

#include "L4_2_1_FusedKernelValidator.h"
#include "L4_2_0_TensorRuntime.h"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <cstring>
#include <random>
#include <chrono>

namespace RawrXD {
namespace L4 {

// ============================================================================
// FP16 Conversion (from L4.1 contract)
// ============================================================================

static inline float FP16ToFP32(uint16_t h) {
    const uint32_t sign = (h >> 15) & 0x1;
    const uint32_t exp = (h >> 10) & 0x1F;
    const uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f * 0.00006103515625f;
        return sign ? -val : val;
    }
    if (exp == 0x1F) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    const uint32_t exp32 = exp + 112;
    const uint32_t mant32 = mant << 13;
    const uint32_t fp32 = (sign << 31) | (exp32 << 23) | mant32;
    
    union { uint32_t i; float f; } conv;
    conv.i = fp32;
    return conv.f;
}

// ============================================================================
// Q4_0 Block Structure
// ============================================================================

struct Q4_0_Block {
    uint16_t scale;
    uint8_t quants[16];
};

static_assert(sizeof(Q4_0_Block) == 18, "Q4_0 block must be 18 bytes");

// Dequantize Q4_0 block to FP32
static void DequantizeQ4_0_Block(
    const Q4_0_Block* block,
    float* output,
    int n_values = 32
) {
    float scale = FP16ToFP32(block->scale);
    
    // NaN/Inf policy: ZERO_FILL (L4.1 contract)
    if (std::isnan(scale) || std::isinf(scale)) {
        for (int i = 0; i < n_values; i++) {
            output[i] = 0.0f;
        }
        return;
    }
    
    for (int i = 0; i < 16 && (i * 2) < n_values; i++) {
        uint8_t byte = block->quants[i];
        int low = (byte & 0x0F) - 8;
        int high = ((byte >> 4) & 0x0F) - 8;
        
        output[i * 2] = low * scale;
        if ((i * 2 + 1) < n_values) {
            output[i * 2 + 1] = high * scale;
        }
    }
}

// ============================================================================
// Reference Implementations (Slow, Unoptimized, Correct)
// ============================================================================

void ReferenceGemv(
    const float* A,
    const float* x,
    float* y,
    size_t rows,
    size_t cols
) {
    for (size_t r = 0; r < rows; r++) {
        float sum = 0.0f;
        for (size_t c = 0; c < cols; c++) {
            sum += A[r * cols + c] * x[c];
        }
        y[r] = sum;
    }
}

void ReferenceQ4_0_Gemv(
    const uint8_t* q4_weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    // Step 1: Dequantize Q4_0 weights to FP32 buffer
    std::vector<float> dequantized(rows * cols);
    
    size_t blocks_per_row = (cols + 31) / 32;
    
    for (size_t r = 0; r < rows; r++) {
        for (size_t b = 0; b < blocks_per_row; b++) {
            const Q4_0_Block* block = reinterpret_cast<const Q4_0_Block*>(
                q4_weights + (r * blocks_per_row + b) * sizeof(Q4_0_Block)
            );
            
            size_t out_pos = r * cols + b * 32;
            size_t remaining = cols - b * 32;
            DequantizeQ4_0_Block(block, &dequantized[out_pos], std::min(size_t(32), remaining));
        }
    }
    
    // Step 2: Run reference GEMV on dequantized weights
    ReferenceGemv(dequantized.data(), input, output, rows, cols);
}

// ============================================================================
// Utility Functions
// ============================================================================

void GenerateRandomVector(float* data, size_t count, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (size_t i = 0; i < count; i++) {
        data[i] = dist(rng);
    }
}

uint8_t* GenerateRandomQ4_0_Weights(size_t rows, size_t cols, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> scale_dist(0.001f, 0.1f);
    std::uniform_int_distribution<int> quant_dist(0, 15);
    
    size_t blocks_per_row = (cols + 31) / 32;
    size_t total_blocks = rows * blocks_per_row;
    size_t buffer_size = total_blocks * sizeof(Q4_0_Block);
    
    uint8_t* buffer = new uint8_t[buffer_size];
    
    for (size_t r = 0; r < rows; r++) {
        for (size_t b = 0; b < blocks_per_row; b++) {
            Q4_0_Block* block = reinterpret_cast<Q4_0_Block*>(
                buffer + (r * blocks_per_row + b) * sizeof(Q4_0_Block)
            );
            
            // Generate random scale (FP16)
            float scale = scale_dist(rng);
            // Simple FP32 to FP16 conversion
            uint32_t f32_bits;
            memcpy(&f32_bits, &scale, 4);
            uint32_t sign = (f32_bits >> 31) & 0x1;
            uint32_t exp = ((f32_bits >> 23) & 0xFF) - 112;
            uint32_t mant = (f32_bits >> 13) & 0x3FF;
            block->scale = static_cast<uint16_t>((sign << 15) | (exp << 10) | mant);
            
            // Generate random quants
            for (int i = 0; i < 16; i++) {
                int low = quant_dist(rng);
                int high = quant_dist(rng);
                block->quants[i] = (high << 4) | low;
            }
        }
    }
    
    return buffer;
}

// ============================================================================
// Comparison and Validation
// ============================================================================

KernelValidationResult CompareOutputs(
    const float* reference,
    const float* actual,
    size_t count,
    const GemvTestConfig& config
) {
    KernelValidationResult result = {};
    result.elements_tested = count;
    result.passed = false;
    result.first_mismatch_index = count; // Initialize to "no mismatch"
    
    double sum_error = 0.0;
    double sum_sq_error = 0.0;
    double dot_product = 0.0;
    double norm_ref = 0.0;
    double norm_actual = 0.0;
    
    result.max_error = 0.0f;
    
    for (size_t i = 0; i < count; i++) {
        float ref_val = reference[i];
        float act_val = actual[i];
        
        // Skip NaN comparisons
        if (std::isnan(ref_val) || std::isnan(act_val)) {
            continue;
        }
        
        float error = std::abs(ref_val - act_val);
        
        if (error > result.max_error) {
            result.max_error = error;
        }
        
        sum_error += error;
        sum_sq_error += error * error;
        
        dot_product += ref_val * act_val;
        norm_ref += ref_val * ref_val;
        norm_actual += act_val * act_val;
        
        // Track first mismatch
        if (error > config.max_absolute_error && result.first_mismatch_index == count) {
            result.first_mismatch_index = i;
            result.first_mismatch_expected = ref_val;
            result.first_mismatch_actual = act_val;
        }
    }
    
    result.mean_error = static_cast<float>(sum_error / count);
    result.rmse = static_cast<float>(std::sqrt(sum_sq_error / count));
    
    if (norm_ref > 0.0 && norm_actual > 0.0) {
        result.cosine_similarity = static_cast<float>(
            dot_product / (std::sqrt(norm_ref) * std::sqrt(norm_actual))
        );
    } else {
        result.cosine_similarity = 0.0f;
    }
    
    // Determine pass/fail
    result.passed = (
        result.cosine_similarity >= config.min_cosine_similarity &&
        result.rmse <= config.max_rmse &&
        result.max_error <= config.max_absolute_error
    );
    
    return result;
}

// ============================================================================
// Validation Entry Points
// ============================================================================

KernelValidationResult ValidateFusedGemv(
    FusedQ4_0_Gemv_Func fused_kernel,
    const uint8_t* q4_weights,
    const float* input,
    size_t rows,
    size_t cols,
    const GemvTestConfig& config
) {
    // Allocate output buffers
    std::vector<float> reference_output(rows);
    std::vector<float> fused_output(rows);
    
    // Run reference implementation
    auto ref_start = std::chrono::high_resolution_clock::now();
    ReferenceQ4_0_Gemv(q4_weights, input, reference_output.data(), rows, cols);
    auto ref_end = std::chrono::high_resolution_clock::now();
    
    // Run fused kernel
    auto fused_start = std::chrono::high_resolution_clock::now();
    fused_kernel(q4_weights, input, fused_output.data(), rows, cols);
    auto fused_end = std::chrono::high_resolution_clock::now();
    
    // Compare outputs
    KernelValidationResult result = CompareOutputs(
        reference_output.data(),
        fused_output.data(),
        rows,
        config
    );
    
    // Timing
    result.reference_time_ms = std::chrono::duration<double, std::milli>(ref_end - ref_start).count();
    result.fused_time_ms = std::chrono::duration<double, std::milli>(fused_end - fused_start).count();
    result.speedup = result.fused_time_ms > 0 ? 
        static_cast<float>(result.reference_time_ms / result.fused_time_ms) : 0.0f;
    
    result.rows_tested = rows;
    result.cols_tested = cols;
    
    return result;
}

KernelValidationResult ValidateFusedGemvRandom(
    FusedQ4_0_Gemv_Func fused_kernel,
    const GemvTestConfig& config
) {
    // Generate random test data
    uint8_t* weights = GenerateRandomQ4_0_Weights(config.rows, config.cols, config.random_seed);
    std::vector<float> input(config.cols);
    GenerateRandomVector(input.data(), config.cols, config.random_seed + 1);
    
    // Run validation
    KernelValidationResult result = ValidateFusedGemv(
        fused_kernel,
        weights,
        input.data(),
        config.rows,
        config.cols,
        config
    );
    
    // Cleanup
    delete[] weights;
    
    return result;
}

KernelValidationResult ValidateFusedGemvAgainstFile(
    FusedQ4_0_Gemv_Func fused_kernel,
    const std::string& gguf_path,
    const std::string& tensor_name,
    uint32_t token_id,
    const GemvTestConfig& config
) {
    // Initialize runtime
    auto runtime = CreateTensorRuntime();
    if (!runtime->Initialize(gguf_path)) {
        KernelValidationResult result = {};
        result.passed = false;
        return result;
    }
    
    // Get tensor
    if (!runtime->HasTensor(tensor_name)) {
        KernelValidationResult result = {};
        result.passed = false;
        return result;
    }
    
    TensorView tensor = runtime->GetTensor(tensor_name);
    
    // Read the row as weights
    size_t cols = tensor.dims[0];
    std::vector<float> weights(cols);
    if (!runtime->ReadRow(tensor, token_id, weights.data())) {
        KernelValidationResult result = {};
        result.passed = false;
        return result;
    }
    
    // For this test, we need to re-quantize to Q4_0 to test the fused kernel
    // This is a simplified version - in practice you'd use pre-quantized weights
    // For now, return a "not implemented" result
    
    KernelValidationResult result = {};
    result.passed = false; // Not yet implemented
    return result;
}

// ============================================================================
// Output Functions
// ============================================================================

void PrintValidationResult(const KernelValidationResult& result) {
    std::cout << "\n";
    std::cout << "L4.2.1 Fused Kernel Validation Result\n";
    std::cout << "=====================================\n";
    std::cout << "\n";
    
    std::cout << "Status: " << (result.passed ? "PASS ✓" : "FAIL ✗") << "\n";
    std::cout << "\n";
    
    std::cout << "Similarity Metrics:\n";
    std::cout << "  Cosine Similarity: " << std::fixed << std::setprecision(6) << result.cosine_similarity << "\n";
    std::cout << "  RMSE:              " << std::scientific << result.rmse << "\n";
    std::cout << "  Max Error:         " << result.max_error << "\n";
    std::cout << "  Mean Error:        " << result.mean_error << "\n";
    std::cout << "\n";
    
    std::cout << "Test Configuration:\n";
    std::cout << "  Elements Tested: " << result.elements_tested << "\n";
    std::cout << "  Rows: " << result.rows_tested << ", Cols: " << result.cols_tested << "\n";
    std::cout << "\n";
    
    if (!result.passed && result.first_mismatch_index < result.elements_tested) {
        std::cout << "First Mismatch:\n";
        std::cout << "  Index:    " << result.first_mismatch_index << "\n";
        std::cout << "  Expected: " << result.first_mismatch_expected << "\n";
        std::cout << "  Actual:   " << result.first_mismatch_actual << "\n";
        std::cout << "\n";
    }
    
    if (result.reference_time_ms > 0) {
        std::cout << "Performance:\n";
        std::cout << "  Reference Time: " << result.reference_time_ms << " ms\n";
        std::cout << "  Fused Time:     " << result.fused_time_ms << " ms\n";
        std::cout << "  Speedup:        " << result.speedup << "x\n";
        std::cout << "\n";
    }
}

bool IsValidationPassed(const KernelValidationResult& result) {
    return result.passed;
}

} // namespace L4
} // namespace RawrXD
