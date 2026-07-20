// ============================================================================
// KernelDispatcher.hpp - Runtime Kernel Selection and Dispatch
// Routes inference operations to optimal implementation based on:
//   - Weight quantization type (Q4_K_M, Q4_0, FP16, FP32)
//   - CPU features (AVX2, AVX512, AVX512-VNNI)
//   - Problem size (rows, cols)
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace Deep2 {

// Forward declarations
class Deep2Engine;

// Weight types matching GGML enum
typedef int WeightType;
constexpr WeightType WEIGHT_FP32   = 0;
constexpr WeightType WEIGHT_FP16   = 1;
constexpr WeightType WEIGHT_Q4_0   = 2;
constexpr WeightType WEIGHT_Q4_1   = 3;
constexpr WeightType WEIGHT_Q5_0   = 6;
constexpr WeightType WEIGHT_Q5_1   = 7;
constexpr WeightType WEIGHT_Q8_0   = 8;
constexpr WeightType WEIGHT_Q8_K   = 9;
constexpr WeightType WEIGHT_Q2_K  = 10;
constexpr WeightType WEIGHT_Q3_K  = 11;
constexpr WeightType WEIGHT_Q4_K  = 12;  // Q4_K_M
constexpr WeightType WEIGHT_Q5_K  = 13;
constexpr WeightType WEIGHT_Q6_K  = 14;

// Kernel implementation types
enum class KernelType {
    Q4_K_M_GEMV_AVX2,       // MASM AVX2 with on-the-fly dequant
    Q4_K_M_GEMV_AVX512,     // AVX512 optimized path
    Q4_0_GEMV_AVX2,         // Legacy Q4_0
    FP16_GEMV_AVX2,         // FP16 weights
    FP32_GEMV_AVX2,         // Standard FP32
    FP32_GEMV_SCALAR,       // Fallback
    UNKNOWN
};

// CPU feature flags
struct CPUFeatures {
    bool hasAVX    = false;
    bool hasAVX2   = false;
    bool hasAVX512 = false;
    bool hasFMA    = false;
    bool hasVNNI   = false;
    
    static CPUFeatures Detect();
    void Print() const;
};

// Kernel dispatch record - tracks what was selected
struct DispatchRecord {
    KernelType kernel;
    WeightType weightType;
    size_t rows;
    size_t cols;
    double executionTimeMs;
    double bandwidthGBps;
};

// ============================================================================
// KernelDispatcher - Central routing for all GEMV operations
// ============================================================================
class KernelDispatcher {
public:
    // Initialize with detected CPU features
    static void Initialize();
    
    // Check if initialized
    static bool IsInitialized() { return initialized; }
    
    // Select optimal kernel for given weight type and dimensions
    static KernelType Select(WeightType type, size_t rows, size_t cols);
    
    // Execute linear layer with automatic dispatch
    // Returns execution time in milliseconds
    static double ExecuteLinear(
        int weightIdx,           // Registered weight tensor
        const float* input,      // Input vector
        const float* bias,       // Optional bias
        float* output,           // Output vector
        size_t outDim,           // Output dimension
        bool useParallel,        // Use ThreadPool
        Deep2Engine* engine      // Engine instance
    );
    
    // Get last dispatch record for profiling
    static const DispatchRecord& GetLastDispatch() { return lastDispatch; }
    
    // Get CPU features
    static const CPUFeatures& GetCPUFeatures() { return cpuFeatures; }
    
    // Check if specific kernel is available
    static bool IsKernelAvailable(KernelType kernel);

private:
    static bool initialized;
    static CPUFeatures cpuFeatures;
    static DispatchRecord lastDispatch;
    
    // Internal dispatch implementations
    static double DispatchQ4_K_M_AVX2(
        int weightIdx, const float* input, const float* bias,
        float* output, size_t outDim, Deep2Engine* engine
    );
    
    static double DispatchFP32_AVX2(
        int weightIdx, const float* input, const float* bias,
        float* output, size_t outDim, Deep2Engine* engine
    );
    
    static double DispatchFP32_Scalar(
        int weightIdx, const float* input, const float* bias,
        float* output, size_t outDim
    );
};

// ============================================================================
// Convenience macros for transformer layer integration
// ============================================================================

// Execute linear with automatic kernel selection
#define DEEP2_LINEAR(weightIdx, input, bias, output, outDim, engine) \
    Deep2::KernelDispatcher::ExecuteLinear(weightIdx, input, bias, output, outDim, false, engine)

// Execute linear with parallelization
#define DEEP2_LINEAR_PARALLEL(weightIdx, input, bias, output, outDim, engine) \
    Deep2::KernelDispatcher::ExecuteLinear(weightIdx, input, bias, output, outDim, true, engine)

// Get kernel type name as string
const char* KernelTypeToString(KernelType type);
const char* WeightTypeToString(WeightType type);

} // namespace Deep2
