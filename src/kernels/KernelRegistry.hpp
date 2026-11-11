//=============================================================================
// RawrXD Kernel Registry
// Central dispatch for optimized compute kernels
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Kernels {

// Kernel capability flags
enum class KernelCaps : uint32_t {
    NONE        = 0,
    AVX512F     = 1 << 0,
    AVX512VL    = 1 << 1,
    AVX512DQ    = 1 << 2,
    AVX512BW    = 1 << 3,
    FMA         = 1 << 4,
    AMX         = 1 << 5,
    BF16        = 1 << 6,
};

inline KernelCaps operator|(KernelCaps a, KernelCaps b) {
    return static_cast<KernelCaps>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline bool has_cap(KernelCaps caps, KernelCaps flag) {
    return (static_cast<uint32_t>(caps) & static_cast<uint32_t>(flag)) != 0;
}

// Quantization types
enum class QuantType : uint32_t {
    F32,
    F16,
    BF16,
    Q8_0,
    Q8_1,
    Q4_0,
    Q4_1,
    Q5_0,
    Q5_1,
    Q6_K,
    Q8_K,
};

// Kernel operation types
enum class KernelOp : uint32_t {
    MatMul,
    MatVec,
    Dequant,
    Softmax,
    RoPE,
    RMSNorm,
};

// Kernel ID for fast lookup
enum class KernelID : uint32_t {
    INVALID = 0,
    
    // Q4 kernels
    Q4_PREPROCESSED_AVX512 = 1,
    Q4_PREPROCESSED_AVX2 = 2,
    Q4_PREPROCESSED_SCALAR = 3,
    
    // Q8 kernels
    Q8_AVX512 = 10,
    Q8_AVX2 = 11,
    Q8_SCALAR = 12,
    
    // FP16 kernels
    FP16_AVX512 = 20,
    FP16_AVX2 = 21,
    
    // FP32 kernels
    FP32_AVX512 = 30,
    FP32_AVX2 = 31,
    FP32_SCALAR = 32,
    
    // GPU kernels
    Q4_CUDA = 100,
    Q4_VULKAN = 101,
    
    MAX_KERNEL_ID
};

// Kernel descriptor with telemetry
struct KernelDesc {
    KernelID id;
    const char* name;
    KernelOp op;
    QuantType quant;
    KernelCaps required_caps;
    uint32_t version;           // ABI version
    uint32_t block_size;        // Block size in bytes
    uint32_t alignment;         // Required alignment
    float estimated_error;      // Expected numerical error
    float estimated_latency_ns; // Estimated latency per block
    float estimated_gflops;     // Estimated compute throughput
    void* entry;                // Function pointer
};

// Self-test result
struct KernelValidationResult {
    bool passed;
    float max_error;
    float avg_error;
    uint64_t cycles;
    const char* error_msg;
};

// Q4_0 kernel function types
typedef float (*Q4DotFn)(
    const void* block,      // PreprocessedQ4Block* or GGUF block
    const float* activations
);

// Kernel registry interface
class KernelRegistry {
public:
    // Initialize registry and detect CPU capabilities
    static void Initialize();
    
    // Get best kernel for operation
    static Q4DotFn GetQ4DotKernel();
    
    // Check if specific kernel is available
    static bool IsAvailable(const KernelDesc& desc);
    
    // Get current CPU capabilities
    static KernelCaps GetCpuCaps();
    
    // Print kernel selection info
    static void PrintDiagnostics();
    
    // Runtime self-test for kernel validation
    static KernelValidationResult ValidateKernel(Q4DotFn kernel);
    static bool RunSelfTest();
    
    // Kernel lookup by ID
    static void* GetKernelEntry(KernelID id);
    static KernelDesc GetKernelDesc(KernelID id);

private:
    static KernelCaps s_cpuCaps;
    static bool s_initialized;
    static bool s_selfTestPassed;
    
    static void InitKernelTable();
};

} // namespace Kernels
} // namespace RawrXD
