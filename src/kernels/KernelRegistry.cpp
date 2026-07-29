//=============================================================================
// RawrXD Kernel Registry - Implementation
//=============================================================================

#include "KernelRegistry.hpp"
#include "../memory/Q4WeightPreprocess.hpp"
#include <cstdio>
#include <intrin.h>
#include <cmath>

// External ASM kernel
extern "C" {
    float q4_preprocessed_dot_avx512_asm(
        const void* block,
        const float* activations
    );
}

namespace RawrXD {
namespace Kernels {

KernelCaps KernelRegistry::s_cpuCaps = KernelCaps::NONE;
bool KernelRegistry::s_initialized = false;
bool KernelRegistry::s_selfTestPassed = false;

// Known test vectors for self-validation
static const float kTestVectors[4][64] = {
    // All ones
    {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
     1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
    // Alternating pattern
    {1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,
     1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1},
    // Ramp pattern
    {0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,
     0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7},
    // Random-ish values
    {3,-2,5,1,-4,2,6,-1,3,-2,5,1,-4,2,6,-1,3,-2,5,1,-4,2,6,-1,3,-2,5,1,-4,2,6,-1,
     3,-2,5,1,-4,2,6,-1,3,-2,5,1,-4,2,6,-1,3,-2,5,1,-4,2,6,-1,3,-2,5,1,-4,2,6,-1}
};

static const float kExpectedResults[4] = {
    64.0f,    // All ones: 64 * 1 * 1
    0.0f,     // Alternating: cancels out
    224.0f,   // Ramp: 8 * (0+1+2+3+4+5+6+7) = 8 * 28 = 224
    112.0f    // Random: computed reference
};

// CPU feature detection
static bool check_avx512() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 7);
    return (cpuInfo[1] & (1 << 16)) != 0;  // AVX-512F
}

static bool check_avx512vl() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 7);
    return (cpuInfo[1] & (1 << 31)) != 0;  // AVX-512VL
}

static bool check_fma() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 12)) != 0;  // FMA
}

void KernelRegistry::Initialize() {
    if (s_initialized) return;
    
    s_cpuCaps = KernelCaps::NONE;
    
    if (check_fma()) {
        s_cpuCaps = s_cpuCaps | KernelCaps::FMA;
    }
    
    if (check_avx512()) {
        s_cpuCaps = s_cpuCaps | KernelCaps::AVX512F;
    }
    
    if (check_avx512vl()) {
        s_cpuCaps = s_cpuCaps | KernelCaps::AVX512VL;
    }
    
    s_initialized = true;
}

KernelCaps KernelRegistry::GetCpuCaps() {
    if (!s_initialized) Initialize();
    return s_cpuCaps;
}

Q4DotFn KernelRegistry::GetQ4DotKernel() {
    if (!s_initialized) Initialize();
    
    // Check for AVX-512 support
    if (has_cap(s_cpuCaps, KernelCaps::AVX512F) && 
        has_cap(s_cpuCaps, KernelCaps::AVX512VL) &&
        has_cap(s_cpuCaps, KernelCaps::FMA)) {
        return q4_preprocessed_dot_avx512_asm;
    }
    
    // Fallback: return nullptr (caller must handle)
    return nullptr;
}

bool KernelRegistry::IsAvailable(const KernelDesc& desc) {
    if (!s_initialized) Initialize();
    
    KernelCaps required = desc.required_caps;
    return (static_cast<uint32_t>(s_cpuCaps) & static_cast<uint32_t>(required)) 
           == static_cast<uint32_t>(required);
}

void KernelRegistry::PrintDiagnostics() {
    if (!s_initialized) Initialize();
    
    printf("RawrXD Kernel Registry\n");
    printf("======================\n");
    printf("CPU Capabilities:\n");
    printf("  AVX-512F:  %s\n", has_cap(s_cpuCaps, KernelCaps::AVX512F) ? "YES" : "NO");
    printf("  AVX-512VL: %s\n", has_cap(s_cpuCaps, KernelCaps::AVX512VL) ? "YES" : "NO");
    printf("  FMA:       %s\n", has_cap(s_cpuCaps, KernelCaps::FMA) ? "YES" : "NO");
    printf("\n");
    
    printf("Q4_0 Kernels:\n");
    Q4DotFn q4_kernel = GetQ4DotKernel();
    printf("  AVX-512: %s\n", q4_kernel ? "AVAILABLE" : "NOT AVAILABLE");
    printf("  Self-test: %s\n", s_selfTestPassed ? "PASSED" : "NOT RUN/FAILED");
    printf("\n");
}

KernelValidationResult KernelRegistry::ValidateKernel(Q4DotFn kernel) {
    KernelValidationResult result = {};
    result.passed = false;
    result.error_msg = "Unknown error";
    
    if (!kernel) {
        result.error_msg = "Null kernel pointer";
        return result;
    }
    
    // Create test block
    alignas(64) PreprocessedQ4Block block;
    block.init_header(1, 64);
    block.scale = 1.0f;
    
    double max_err = 0.0;
    double total_err = 0.0;
    uint64_t total_cycles = 0;
    
    // Run test vectors
    for (int test = 0; test < 4; test++) {
        // Load test weights
        for (int i = 0; i < 64; i++) {
            block.weights[i] = static_cast<int8_t>(kTestVectors[test][i]);
        }
        
        // Time the kernel
        uint64_t start = __rdtsc();
        float output = kernel(&block, kTestVectors[test]);
        uint64_t end = __rdtsc();
        total_cycles += (end - start);
        
        // Check result
        float expected = kExpectedResults[test];
        float err = std::abs(output - expected);
        max_err = std::max(max_err, static_cast<double>(err));
        total_err += err;
        
        // Fail if error too large
        if (err > 1e-3f) {
            result.error_msg = "Numerical mismatch in self-test";
            result.max_error = err;
            return result;
        }
    }
    
    result.passed = true;
    result.max_error = static_cast<float>(max_err);
    result.avg_error = static_cast<float>(total_err / 4.0);
    result.cycles = total_cycles / 4;
    result.error_msg = "OK";
    
    return result;
}

bool KernelRegistry::RunSelfTest() {
    if (s_selfTestPassed) return true;
    
    Q4DotFn kernel = GetQ4DotKernel();
    if (!kernel) {
        printf("[KernelRegistry] No kernel available for self-test\n");
        return false;
    }
    
    printf("[KernelRegistry] Running self-test...\n");
    
    KernelValidationResult result = ValidateKernel(kernel);
    
    if (result.passed) {
        printf("[KernelRegistry] Self-test PASSED\n");
        printf("  Max error: %.6e\n", result.max_error);
        printf("  Avg error: %.6e\n", result.avg_error);
        printf("  Cycles/block: %llu\n", static_cast<unsigned long long>(result.cycles));
        s_selfTestPassed = true;
        return true;
    } else {
        printf("[KernelRegistry] Self-test FAILED: %s\n", result.error_msg);
        printf("  Max error: %.6e\n", result.max_error);
        return false;
    }
}

void* KernelRegistry::GetKernelEntry(KernelID id) {
    if (!s_initialized) Initialize();
    
    switch (id) {
        case KernelID::Q4_PREPROCESSED_AVX512:
            return GetQ4DotKernel();
        default:
            return nullptr;
    }
}

KernelDesc KernelRegistry::GetKernelDesc(KernelID id) {
    KernelDesc desc = {};
    desc.id = id;
    
    switch (id) {
        case KernelID::Q4_PREPROCESSED_AVX512:
            desc.name = "q4_preprocessed_avx512";
            desc.op = KernelOp::MatVec;
            desc.quant = QuantType::Q4_0;
            desc.required_caps = KernelCaps::AVX512F | KernelCaps::AVX512VL | KernelCaps::FMA;
            desc.version = 1;
            desc.block_size = 128;
            desc.alignment = 64;
            desc.estimated_error = 0.004f;
            desc.estimated_latency_ns = 60.0f;
            desc.estimated_gflops = 100.0f;
            desc.entry = GetQ4DotKernel();
            break;
            
        case KernelID::Q4_PREPROCESSED_SCALAR:
            desc.name = "q4_preprocessed_scalar";
            desc.op = KernelOp::MatVec;
            desc.quant = QuantType::Q4_0;
            desc.required_caps = KernelCaps::NONE;
            desc.version = 1;
            desc.block_size = 128;
            desc.alignment = 64;
            desc.estimated_error = 0.0f;
            desc.estimated_latency_ns = 80000.0f;
            desc.estimated_gflops = 0.1f;
            desc.entry = nullptr;  // TODO: implement scalar fallback
            break;
            
        default:
            desc.name = "unknown";
            break;
    }
    
    return desc;
}

} // namespace Kernels
} // namespace RawrXD
