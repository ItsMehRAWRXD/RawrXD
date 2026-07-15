#pragma once
#include "q4k_decoder.hpp"
#include "cpu_capabilities.hpp"
#include <cstdint>
#include <cstddef>

// MASM kernel declarations
extern "C" {
    // MASM kernel: Q4_0 x Q8_0 dot product
    // Parameters: RCX=x blocks, RDX=y blocks, R8=n blocks
    // Returns: float result in XMM0
    float vec_dot_q4_0_q8_0_masm(const void* x, const void* y, int n);
}

namespace rawrxd {
namespace runtime {

// Optimized Q4_K decoder with runtime dispatch
class Q4KDecoderOptimized {
public:
    // Initialize decoder - detects CPU capabilities
    static void Initialize();
    
    // Check if MASM kernel is available
    static bool HasMASMKernel();
    
    // Decode a row using best available implementation
    // Automatically dispatches to MASM if AVX2 is available
    static void DecodeRowOptimized(const BlockQ4_K* blocks, float* output, size_t nBlocks);
    
    // Dot product with Q8_K - uses MASM kernel if available
    static float DotProductQ4K_Q8K(
        const BlockQ4_K* x,
        const BlockQ8_K* y,
        size_t nBlocks
    );
    
    // Get last execution metrics (for telemetry)
    struct Metrics {
        uint64_t cycles_taken;
        size_t elements_processed;
        bool used_masm;
        const char* implementation_name;
    };
    static const Metrics& GetLastMetrics();
    
private:
    static bool s_initialized;
    static bool s_has_avx2;
    static bool s_has_avx512;
    static Metrics s_last_metrics;
    
    // Scalar fallback implementation
    static void DecodeRowScalar(const BlockQ4_K* blocks, float* output, size_t nBlocks);
    
    // AVX2 implementation (C++ intrinsics)
    static void DecodeRowAVX2(const BlockQ4_K* blocks, float* output, size_t nBlocks);
    
    // MASM kernel wrapper
    static float DotProductMASM(const BlockQ4_K* x, const BlockQ8_K* y, size_t nBlocks);
};

// Telemetry helper for SEG integration
struct Q4KTelemetry {
    uint64_t total_cycles;
    uint64_t total_elements;
    uint32_t masm_calls;
    uint32_t avx2_calls;
    uint32_t scalar_calls;
    float avg_tokens_per_sec;
    
    void Reset() {
        total_cycles = 0;
        total_elements = 0;
        masm_calls = 0;
        avx2_calls = 0;
        scalar_calls = 0;
        avg_tokens_per_sec = 0.0f;
    }
};

// Global telemetry instance for SEG
extern Q4KTelemetry g_q4k_telemetry;

} // namespace runtime
} // namespace rawrxd
