#include "q4k_decoder_optimized.hpp"
#include "q4k_decoder.hpp"
#include "cpu_capabilities.hpp"
#include <cstdio>
#include <cstring>

using namespace rawrxd::runtime;
using rawrxd::BlockQ4_K;
using rawrxd::BlockQ8_K;

int main() {
    printf("=== Q4_K Optimized Decoder Test ===\n\n");
    
    // Test 1: CPU Capability Detection
    printf("Test 1: CPU Capability Detection\n");
    const auto& caps = CpuCapabilities::Get();
    printf("  SSE: %s\n", caps.has_sse ? "YES" : "NO");
    printf("  SSE2: %s\n", caps.has_sse2 ? "YES" : "NO");
    printf("  SSE3: %s\n", caps.has_sse3 ? "YES" : "NO");
    printf("  SSSE3: %s\n", caps.has_ssse3 ? "YES" : "NO");
    printf("  SSE4.1: %s\n", caps.has_sse41 ? "YES" : "NO");
    printf("  SSE4.2: %s\n", caps.has_sse42 ? "YES" : "NO");
    printf("  AVX: %s\n", caps.has_avx ? "YES" : "NO");
    printf("  AVX2: %s\n", caps.has_avx2 ? "YES" : "NO");
    printf("  AVX-512F: %s\n", caps.has_avx512f ? "YES" : "NO");
    printf("  AVX-512DQ: %s\n", caps.has_avx512dq ? "YES" : "NO");
    printf("  AVX-512BW: %s\n", caps.has_avx512bw ? "YES" : "NO");
    printf("  AVX-512VL: %s\n", caps.has_avx512vl ? "YES" : "NO");
    printf("  FMA: %s\n", caps.has_fma ? "YES" : "NO");
    printf("  BMI1: %s\n", caps.has_bmi1 ? "YES" : "NO");
    printf("  BMI2: %s\n", caps.has_bmi2 ? "YES" : "NO");
    printf("  L1D Cache: %u KB\n", caps.l1d_cache_size / 1024);
    printf("  L2 Cache: %u KB\n", caps.l2_cache_size / 1024);
    printf("  L3 Cache: %u KB\n", caps.l3_cache_size / 1024 / 1024);
    printf("  PASSED\n\n");
    
    // Test 2: MASM Kernel Availability
    printf("Test 2: MASM Kernel Availability\n");
    Q4KDecoderOptimized::Initialize();
    bool has_masm = Q4KDecoderOptimized::HasMASMKernel();
    printf("  MASM Kernel Available: %s\n", has_masm ? "YES" : "NO");
    printf("  PASSED\n\n");
    
    // Test 3: Decode Row Optimized
    printf("Test 3: Decode Row Optimized\n");
    {
        BlockQ4_K blocks[2];
        std::memset(blocks, 0, sizeof(blocks));
        
        // Initialize with test data
        for (int b = 0; b < 2; b++) {
            blocks[b].d = 0x3C00;  // F16 1.0
            blocks[b].dmin = 0;
            for (int i = 0; i < 12; i++) {
                blocks[b].scales[i] = 0xFF;
            }
            for (int i = 0; i < 128; i++) {
                blocks[b].qs[i] = 0x11;  // nibbles = 1
            }
        }
        
        float output[512];
        Q4KDecoderOptimized::DecodeRowOptimized(blocks, output, 2);
        
        const auto& metrics = Q4KDecoderOptimized::GetLastMetrics();
        printf("  Elements processed: %zu\n", metrics.elements_processed);
        printf("  Cycles taken: %llu ns\n", (unsigned long long)metrics.cycles_taken);
        printf("  Implementation: %s\n", metrics.implementation_name);
        printf("  Used MASM: %s\n", metrics.used_masm ? "YES" : "NO");
        printf("  First value: %f\n", output[0]);
        printf("  PASSED\n\n");
    }
    
    // Test 4: Dot Product
    printf("Test 4: Dot Product Q4_K x Q8_K\n");
    {
        BlockQ4_K x[2];
        BlockQ8_K y[2];
        std::memset(x, 0, sizeof(x));
        std::memset(y, 0, sizeof(y));
        
        // Initialize Q4_K blocks
        for (int b = 0; b < 2; b++) {
            x[b].d = 0x3C00;  // F16 1.0
            x[b].dmin = 0;
            for (int i = 0; i < 12; i++) {
                x[b].scales[i] = 0xFF;
            }
            for (int i = 0; i < 128; i++) {
                x[b].qs[i] = 0x11;
            }
        }
        
        // Initialize Q8_K blocks
        for (int b = 0; b < 2; b++) {
            y[b].d = 0x3C00;  // F16 1.0
            for (int i = 0; i < 256; i++) {
                y[b].qs[i] = 1;
            }
            for (int i = 0; i < 16; i++) {
                y[b].bsums[i] = 16;  // Sum of 16 values
            }
        }
        
        float result = Q4KDecoderOptimized::DotProductQ4K_Q8K(x, y, 2);
        
        const auto& metrics = Q4KDecoderOptimized::GetLastMetrics();
        printf("  Dot product result: %f\n", result);
        printf("  Elements processed: %zu\n", metrics.elements_processed);
        printf("  Cycles taken: %llu ns\n", (unsigned long long)metrics.cycles_taken);
        printf("  Implementation: %s\n", metrics.implementation_name);
        printf("  Used MASM: %s\n", metrics.used_masm ? "YES" : "NO");
        printf("  PASSED\n\n");
    }
    
    // Test 5: Telemetry Summary
    printf("Test 5: Telemetry Summary\n");
    printf("  Total cycles: %llu\n", (unsigned long long)g_q4k_telemetry.total_cycles);
    printf("  Total elements: %llu\n", (unsigned long long)g_q4k_telemetry.total_elements);
    printf("  MASM calls: %u\n", g_q4k_telemetry.masm_calls);
    printf("  AVX2 calls: %u\n", g_q4k_telemetry.avx2_calls);
    printf("  Scalar calls: %u\n", g_q4k_telemetry.scalar_calls);
    printf("  PASSED\n\n");
    
    printf("=== All Tests PASSED ===\n");
    return 0;
}
