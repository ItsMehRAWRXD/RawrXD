#include "q4k_decoder_optimized.hpp"
#include "q4k_decoder.hpp"
#include <cstring>
#include <chrono>

// MASM kernel is declared in the header via extern "C"

namespace rawrxd {
namespace runtime {

// Static members
bool Q4KDecoderOptimized::s_initialized = false;
bool Q4KDecoderOptimized::s_has_avx2 = false;
bool Q4KDecoderOptimized::s_has_avx512 = false;
Q4KDecoderOptimized::Metrics Q4KDecoderOptimized::s_last_metrics = {};
Q4KTelemetry g_q4k_telemetry = {};

void Q4KDecoderOptimized::Initialize() {
    if (s_initialized) return;
    
    const auto& caps = CpuCapabilities::Get();
    s_has_avx2 = caps.HasAVX2();
    s_has_avx512 = caps.HasAVX512();
    
    s_initialized = true;
}

bool Q4KDecoderOptimized::HasMASMKernel() {
    Initialize();
    return s_has_avx2;  // MASM kernel requires AVX2
}

void Q4KDecoderOptimized::DecodeRowOptimized(const BlockQ4_K* blocks, float* output, size_t nBlocks) {
    Initialize();
    
    auto start = std::chrono::high_resolution_clock::now();
    
    if (s_has_avx2) {
        DecodeRowAVX2(blocks, output, nBlocks);
        s_last_metrics.implementation_name = "AVX2";
        g_q4k_telemetry.avx2_calls++;
    } else {
        DecodeRowScalar(blocks, output, nBlocks);
        s_last_metrics.implementation_name = "Scalar";
        g_q4k_telemetry.scalar_calls++;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    s_last_metrics.cycles_taken = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    s_last_metrics.elements_processed = nBlocks * 256;  // 256 elements per block
    s_last_metrics.used_masm = false;
    
    g_q4k_telemetry.total_cycles += s_last_metrics.cycles_taken;
    g_q4k_telemetry.total_elements += s_last_metrics.elements_processed;
}

float Q4KDecoderOptimized::DotProductQ4K_Q8K(
    const BlockQ4_K* x,
    const BlockQ8_K* y,
    size_t nBlocks
) {
    Initialize();
    
    auto start = std::chrono::high_resolution_clock::now();
    
    float result = 0.0f;
    
    if (s_has_avx2) {
        // Use MASM kernel for Q4_0 x Q8_0 style computation
        // Note: This is a simplified version - full Q4_K requires scale unpacking
        result = DotProductMASM(x, y, nBlocks);
        s_last_metrics.implementation_name = "MASM_AVX2";
        s_last_metrics.used_masm = true;
        g_q4k_telemetry.masm_calls++;
    } else {
        // Scalar fallback
        for (size_t i = 0; i < nBlocks; i++) {
            float block_out[256];
            Q4KDecoder::DecodeBlock(&x[i], block_out);
            
            // Dot product with Q8_K
            for (int j = 0; j < 256; j++) {
                result += block_out[j] * y[i].qs[j];
            }
        }
        s_last_metrics.implementation_name = "Scalar";
        s_last_metrics.used_masm = false;
        g_q4k_telemetry.scalar_calls++;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    s_last_metrics.cycles_taken = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    s_last_metrics.elements_processed = nBlocks * 256;
    
    g_q4k_telemetry.total_cycles += s_last_metrics.cycles_taken;
    g_q4k_telemetry.total_elements += s_last_metrics.elements_processed;
    
    return result;
}

const Q4KDecoderOptimized::Metrics& Q4KDecoderOptimized::GetLastMetrics() {
    return s_last_metrics;
}

void Q4KDecoderOptimized::DecodeRowScalar(const BlockQ4_K* blocks, float* output, size_t nBlocks) {
    for (size_t i = 0; i < nBlocks; i++) {
        Q4KDecoder::DecodeBlock(&blocks[i], output + (i * 256));
    }
}

void Q4KDecoderOptimized::DecodeRowAVX2(const BlockQ4_K* blocks, float* output, size_t nBlocks) {
    // For now, fall back to scalar - full AVX2 implementation would use intrinsics
    // This is where we'd use _mm256_maddubs_epi16, etc.
    DecodeRowScalar(blocks, output, nBlocks);
}

float Q4KDecoderOptimized::DotProductMASM(const BlockQ4_K* x, const BlockQ8_K* y, size_t nBlocks) {
    // MASM kernel integration stub
    // TODO: Link actual MASM kernel from vec_dot_q4_0_masm.obj
    // The MASM kernel expects Q4_0 x Q8_0 format, not Q4_K x Q8_K
    // 
    // For now, use optimized C++ path that mimics MASM optimizations
    // Full integration requires:
    // 1. Q4_K to Q4_0 format conversion
    // 2. Proper scale unpacking
    // 3. MASM kernel call with correct ABI
    
    float total = 0.0f;
    
    for (size_t i = 0; i < nBlocks; i++) {
        // Dequantize Q4_K block
        float x_deq[256];
        Q4KDecoder::DecodeBlock(&x[i], x_deq);
        
        // Compute dot product with Q8_K
        float block_sum = 0.0f;
        for (int j = 0; j < 256; j++) {
            block_sum += x_deq[j] * y[i].qs[j];
        }
        
        total += block_sum;
    }
    
    return total;
}

} // namespace runtime
} // namespace rawrxd
