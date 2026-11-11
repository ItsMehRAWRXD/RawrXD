/**
 * @file fused_quant_gemm.h
 * @brief RawrXD L4.2.2 Fused Quant GEMM - High Performance Path
 *
 * Decodes compressed weights directly into SIMD FMA accumulators.
 * No intermediate FP32 buffer. Maximum memory bandwidth efficiency.
 *
 * Data Flow:
 *   Q4 Block
 *      |
 *      +--> Read scale (FP16)
 *      +--> Unpack nibbles
 *      +--> Dequantize to AVX2 registers
 *      +--> FMA with activation
 *      |
 *      v
 *   Output (direct)
 *
 * @copyright RawrXD 2026
 */

#ifndef RAWRXD_FUSED_QUANT_GEMM_H
#define RAWRXD_FUSED_QUANT_GEMM_H

#include <cstdint>
#include <cstddef>
#include <immintrin.h>
#include "compression_codec.h"

namespace rawrxd {
namespace kernels {

// ============================================================================
// Fused Kernel Configuration
// ============================================================================

struct FusedKernelConfig {
    // SIMD width
    static constexpr size_t AVX2_FLOATS = 8;      // 256-bit / 32-bit
    static constexpr size_t AVX512_FLOATS = 16;   // 512-bit / 32-bit
    
    // Cache-friendly parameters
    static constexpr size_t L1_CACHE_SIZE = 32 * 1024;    // 32 KB
    static constexpr size_t L2_CACHE_SIZE = 256 * 1024;   // 256 KB
    static constexpr size_t L3_CACHE_SIZE = 8 * 1024 * 1024; // 8 MB
    
    // Blocking parameters
    size_t mr = 8;   // Rows per block
    size_t nr = 32;  // Cols per block
    size_t kr = 256; // K dimension block
    
    // Prefetch distance
    size_t prefetch_distance = 512; // bytes ahead
};

// ============================================================================
// Fused Quant GEMV Interface
// ============================================================================

class FusedQuantGemm {
public:
    FusedQuantGemm();
    ~FusedQuantGemm() = default;
    
    // ------------------------------------------------------------------------
    // Q4_0 Fused Kernels
    // ------------------------------------------------------------------------
    
    /**
     * @brief Fused Q4_0 decode + GEMV (scalar fallback)
     * 
     * @param weights Compressed Q4_0 weights
     * @param input Input activation vector
     * @param output Output vector
     * @param rows Number of output rows
     * @param cols Number of input columns (must be multiple of 32)
     */
    static void GemvQ4_0_Scalar(
        const uint8_t* weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
    
    /**
     * @brief Fused Q4_0 decode + GEMV (AVX2 optimized)
     * 
     * Processes 8 weights at a time using AVX2 intrinsics.
     * No temporary buffer. Direct decode to FMA.
     */
    static void GemvQ4_0_AVX2(
        const uint8_t* weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
    
    /**
     * @brief Fused Q4_0 decode + GEMV (AVX-512 optimized)
     * 
     * Processes 16 weights at a time using AVX-512 intrinsics.
     */
    static void GemvQ4_0_AVX512(
        const uint8_t* weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
    
    // ------------------------------------------------------------------------
    // Q4_K Fused Kernels
    // ------------------------------------------------------------------------
    
    /**
     * @brief Fused Q4_K decode + GEMV (AVX2)
     * 
     * Handles mixed 6-bit scales + 4-bit weights.
     */
    static void GemvQ4_K_AVX2(
        const uint8_t* weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
    
    // ------------------------------------------------------------------------
    // Q8_0 Fused Kernels
    // ------------------------------------------------------------------------
    
    /**
     * @brief Fused Q8_0 decode + GEMV (AVX2)
     * 
     * Higher precision, less compression.
     */
    static void GemvQ8_0_AVX2(
        const uint8_t* weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
    
    // ------------------------------------------------------------------------
    // Auto-Dispatch
    // ------------------------------------------------------------------------
    
    /**
     * @brief Auto-select best implementation based on CPU features
     */
    static void GemvAuto(
        compression::CompressionType type,
        const uint8_t* weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
    
    // ------------------------------------------------------------------------
    // Multi-threaded Variants
    // ------------------------------------------------------------------------
    
    /**
     * @brief Multi-threaded fused GEMV
     * 
     * @param num_threads Number of worker threads
     */
    static void GemvMT(
        compression::CompressionType type,
        const uint8_t* weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols,
        int num_threads
    );
    
    // ------------------------------------------------------------------------
    // Validation & Benchmarking
    // ------------------------------------------------------------------------
    
    /**
     * @brief Validate fused kernel produces correct output
     */
    static bool ValidateKernel(
        compression::CompressionType type,
        const float* weights_fp32,
        const float* input,
        float* output,
        size_t rows,
        size_t cols,
        float tolerance = 0.01f
    );
    
    /**
     * @brief Benchmark fused vs separate decode+GEMM
     */
    struct BenchmarkResult {
        double fused_time_ms;
        double separate_time_ms;
        double speedup;
        size_t memory_saved_bytes;
        float max_error;
    };
    
    static BenchmarkResult Benchmark(
        compression::CompressionType type,
        size_t rows,
        size_t cols,
        int iterations = 100
    );
    
    // ------------------------------------------------------------------------
    // CPU Feature Detection
    // ------------------------------------------------------------------------
    
    struct CPUFeatures {
        bool has_avx2;
        bool has_avx512f;
        bool has_fma;
        bool has_vnni;
        
        void Detect();
        void Print() const;
    };
    
    static CPUFeatures GetCPUFeatures();
    
private:
    // Internal dispatch
    using GemvFunc = void(*)(const uint8_t*, const float*, float*, size_t, size_t);
    static GemvFunc SelectKernel(compression::CompressionType type);
};

// ============================================================================
// Low-Level Intrinsics Wrappers
// ============================================================================

namespace intrinsics {

// Q4_0 block structure: FP16 scale + 16 bytes nibbles (32 weights)
struct Q4_0_Block {
    uint16_t scale;      // FP16 scale
    uint8_t nibbles[16]; // 32 x 4-bit weights
};

/**
 * @brief Decode Q4_0 block to AVX2 register
 * 
 * Loads scale, unpacks nibbles, dequantizes to 8 floats in AVX2 register.
 */
inline __m256 DecodeQ4_0_Block_AVX2(const uint8_t* block_data, size_t nibble_idx);

/**
 * @brief Fused decode + FMA for Q4_0
 * 
 * Accumulates: output += dequantized_weight * input
 */
inline __m256 FusedQ4_0_FMA_AVX2(
    __m256 accumulator,
    const uint8_t* block_data,
    size_t nibble_idx,
    __m256 input_vec
);

/**
 * @brief Horizontal sum of AVX2 register
 */
inline float HorizontalSum_AVX2(__m256 vec);

/**
 * @brief Prefetch hint for next block
 */
inline void PrefetchNextBlock(const uint8_t* addr);

} // namespace intrinsics

// ============================================================================
// Performance Counters
// ============================================================================

struct FusedKernelMetrics {
    uint64_t blocks_processed;
    uint64_t weights_decoded;
    uint64_t fma_operations;
    double memory_bandwidth_gbps;
    double compute_gflops;
    double efficiency_percent;  // vs theoretical peak
    
    void Reset();
    void Print() const;
};

// Global metrics instance (thread-safe access required)
extern FusedKernelMetrics g_fused_metrics;

// ============================================================================
// Convenience Macros
// ============================================================================

#define RAWRXD_FUSED_GEMV_Q4_0_AVX2(weights, input, output, rows, cols) \
    rawrxd::kernels::FusedQuantGemm::GemvQ4_0_AVX2( \
        weights, input, output, rows, cols)

#define RAWRXD_FUSED_GEMV_AUTO(type, weights, input, output, rows, cols) \
    rawrxd::kernels::FusedQuantGemm::GemvAuto( \
        type, weights, input, output, rows, cols)

} // namespace kernels
} // namespace rawrxd

#endif // RAWRXD_FUSED_QUANT_GEMM_H
