/**=============================================================================
 * RawrXD_FusedQuantizedKernels.hpp
 * Fused Dequantize + GEMM Kernels for Q4_0 and Q8_0
 * 
 * Eliminates separate dequantization pass by fusing it into the GEMM kernel.
 * Reduces memory bandwidth by ~4x for Q4_0 and ~2x for Q8_0.
 * 
 * Reference: llama.cpp GGML Q4_0/Q8_0 compute graph optimizations
 *=============================================================================*/

#ifndef RAWRXD_FUSED_QUANTIZED_KERNELS_HPP
#define RAWRXD_FUSED_QUANTIZED_KERNELS_HPP

#include <cstdint>
#include <cstddef>
#include <immintrin.h>
#include <math.h>
#include <algorithm>

namespace RawrXD {
namespace Kernels {

/**=============================================================================
 * Quantized Block Structures
 *=============================================================================*/

// Q4_0 block: 32 4-bit weights packed into 16 bytes + 2-byte scale
struct alignas(32) BlockQ4_0 {
    static constexpr int BLOCK_SIZE = 32;
    
    uint16_t scale;      // FP16 scale
    uint8_t qs[16];      // 4-bit weights packed (32 weights)
    
    // Dequantize single element
    inline float Dequantize(int idx) const {
        // Extract 4-bit value
        uint8_t byte = qs[idx / 2];
        uint8_t nibble = (idx % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
        
        // Convert to signed and scale
        int8_t signed_val = (int8_t)(nibble | ((nibble & 0x08) ? 0xF0 : 0x00));
        float scale_f = (float)scale / 256.0f;  // Simple FP16 to FP32
        return (float)signed_val * scale_f;
    }
};

// Q8_0 block: 32 8-bit weights + 2-byte scale
struct alignas(32) BlockQ8_0 {
    static constexpr int BLOCK_SIZE = 32;
    
    uint16_t scale;      // FP16 scale
    int8_t qs[32];       // 8-bit weights
    
    // Dequantize single element
    inline float Dequantize(int idx) const {
        float scale_f = (float)scale / 256.0f;
        return (float)qs[idx] * scale_f;
    }
};

/**=============================================================================
 * Fused Quantized GEMM - Scalar Implementation
 * 
 * Computes: C = A @ B^T where B is quantized
 * Fuses dequantization into the GEMM loop
 *=============================================================================*/
class FusedQuantizedGEMM {
public:
    /**=========================================================================
     * GEMM with Q4_0 weights
     * 
     * @param A Input matrix [M, K] (float32)
     * @param B Quantized weight matrix [N, K] in Q4_0 blocks
     * @param C Output matrix [M, N]
     * @param M Batch size / number of rows
     * @param N Number of output channels
     * @param K Input channels (must be multiple of 32)
     *=========================================================================*/
    static void GemmQ4_0(
        const float* __restrict A,
        const BlockQ4_0* __restrict B,
        float* __restrict C,
        int M, int N, int K
    ) {
        const int blocks_per_row = K / BlockQ4_0::BLOCK_SIZE;
        
        for (int m = 0; m < M; ++m) {
            for (int n = 0; n < N; ++n) {
                float sum = 0.0f;
                
                // Process each block
                for (int bk = 0; bk < blocks_per_row; ++bk) {
                    const BlockQ4_0* block = &B[(size_t)n * blocks_per_row + bk];
                    
                    // Dequantize and accumulate on-the-fly
                    for (int i = 0; i < BlockQ4_0::BLOCK_SIZE; ++i) {
                        int k_idx = bk * BlockQ4_0::BLOCK_SIZE + i;
                        float w_deq = block->Dequantize(i);
                        sum += A[m * K + k_idx] * w_deq;
                    }
                }
                
                C[m * N + n] = sum;
            }
        }
    }
    
    /**=========================================================================
     * GEMM with Q8_0 weights
     *=========================================================================*/
    static void GemmQ8_0(
        const float* __restrict A,
        const BlockQ8_0* __restrict B,
        float* __restrict C,
        int M, int N, int K
    ) {
        const int blocks_per_row = K / BlockQ8_0::BLOCK_SIZE;
        
        for (int m = 0; m < M; ++m) {
            for (int n = 0; n < N; ++n) {
                float sum = 0.0f;
                
                for (int bk = 0; bk < blocks_per_row; ++bk) {
                    const BlockQ8_0* block = &B[(size_t)n * blocks_per_row + bk];
                    
                    for (int i = 0; i < BlockQ8_0::BLOCK_SIZE; ++i) {
                        int k_idx = bk * BlockQ8_0::BLOCK_SIZE + i;
                        float w_deq = block->Dequantize(i);
                        sum += A[m * K + k_idx] * w_deq;
                    }
                }
                
                C[m * N + n] = sum;
            }
        }
    }
    
    /**=========================================================================
     * Optimized GEMM with accumulation in registers
     * Reduces memory traffic by keeping accumulator in registers
     *=========================================================================*/
    static void GemmQ4_0_Optimized(
        const float* __restrict A,
        const BlockQ4_0* __restrict B,
        float* __restrict C,
        int M, int N, int K
    ) {
        const int blocks_per_row = K / BlockQ4_0::BLOCK_SIZE;
        
        for (int m = 0; m < M; ++m) {
            for (int n = 0; n < N; ++n) {
                // Accumulator in register
                register float acc = 0.0f;
                
                for (int bk = 0; bk < blocks_per_row; ++bk) {
                    const BlockQ4_0* block = &B[(size_t)n * blocks_per_row + bk];
                    const float* a_ptr = A + m * K + bk * BlockQ4_0::BLOCK_SIZE;
                    
                    // Unroll by 8 for better instruction-level parallelism
                    #pragma unroll 8
                    for (int i = 0; i < BlockQ4_0::BLOCK_SIZE; ++i) {
                        float w_deq = block->Dequantize(i);
                        acc += a_ptr[i] * w_deq;
                    }
                }
                
                C[m * N + n] = acc;
            }
        }
    }
    
    /**=========================================================================
     * Batch GEMM for transformer layers
     * Processes multiple heads in parallel
     *=========================================================================*/
    static void BatchGemmQ4_0(
        const float* __restrict A,      // [batch, M, K]
        const BlockQ4_0* __restrict B,  // [batch, N, K/32] (quantized)
        float* __restrict C,            // [batch, M, N]
        int batch_size,
        int M, int N, int K
    ) {
        for (int b = 0; b < batch_size; ++b) {
            const float* A_batch = A + (size_t)b * M * K;
            const BlockQ4_0* B_batch = B + (size_t)b * N * (K / BlockQ4_0::BLOCK_SIZE);
            float* C_batch = C + (size_t)b * M * N;
            
            GemmQ4_0(A_batch, B_batch, C_batch, M, N, K);
        }
    }
};

/**=============================================================================
 * Two-Pass vs Fused Comparison
 * Shows the benefit of fusing dequantization into GEMM
 *=============================================================================*/
class QuantizedGEMMComparison {
public:
    /**=========================================================================
     * Two-pass approach: Dequantize first, then GEMM
     * Memory traffic: Read Q4_0 (18 bytes per 32 weights) + Write FP32 (128 bytes)
     *                 + Read FP32 (128 bytes) for GEMM
     * Total: 274 bytes per 32 weights
     *=========================================================================*/
    static void TwoPassQ4_0(
        const float* __restrict A,
        const BlockQ4_0* __restrict B_quantized,
        float* __restrict C,
        int M, int N, int K,
        float* __restrict B_dequantized_buffer
    ) {
        const int blocks_per_row = K / BlockQ4_0::BLOCK_SIZE;
        
        // Pass 1: Dequantize B
        for (int n = 0; n < N; ++n) {
            for (int bk = 0; bk < blocks_per_row; ++bk) {
                const BlockQ4_0* block = &B_quantized[(size_t)n * blocks_per_row + bk];
                float* deq_ptr = B_dequantized_buffer + (size_t)n * K + bk * BlockQ4_0::BLOCK_SIZE;
                
                for (int i = 0; i < BlockQ4_0::BLOCK_SIZE; ++i) {
                    deq_ptr[i] = block->Dequantize(i);
                }
            }
        }
        
        // Pass 2: Standard GEMM
        for (int m = 0; m < M; ++m) {
            for (int n = 0; n < N; ++n) {
                float sum = 0.0f;
                for (int k = 0; k < K; ++k) {
                    sum += A[m * K + k] * B_dequantized_buffer[n * K + k];
                }
                C[m * N + n] = sum;
            }
        }
    }
    
    /**=========================================================================
     * Fused approach: Dequantize on-the-fly during GEMM
     * Memory traffic: Read Q4_0 (18 bytes per 32 weights) only
     * Total: 18 bytes per 32 weights
     * 
     * Bandwidth reduction: 274/18 = 15.2x theoretical
     *=========================================================================*/
    static void FusedQ4_0(
        const float* __restrict A,
        const BlockQ4_0* __restrict B_quantized,
        float* __restrict C,
        int M, int N, int K
    ) {
        FusedQuantizedGEMM::GemmQ4_0(A, B_quantized, C, M, N, K);
    }
};

/**=============================================================================
 * Quantized KV-Cache for Efficient Inference
 * Stores KV cache in Q8_0 format to reduce memory footprint
 *=============================================================================*/
class QuantizedKVCache {
public:
    /**=========================================================================
     * Initialize quantized KV cache
     * @param max_seq_len Maximum sequence length
     * @param num_heads Number of attention heads
     * @param head_dim Head dimension (must be multiple of 32)
     *=========================================================================*/
    QuantizedKVCache(int max_seq_len, int num_heads, int head_dim)
        : max_seq_len_(max_seq_len),
          num_heads_(num_heads),
          head_dim_(head_dim),
          current_len_(0) {
        
        int blocks_per_head = head_dim / BlockQ8_0::BLOCK_SIZE;
        size_t cache_size = (size_t)max_seq_len * num_heads * blocks_per_head;
        
        k_cache_ = new BlockQ8_0[cache_size];
        v_cache_ = new BlockQ8_0[cache_size];
        
        // Initialize to zero
        std::memset(k_cache_, 0, cache_size * sizeof(BlockQ8_0));
        std::memset(v_cache_, 0, cache_size * sizeof(BlockQ8_0));
    }
    
    ~QuantizedKVCache() {
        delete[] k_cache_;
        delete[] v_cache_;
    }
    
    /**=========================================================================
     * Append new K and V values to cache
     * Quantizes from FP32 to Q8_0
     *=========================================================================*/
    void Append(const float* __restrict k_new, const float* __restrict v_new) {
        if (current_len_ >= max_seq_len_) return;
        
        int blocks_per_head = head_dim_ / BlockQ8_0::BLOCK_SIZE;
        
        for (int h = 0; h < num_heads_; ++h) {
            for (int bk = 0; bk < blocks_per_head; ++bk) {
                // Quantize K
                BlockQ8_0* k_block = &k_cache_[((size_t)current_len_ * num_heads_ + h) * blocks_per_head + bk];
                QuantizeBlockQ8_0(k_new + h * head_dim_ + bk * BlockQ8_0::BLOCK_SIZE, k_block);
                
                // Quantize V
                BlockQ8_0* v_block = &v_cache_[((size_t)current_len_ * num_heads_ + h) * blocks_per_head + bk];
                QuantizeBlockQ8_0(v_new + h * head_dim_ + bk * BlockQ8_0::BLOCK_SIZE, v_block);
            }
        }
        
        current_len_++;
    }
    
    /**=========================================================================
     * Get K cache pointer for attention computation
     *=========================================================================*/
    const BlockQ8_0* GetKCache() const { return k_cache_; }
    const BlockQ8_0* GetVCache() const { return v_cache_; }
    
    int GetCurrentLength() const { return current_len_; }
    int GetMaxLength() const { return max_seq_len_; }
    
    /**=========================================================================
     * Memory usage comparison
     *=========================================================================*/
    static size_t GetMemoryUsageFP32(int max_seq_len, int num_heads, int head_dim) {
        return (size_t)max_seq_len * num_heads * head_dim * sizeof(float) * 2;  // K + V
    }
    
    static size_t GetMemoryUsageQ8_0(int max_seq_len, int num_heads, int head_dim) {
        int blocks_per_head = head_dim / BlockQ8_0::BLOCK_SIZE;
        size_t blocks_total = (size_t)max_seq_len * num_heads * blocks_per_head * 2;  // K + V
        return blocks_total * sizeof(BlockQ8_0);
    }

private:
    void QuantizeBlockQ8_0(const float* __restrict src, BlockQ8_0* __restrict dst) {
        // Find max absolute value for scaling
        float max_abs = 0.0f;
        for (int i = 0; i < BlockQ8_0::BLOCK_SIZE; ++i) {
            max_abs = std::max(max_abs, std::abs(src[i]));
        }
        
        // Compute scale (FP16)
        float scale = max_abs / 127.0f;
        if (scale == 0.0f) scale = 1.0f;
        dst->scale = (uint16_t)(scale * 256.0f);  // Simplified FP16
        
        // Quantize values
        for (int i = 0; i < BlockQ8_0::BLOCK_SIZE; ++i) {
            float quantized = src[i] / scale;
            quantized = std::max(-128.0f, std::min(127.0f, quantized));
            dst->qs[i] = (int8_t)std::round(quantized);
        }
    }
    
    int max_seq_len_;
    int num_heads_;
    int head_dim_;
    int current_len_;
    
    BlockQ8_0* k_cache_;
    BlockQ8_0* v_cache_;
};

} // namespace Kernels
} // namespace RawrXD

#endif // RAWRXD_FUSED_QUANTIZED_KERNELS_HPP
