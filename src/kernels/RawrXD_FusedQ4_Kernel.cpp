//=============================================================================
// Fix #4: Fused Q4_0 Kernel Implementation
// RawrXD IDE - High-Performance Inference
//=============================================================================

#include "RawrXD_FusedQ4_Kernel.hpp"
#include <cstring>
#include <thread>
#include <vector>
#include <immintrin.h>

namespace RawrXD {
namespace Kernels {

// Static metrics storage
FusedQ4MatMul::Metrics FusedQ4MatMul::s_last_metrics = {};

//=============================================================================
// CPU Feature Detection
//=============================================================================
bool FusedQ4MatMul::IsAVX512Available() {
    int cpuInfo[4] = {0};
    
    // Check CPUID for AVX-512 Foundation (bit 16 of EBX in leaf 7)
    __cpuid(cpuInfo, 0);
    if (cpuInfo[0] >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        return (cpuInfo[1] & (1 << 16)) != 0;  // AVX-512F
    }
    return false;
}

//=============================================================================
// Prefetch Strategy
//=============================================================================
void FusedQ4MatMul::PrefetchWeights(const Q4_0Block* weights, int num_blocks) {
    const char* ptr = reinterpret_cast<const char*>(weights);
    size_t bytes = num_blocks * sizeof(Q4_0Block);
    
    // Prefetch in 64-byte cache line chunks
    for (size_t i = 0; i < bytes; i += 64) {
        _mm_prefetch(ptr + i, _MM_HINT_T1);  // L2 prefetch
    }
}

//=============================================================================
// Tiled Execution for Cache Efficiency
//=============================================================================
bool FusedQ4MatMul::ExecuteTiled(
    const float* A, const Q4_0Block* B, float* C,
    int M, int K, int N, int tile_M, int tile_N
) {
    // Calculate number of Q4_0 blocks per K dimension
    const int blocks_per_K = K / 32;  // 32 elements per Q4_0 block
    
    // Tile dimensions tuned for L2 cache (512KB per core)
    // Each tile should fit comfortably in L2
    if (tile_M <= 0) tile_M = 64;   // 64 rows
    if (tile_N <= 0) tile_N = 256;  // 256 columns (8 ZMM registers * 16 floats)
    
    // Zero output matrix
    std::memset(C, 0, M * N * sizeof(float));
    
    // Tiled execution
    for (int m0 = 0; m0 < M; m0 += tile_M) {
        int m_end = std::min(m0 + tile_M, M);
        
        for (int n0 = 0; n0 < N; n0 += tile_N) {
            int n_end = std::min(n0 + tile_N, N);
            int n_count = n_end - n0;
            
            // Prefetch weight tile into L2
            const Q4_0Block* B_tile = B + (n0 * blocks_per_K);
            PrefetchWeights(B_tile, blocks_per_K * (n_count / 32));
            
            // Process tile
            for (int m = m0; m < m_end; ++m) {
                const float* A_row = A + (m * K);
                float* C_row = C + (m * N) + n0;
                
                // Call assembly kernel for this row segment
                // Note: Assembly kernel handles 128 columns at a time
                for (int n = 0; n < n_count; n += 128) {
                    int n_seg = std::min(128, n_count - n);
                    const Q4_0Block* B_seg = B_tile + ((n0 + n) * blocks_per_K / 32);
                    
                    RawrXD_FusedQ4_0_MatMul_AVX512(
                        A_row,
                        B_seg,
                        C_row + n,
                        1,           // M=1 (single row)
                        K,           // Full K dimension
                        n_seg,       // Segment of N
                        K,           // lda
                        N            // ldc
                    );
                }
            }
        }
    }
    
    return true;
}

//=============================================================================
// Main Execute Function
//=============================================================================
bool FusedQ4MatMul::Execute(
    const float* activation,
    const Q4_0Block* weights,
    float* output,
    int M, int K, int N,
    const Config& config
) {
    if (!activation || !weights || !output) {
        return false;
    }
    
    if (M <= 0 || K <= 0 || N <= 0) {
        return false;
    }
    
    // K must be multiple of 32 (Q4_0 block size)
    if (K % 32 != 0) {
        return false;
    }
    
    // Check AVX-512 availability
    if (config.use_avx512 && !IsAVX512Available()) {
        return false;
    }
    
    // Use tiled execution for cache efficiency
    return ExecuteTiled(activation, weights, output, M, K, N, 64, 256);
}

//=============================================================================
// Optimized QKV Projection
//=============================================================================
bool FusedQ4MatMul::ExecuteQKVProjection(
    const float* query_input,
    const Q4_0Block* q_weights,
    const Q4_0Block* k_weights,
    const Q4_0Block* v_weights,
    float* q_output,
    float* k_output,
    float* v_output,
    int batch_size, int seq_len, int hidden_dim,
    const Config& config
) {
    const int M = batch_size * seq_len;
    const int K = hidden_dim;
    const int N = hidden_dim;
    
    // Validate dimensions
    if (hidden_dim % 32 != 0) {
        return false;
    }
    
    // Execute Q projection
    if (!Execute(query_input, q_weights, q_output, M, K, N, config)) {
        return false;
    }
    
    // Execute K projection
    if (!Execute(query_input, k_weights, k_output, M, K, N, config)) {
        return false;
    }
    
    // Execute V projection
    if (!Execute(query_input, v_weights, v_output, M, K, N, config)) {
        return false;
    }
    
    return true;
}

} // namespace Kernels
} // namespace RawrXD
