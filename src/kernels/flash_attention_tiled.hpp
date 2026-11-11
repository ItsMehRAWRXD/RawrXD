//=============================================================================
// Flash Attention - Tiled Implementation
// Memory-efficient attention with O(sqrt(N)) memory complexity
// Keeps intermediate results in L2/L3 cache, never materializes full N×N matrix
//=============================================================================
#pragma once

#include <immintrin.h>
#include <cstdint.h>
#include <cstddef.h>

namespace RawrXD {
namespace Kernels {

//=============================================================================
// Tile Configuration
// Sized to fit in L2/L3 cache for maximum throughput
//=============================================================================

struct TileConfig {
    // Query tile: processes this many queries at once
    // Sized to fit Q tile + O accumulator in L2 cache
    static constexpr int kQueryTileSize = 64;  // tokens
    
    // Key-Value tile: processes this many KV positions at once
    // Sized to fit K tile + V tile in L2 cache alongside Q tile
    static constexpr int kKVTileSize = 256;   // tokens
    
    // Head dimension tile (for large head_dim)
    static constexpr int kHeadTileSize = 64;    // features
    
    // Softmax online statistics
    struct OnlineSoftmaxState {
        float m;      // Running max
        float l;      // Running sum of exp(x - m)
        __m512 acc;   // Accumulated output (AVX-512 register)
    };
};

//=============================================================================
// Tiled Flash Attention Kernel
//=============================================================================

class FlashAttentionTiled {
public:
    // Main entry point
    // Q, K, V are in NHWC layout (interleaved)
    // Output is written to O in NHWC layout
    static void Compute(
        const float* __restrict Q,     // [seq_len, num_heads, head_dim]
        const float* __restrict K,     // [seq_len, num_heads, head_dim]
        const float* __restrict V,     // [seq_len, num_heads, head_dim]
        float* __restrict O,           // [seq_len, num_heads, head_dim]
        int batch_size,
        int seq_len,
        int num_heads,
        int head_dim,
        float softmax_scale            // 1/sqrt(head_dim)
    );
    
private:
    // Process a block of queries against a block of KV pairs
    static void ComputeTile(
        const float* __restrict Q_tile,
        const float* __restrict K_tile,
        const float* __restrict V_tile,
        float* __restrict O_tile,
        TileConfig::OnlineSoftmaxState& state,
        int q_tile_size,
        int kv_tile_size,
        int head_dim,
        float scale
    );
    
    // Online softmax update (numerically stable)
    static void UpdateOnlineSoftmax(
        TileConfig::OnlineSoftmaxState& state,
        float new_max,
        float new_sum_exp,
        const __m512& new_values
    );
    
    // Rescale accumulator when max changes
    static __m512 RescaleAccumulator(
        const __m512& acc,
        float old_m,
        float new_m,
        float old_l,
        float new_l
    );
};

//=============================================================================
// Memory-Efficient Attention (MFA) - Simplified API
// Drop-in replacement for standard attention
//=============================================================================

extern "C" void flash_attention_tiled_avx512(
    const float* Q,
    const float* K,
    const float* V,
    float* O,
    int batch_size,
    int seq_len,
    int num_heads,
    int head_dim
);

//=============================================================================
// Validation Helpers
//=============================================================================

class FlashAttentionValidator {
public:
    // Numerical accuracy check against reference implementation
    // Returns max absolute error
    static float ValidateAccuracy(
        const float* reference_output,
        const float* flash_output,
        int batch_size,
        int seq_len,
        int num_heads,
        int head_dim
    );
    
    // Performance comparison
    struct PerfResult {
        double time_ms;
        double memory_mb;
        double tps;
    };
    static PerfResult Benchmark(
        int batch_size,
        int seq_len,
        int num_heads,
        int head_dim
    );
    
    // Acceptable error threshold for FP32
    static constexpr float kAcceptableError = 1e-4f;
};

} // namespace Kernels
} // namespace RawrXD
