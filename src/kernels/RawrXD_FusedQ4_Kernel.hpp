//=============================================================================
// Fix #4: Fused Q4_0 Kernel Interface
// RawrXD IDE - High-Performance Inference
//=============================================================================
// Provides C++ interface to AVX-512 assembly kernel
// Integrates with NHWC layout from Fix #3
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <immintrin.h>

namespace RawrXD {
namespace Kernels {

//=============================================================================
// Forward declarations for assembly functions
//=============================================================================
extern "C" {
    // Fused Q4_0 MatMul: C = A * B where B is Q4_0 quantized
    // Parameters passed via Windows x64 ABI
    void RawrXD_FusedQ4_0_MatMul_AVX512(
        const float* A,           // Activation matrix (M x K)
        const void* B,            // Q4_0 weight blocks
        float* C,                 // Output matrix (M x N)
        int64_t M,                // Rows of A
        int64_t K,                // Columns of A / rows of B
        int64_t N,                // Columns of B/C
        int64_t lda,              // Leading dimension of A
        int64_t ldc               // Leading dimension of C
    );
}

//=============================================================================
// Q4_0 Block Structure (matches GGUF Q4_0)
//=============================================================================
#pragma pack(push, 1)
struct Q4_0Block {
    float scale;                    // Block scale factor
    uint8_t data[16];              // 32 packed 4-bit weights
    // Total: 20 bytes per block
};
#pragma pack(pop)

static_assert(sizeof(Q4_0Block) == 20, "Q4_0Block must be 20 bytes");

//=============================================================================
// Fused Q4_0 MatMul Wrapper
//=============================================================================
class FusedQ4MatMul {
public:
    // Configuration for kernel execution
    struct Config {
        bool use_avx512 = true;     // Use AVX-512 if available
        int num_threads = 0;        // 0 = auto-detect
        bool enable_profiling = false;
    };

    // Performance metrics
    struct Metrics {
        double execution_time_ms;
        double throughput_gops;
        uint64_t cache_misses;
        uint64_t instructions_retired;
    };

    //=============================================================================
    // Execute fused Q4_0 matrix multiplication
    // 
    // Layout requirements (NHWC from Fix #3):
    //   - A: [M, K] in NHWC layout (contiguous channels)
    //   - B: [K, N] in Q4_0 blocks, NHWC-aware ordering
    //   - C: [M, N] in NHWC layout
    //
    // Returns: true on success, false on error
    //=============================================================================
    static bool Execute(
        const float* activation,    // M x K float32 matrix
        const Q4_0Block* weights,   // K x N in Q4_0 blocks
        float* output,              // M x N float32 output
        int M, int K, int N,
        const Config& config = {}
    );

    //=============================================================================
    // Optimized for transformer QKV projection
    //   - batch_size: number of sequences
    //   - seq_len: sequence length
    //   - num_heads: number of attention heads
    //   - head_dim: dimension per head
    //=============================================================================
    static bool ExecuteQKVProjection(
        const float* query_input,   // [batch, seq_len, hidden_dim]
        const Q4_0Block* q_weights, // [hidden_dim, hidden_dim] Q4_0
        const Q4_0Block* k_weights, // [hidden_dim, hidden_dim] Q4_0
        const Q4_0Block* v_weights, // [hidden_dim, hidden_dim] Q4_0
        float* q_output,            // [batch, seq_len, hidden_dim]
        float* k_output,            // [batch, seq_len, hidden_dim]
        float* v_output,            // [batch, seq_len, hidden_dim]
        int batch_size, int seq_len, int hidden_dim,
        const Config& config = {}
    );

    // Get last execution metrics
    static const Metrics& GetLastMetrics() { return s_last_metrics; }

    // Check AVX-512 support
    static bool IsAVX512Available();

private:
    static Metrics s_last_metrics;

    // Internal tiled execution for cache efficiency
    static bool ExecuteTiled(
        const float* A, const Q4_0Block* B, float* C,
        int M, int K, int N, int tile_M, int tile_N
    );

    // Prefetch weights into L2 cache
    static void PrefetchWeights(const Q4_0Block* weights, int num_blocks);
};

//=============================================================================
// Inline prefetch helpers
//=============================================================================
inline void PrefetchL1(const void* addr) {
    _mm_prefetch((const char*)addr, _MM_HINT_T0);
}

inline void PrefetchL2(const void* addr) {
    _mm_prefetch((const char*)addr, _MM_HINT_T1);
}

inline void PrefetchL3(const void* addr) {
    _mm_prefetch((const char*)addr, _MM_HINT_T2);
}

} // namespace Kernels
} // namespace RawrXD
