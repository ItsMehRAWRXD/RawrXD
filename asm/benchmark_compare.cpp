// ============================================================================
// benchmark_compare.cpp - Compare Original vs Intrinsics Kernels
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <chrono>

// Original kernels (from resurrected)
extern "C" {
    int flash_attention_v2_f32(float* Q, float* K, float* V, float* output,
                                size_t seq_len, size_t head_dim);
    int q4_0_q8_0_matmul(const void* A, const void* B, float* C,
                         size_t m, size_t n, size_t k);
}

// Intrinsics kernels
extern "C" {
    int Sovereign_FlashAttentionV2_Intrinsics(
        float* Q, float* K, float* V, float* output,
        size_t seq_len, size_t head_dim);
    int Sovereign_Q4Q8_MatMul_Intrinsics(
        const void* A, const void* B, float* C,
        size_t m, size_t n, size_t k);
    const char* Sovereign_GetQ4Q8Version();
    const char* Sovereign_GetFlashAttentionVersion();
}

// Benchmark config
const int WARMUP = 5;
const int ITERATIONS = 50;

// Timer
inline double GetMicroseconds() {
    auto now = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::time_point_cast<std::chrono::microseconds>(now);
    return (double)us.time_since_epoch().count();
}

template<typename T>
T* AlignedAlloc(size_t count) {
    return (T*)_aligned_malloc(count * sizeof(T), 64);
}

// ============================================================================
// Benchmark Q4Q8 MatMul
// ============================================================================
void BenchmarkQ4Q8() {
    printf("\n========== Q4_0_Q8_0_MatMul Comparison ==========\n");
    printf("Version: %s\n\n", Sovereign_GetQ4Q8Version());
    
    const size_t m = 512, n = 512, k = 512;
    
    // Allocate buffers
    size_t a_size = (m * k + 1) / 2 + (m * k / 32) * 2;
    size_t b_size = k * n + (k * n / 32) * 2;
    
    uint8_t* A = AlignedAlloc<uint8_t>(a_size);
    uint8_t* B = AlignedAlloc<uint8_t>(b_size);
    float* C_orig = AlignedAlloc<float>(m * n);
    float* C_intr = AlignedAlloc<float>(m * n);
    
    memset(A, 0x11, a_size);
    memset(B, 0x22, b_size);
    
    // Original kernel
    printf("[Original]\n");
    for (int i = 0; i < WARMUP; i++) {
        q4_0_q8_0_matmul(A, B, C_orig, m, n, k);
    }
    
    double start = GetMicroseconds();
    for (int i = 0; i < ITERATIONS; i++) {
        q4_0_q8_0_matmul(A, B, C_orig, m, n, k);
    }
    double orig_us = (GetMicroseconds() - start) / ITERATIONS;
    
    double ops = 2.0 * m * n * k;
    double orig_gflops = (ops / orig_us) / 1000.0;
    
    printf("  Time:   %.3f us\n", orig_us);
    printf("  Perf:   %.2f GFLOP/s\n", orig_gflops);
    
    // Intrinsics kernel
    printf("\n[Intrinsics]\n");
    for (int i = 0; i < WARMUP; i++) {
        Sovereign_Q4Q8_MatMul_Intrinsics(A, B, C_intr, m, n, k);
    }
    
    start = GetMicroseconds();
    for (int i = 0; i < ITERATIONS; i++) {
        Sovereign_Q4Q8_MatMul_Intrinsics(A, B, C_intr, m, n, k);
    }
    double intr_us = (GetMicroseconds() - start) / ITERATIONS;
    
    double intr_gflops = (ops / intr_us) / 1000.0;
    double speedup = orig_us / intr_us;
    
    printf("  Time:   %.3f us\n", intr_us);
    printf("  Perf:   %.2f GFLOP/s\n", intr_gflops);
    printf("  Speedup: %.2fx\n", speedup);
    
    // Verify correctness (rough check)
    bool match = true;
    for (size_t i = 0; i < m * n && i < 100; i++) {
        if (std::abs(C_orig[i] - C_intr[i]) > 0.1f) {
            match = false;
            break;
        }
    }
    printf("  Correctness: %s\n", match ? "PASS (rough)" : "CHECK");
    
    _aligned_free(A);
    _aligned_free(B);
    _aligned_free(C_orig);
    _aligned_free(C_intr);
}

// ============================================================================
// Benchmark FlashAttention
// ============================================================================
void BenchmarkFlashAttention() {
    printf("\n========== FlashAttentionV2 Comparison ==========\n");
    printf("Version: %s\n\n", Sovereign_GetFlashAttentionVersion());
    
    const size_t seq_len = 256;  // Smaller for intrinsics (more compute)
    const size_t head_dim = 64;
    const size_t total = seq_len * head_dim;
    
    float* Q = AlignedAlloc<float>(total);
    float* K = AlignedAlloc<float>(total);
    float* V = AlignedAlloc<float>(total);
    float* out_orig = AlignedAlloc<float>(total);
    float* out_intr = AlignedAlloc<float>(total);
    
    for (size_t i = 0; i < total; i++) {
        Q[i] = 0.1f;
        K[i] = 0.1f;
        V[i] = 0.1f;
    }
    
    // Original
    printf("[Original]\n");
    for (int i = 0; i < WARMUP; i++) {
        flash_attention_v2_f32(Q, K, V, out_orig, seq_len, head_dim);
    }
    
    double start = GetMicroseconds();
    for (int i = 0; i < ITERATIONS; i++) {
        flash_attention_v2_f32(Q, K, V, out_orig, seq_len, head_dim);
    }
    double orig_us = (GetMicroseconds() - start) / ITERATIONS;
    
    double ops = 4.0 * seq_len * seq_len * head_dim;
    double orig_gflops = (ops / orig_us) / 1000.0;
    
    printf("  Time:   %.3f us\n", orig_us);
    printf("  Perf:   %.2f GFLOP/s\n", orig_gflops);
    
    // Intrinsics
    printf("\n[Intrinsics]\n");
    for (int i = 0; i < WARMUP; i++) {
        Sovereign_FlashAttentionV2_Intrinsics(Q, K, V, out_intr, seq_len, head_dim);
    }
    
    start = GetMicroseconds();
    for (int i = 0; i < ITERATIONS; i++) {
        Sovereign_FlashAttentionV2_Intrinsics(Q, K, V, out_intr, seq_len, head_dim);
    }
    double intr_us = (GetMicroseconds() - start) / ITERATIONS;
    
    double intr_gflops = (ops / intr_us) / 1000.0;
    double speedup = orig_us / intr_us;
    
    printf("  Time:   %.3f us\n", intr_us);
    printf("  Perf:   %.2f GFLOP/s\n", intr_gflops);
    printf("  Speedup: %.2fx\n", speedup);
    
    _aligned_free(Q);
    _aligned_free(K);
    _aligned_free(V);
    _aligned_free(out_orig);
    _aligned_free(out_intr);
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("=================================================================\n");
    printf("Sovereign Phase 7B - Intrinsics vs Original Benchmark\n");
    printf("=================================================================\n");
    
    BenchmarkQ4Q8();
    BenchmarkFlashAttention();
    
    printf("\n=================================================================\n");
    printf("Benchmark Complete\n");
    printf("=================================================================\n");
    
    return 0;
}
