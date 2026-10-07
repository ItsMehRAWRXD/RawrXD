// ============================================================================
// benchmark_kernels.cpp - Phase 7B Performance Benchmark
// ============================================================================
// Measures: Q4_0_Q8_0_MatMul and FlashAttentionV2 performance
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <chrono>

// External declarations from resurrected kernels
extern "C" {
    int flash_attention_v2_f32(float* Q, float* K, float* V, float* output,
                                size_t seq_len, size_t head_dim);
    int q4_0_q8_0_matmul(const void* A, const void* B, float* C,
                         size_t m, size_t n, size_t k);
}

// Benchmark configuration
const int WARMUP_ITERATIONS = 10;
const int BENCHMARK_ITERATIONS = 100;

// Test sizes (realistic LLM dimensions)
struct TestSize {
    const char* name;
    size_t m, n, k;  // For matmul: A(m,k) * B(k,n) = C(m,n)
    size_t seq_len, head_dim;  // For attention
};

TestSize TEST_SIZES[] = {
    {"Small (512x512)",     512, 512, 512,   512, 64},
    {"Medium (1Kx1K)",     1024, 1024, 1024, 1024, 64},
    {"Large (4Kx4K)",     4096, 4096, 4096, 4096, 64},
    {"XL (8Kx8K)",        8192, 8192, 8192, 8192, 64},
};

// High-resolution timer using chrono
inline double GetMicroseconds() {
    auto now = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::time_point_cast<std::chrono::microseconds>(now);
    return (double)us.time_since_epoch().count();
}

// Allocate aligned memory
template<typename T>
T* AlignedAlloc(size_t count, size_t alignment = 64) {
    return (T*)_aligned_malloc(count * sizeof(T), alignment);
}

template<typename T>
void AlignedFree(T* ptr) {
    _aligned_free(ptr);
}

// ============================================================================
// Benchmark Q4_0_Q8_0_MatMul
// ============================================================================
void BenchmarkQ4Q8MatMul(const TestSize& size) {
    printf("\n--- Q4_0_Q8_0_MatMul: %s ---\n", size.name);
    
    // Allocate buffers
    // Q4_0: 4 bits per weight, 32 weights per block = 16 bytes per block + 2 bytes scale
    // For simplicity, allocate larger buffers
    size_t a_size = (size.m * size.k + 1) / 2 + (size.m * size.k / 32) * 2;
    size_t b_size = size.k * size.n + (size.k * size.n / 32) * 2;
    size_t c_size = size.m * size.n;
    
    uint8_t* A = AlignedAlloc<uint8_t>(a_size);
    uint8_t* B = AlignedAlloc<uint8_t>(b_size);
    float* C = AlignedAlloc<float>(c_size);
    
    if (!A || !B || !C) {
        printf("[ERROR] Memory allocation failed\n");
        return;
    }
    
    // Initialize with test pattern
    memset(A, 0x11, a_size);  // Pattern: all 1s in nibbles
    memset(B, 0x22, b_size);  // Pattern for Q8_0
    memset(C, 0, c_size * sizeof(float));
    
    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        q4_0_q8_0_matmul(A, B, C, size.m, size.n, size.k);
    }
    
    // Benchmark
    double start = GetMicroseconds();
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        q4_0_q8_0_matmul(A, B, C, size.m, size.n, size.k);
    }
    double end = GetMicroseconds();
    
    // Calculate metrics
    double total_us = end - start;
    double avg_us = total_us / BENCHMARK_ITERATIONS;
    double ops = 2.0 * (double)size.m * size.n * size.k;  // Multiply-adds
    double gflops = (ops / avg_us) / 1000.0;  // GFLOP/s
    
    // Memory bandwidth (rough estimate)
    double bytes_accessed = (double)(a_size + b_size + c_size * sizeof(float));
    double bandwidth_gbps = (bytes_accessed / avg_us) / 1000.0;  // GB/s
    
    printf("  Avg time:     %.3f us\n", avg_us);
    printf("  Throughput:   %.2f GFLOP/s\n", gflops);
    printf("  Memory BW:    %.2f GB/s\n", bandwidth_gbps);
    printf("  Ops/call:     %.0f\n", ops);
    
    // Estimate tokens/sec (assuming matmul is 80% of inference time)
    // Rough estimate: 1 token requires ~2 * params FLOPs
    double tokens_per_sec = (1.0 / (avg_us * 1.25)) * 1e6;
    printf("  Est tokens/s: %.0f\n", tokens_per_sec);
    
    AlignedFree(A);
    AlignedFree(B);
    AlignedFree(C);
}

// ============================================================================
// Benchmark FlashAttentionV2
// ============================================================================
void BenchmarkFlashAttention(const TestSize& size) {
    printf("\n--- FlashAttentionV2: %s ---\n", size.name);
    
    size_t seq_len = size.seq_len;
    size_t head_dim = size.head_dim;
    size_t total_elements = seq_len * head_dim;
    
    float* Q = AlignedAlloc<float>(total_elements);
    float* K = AlignedAlloc<float>(total_elements);
    float* V = AlignedAlloc<float>(total_elements);
    float* output = AlignedAlloc<float>(total_elements);
    
    if (!Q || !K || !V || !output) {
        printf("[ERROR] Memory allocation failed\n");
        return;
    }
    
    // Initialize
    for (size_t i = 0; i < total_elements; i++) {
        Q[i] = 0.1f;
        K[i] = 0.1f;
        V[i] = 0.1f;
        output[i] = 0.0f;
    }
    
    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        flash_attention_v2_f32(Q, K, V, output, seq_len, head_dim);
    }
    
    // Benchmark
    double start = GetMicroseconds();
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        flash_attention_v2_f32(Q, K, V, output, seq_len, head_dim);
    }
    double end = GetMicroseconds();
    
    // Calculate metrics
    double total_us = end - start;
    double avg_us = total_us / BENCHMARK_ITERATIONS;
    
    // Attention FLOPs: 2 * seq_len^2 * head_dim (Q*K^T) + 2 * seq_len^2 * head_dim (softmax*V)
    double ops = 4.0 * (double)seq_len * seq_len * head_dim;
    double gflops = (ops / avg_us) / 1000.0;
    
    printf("  Avg time:     %.3f us\n", avg_us);
    printf("  Throughput:   %.2f GFLOP/s\n", gflops);
    printf("  Ops/call:     %.0f\n", ops);
    
    AlignedFree(Q);
    AlignedFree(K);
    AlignedFree(V);
    AlignedFree(output);
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("=================================================================\n");
    printf("Sovereign Phase 7B - Kernel Performance Benchmark\n");
    printf("=================================================================\n");
    printf("Iterations: %d (warmup) + %d (benchmark)\n", WARMUP_ITERATIONS, BENCHMARK_ITERATIONS);
    printf("Timer: QueryPerformanceCounter\n");
    printf("=================================================================\n");
    
    const int num_sizes = sizeof(TEST_SIZES) / sizeof(TEST_SIZES[0]);
    
    // Benchmark Q4Q8 MatMul
    printf("\n\n[Q4_0_Q8_0_MatMul Benchmarks]\n");
    for (int i = 0; i < num_sizes; i++) {
        BenchmarkQ4Q8MatMul(TEST_SIZES[i]);
    }
    
    // Benchmark FlashAttention
    printf("\n\n[FlashAttentionV2 Benchmarks]\n");
    for (int i = 0; i < num_sizes; i++) {
        // Skip XL for attention (too slow)
        if (i < 3) {
            BenchmarkFlashAttention(TEST_SIZES[i]);
        }
    }
    
    printf("\n=================================================================\n");
    printf("Benchmark Complete\n");
    printf("=================================================================\n");
    
    return 0;
}
