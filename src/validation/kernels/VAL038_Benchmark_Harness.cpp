//=============================================================================
// VAL-038 Benchmark Harness
// Direct ABI call to MASM kernels with rdtsc timing
// No dispatch overhead, no allocation, no logging in hot path
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <immintrin.h>

// rdtsc/rtdscp intrinsics from immintrin.h
// __rdtsc, __rdtscp, __cpuid are available via intrin.h on MSVC
#ifdef _MSC_VER
    #include <intrin.h>
#endif

// Disable optimizations for timing code
#pragma optimize("", off)

//=============================================================================
// External MASM Kernel Declarations (direct ABI)
//=============================================================================
extern "C" {
    // VAL-038 Fused Tree Attention
    // RCX=output, RDX=Q, R8=K, R9=V, [RSP+40]=num_q, [RSP+48]=num_k, [RSP+56]=tree_mask
    void TreeAttention_Fused_VAL038(
        float* output,
        const float* Q,
        const float* K,
        const float* V,
        uint32_t num_q,
        uint32_t num_k,
        const uint8_t* tree_mask
    );
    
    // Softmax LUT kernel
    // RCX=input, RDX=output, R8=length
    void Softmax_LUT_AVX512(
        const float* input,
        float* output,
        uint32_t length
    );
    
    // Init LUT tables (call once)
    void Softmax_LUT_Init();
}

//=============================================================================
// rdtsc Timing - Minimal Overhead
//=============================================================================
inline uint64_t rdtsc() {
    return __rdtsc();
}

inline uint64_t rdtscp(uint32_t& aux) {
    return __rdtscp(&aux);
}

// Warm up CPU to stabilize frequency
void warmup_cpu() {
    volatile int sum = 0;
    for (int i = 0; i < 1000000; i++) {
        sum += i;
    }
}

// Serialize instruction stream
inline void cpuid() {
    int regs[4];
    __cpuid(regs, 0);
}

//=============================================================================
// Benchmark Configuration
//=============================================================================
constexpr uint32_t HEAD_DIM = 64;
constexpr uint32_t BLOCK_Q = 16;  // Queries per block
constexpr uint32_t BLOCK_K = 16;  // Keys per block
constexpr uint32_t WARMUP_ITERATIONS = 1000;
constexpr uint32_t BENCHMARK_ITERATIONS = 100000;

//=============================================================================
// Reference Implementation (C++ scalar)
//=============================================================================
void reference_attention(
    float* output,
    const float* Q,
    const float* K,
    const float* V,
    uint32_t num_q,
    uint32_t num_k,
    const uint8_t* tree_mask
) {
    const float scale = 1.0f / std::sqrt(static_cast<float>(HEAD_DIM));
    
    for (uint32_t q = 0; q < num_q; q++) {
        // Compute Q·K^T for this query
        float scores[BLOCK_K];
        float max_score = -1e38f;
        
        for (uint32_t k = 0; k < num_k; k++) {
            if (!tree_mask[q * num_k + k]) {
                scores[k] = -1e38f;
                continue;
            }
            
            // Dot product Q[q] · K[k]
            float dot = 0.0f;
            for (uint32_t d = 0; d < HEAD_DIM; d++) {
                dot += Q[q * HEAD_DIM + d] * K[k * HEAD_DIM + d];
            }
            scores[k] = dot * scale;
            max_score = std::max(max_score, scores[k]);
        }
        
        // Softmax
        float sum_exp = 0.0f;
        for (uint32_t k = 0; k < num_k; k++) {
            if (scores[k] > -1e37f) {
                scores[k] = std::exp(scores[k] - max_score);
                sum_exp += scores[k];
            } else {
                scores[k] = 0.0f;
            }
        }
        
        float inv_sum = 1.0f / sum_exp;
        for (uint32_t k = 0; k < num_k; k++) {
            scores[k] *= inv_sum;
        }
        
        // Weighted sum of V
        for (uint32_t d = 0; d < HEAD_DIM; d++) {
            float acc = 0.0f;
            for (uint32_t k = 0; k < num_k; k++) {
                acc += scores[k] * V[k * HEAD_DIM + d];
            }
            output[q * HEAD_DIM + d] = acc;
        }
    }
}

//=============================================================================
// Validation
//=============================================================================
bool validate_results(
    const float* ref_output,
    const float* asm_output,
    uint32_t num_elements,
    float tolerance = 1e-3f
) {
    float max_error = 0.0f;
    bool passed = true;
    
    for (uint32_t i = 0; i < num_elements; i++) {
        float error = std::abs(ref_output[i] - asm_output[i]);
        max_error = std::max(max_error, error);
        
        if (error > tolerance) {
            if (passed) {
                printf("VALIDATION FAILED:\n");
                passed = false;
            }
            if (i < 5) {
                printf("  [%u]: ref=%.6f asm=%.6f err=%.6f\n", 
                       i, ref_output[i], asm_output[i], error);
            }
        }
    }
    
    if (passed) {
        printf("VALIDATION PASSED (max_error=%.6e)\n", max_error);
    } else {
        printf("Max error: %.6e\n", max_error);
    }
    
    return passed;
}

//=============================================================================
// Benchmark
//=============================================================================
struct BenchmarkResult {
    uint64_t cycles_min;
    uint64_t cycles_avg;
    uint64_t cycles_max;
    double latency_ns;
    double throughput_kops_per_sec;
};

BenchmarkResult benchmark_kernel(
    void (*kernel)(float*, const float*, const float*, const float*, 
                   uint32_t, uint32_t, const uint8_t*),
    float* output,
    const float* Q,
    const float* K,
    const float* V,
    uint32_t num_q,
    uint32_t num_k,
    const uint8_t* tree_mask,
    const char* name
) {
    // Warmup
    for (uint32_t i = 0; i < WARMUP_ITERATIONS; i++) {
        kernel(output, Q, K, V, num_q, num_k, tree_mask);
    }
    
    // Benchmark
    uint64_t cycles_min = UINT64_MAX;
    uint64_t cycles_max = 0;
    uint64_t cycles_sum = 0;
    
    for (uint32_t i = 0; i < BENCHMARK_ITERATIONS; i++) {
        cpuid();  // Serialize
        uint64_t t0 = rdtsc();
        
        kernel(output, Q, K, V, num_q, num_k, tree_mask);
        
        uint32_t aux;
        uint64_t t1 = rdtscp(aux);
        cpuid();  // Serialize
        
        uint64_t cycles = t1 - t0;
        cycles_min = std::min(cycles_min, cycles);
        cycles_max = std::max(cycles_max, cycles);
        cycles_sum += cycles;
    }
    
    BenchmarkResult result;
    result.cycles_min = cycles_min;
    result.cycles_avg = cycles_sum / BENCHMARK_ITERATIONS;
    result.cycles_max = cycles_max;
    
    // Estimate latency (assume 3.5 GHz base clock)
    const double GHz = 3.5;
    result.latency_ns = result.cycles_min / GHz;
    result.throughput_kops_per_sec = 1e6 / result.latency_ns;
    
    return result;
}

//=============================================================================
// Main
//=============================================================================
int main() {
    printf("=============================================================================\n");
    printf("VAL-038 Benchmark Harness\n");
    printf("Direct ABI call to MASM kernels with rdtsc timing\n");
    printf("=============================================================================\n\n");
    
    // Check CPU features
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    bool has_avx = (cpu_info[2] & (1 << 28)) != 0;
    
    __cpuid(cpu_info, 7);
    bool has_avx512f = (cpu_info[1] & (1 << 16)) != 0;
    bool has_avx512bw = (cpu_info[1] & (1 << 30)) != 0;
    bool has_avx512vl = (cpu_info[1] & (1 << 31)) != 0;
    
    printf("CPU Features:\n");
    printf("  AVX:      %s\n", has_avx ? "YES" : "NO");
    printf("  AVX-512F: %s\n", has_avx512f ? "YES" : "NO");
    printf("  AVX-512BW: %s\n", has_avx512bw ? "YES" : "NO");
    printf("  AVX-512VL: %s\n", has_avx512vl ? "YES" : "NO");
    printf("\n");
    
    if (!has_avx512f) {
        printf("ERROR: AVX-512F required for VAL-038 kernels\n");
        return 1;
    }
    
    // Initialize LUT
    Softmax_LUT_Init();
    
    // Allocate aligned buffers
    alignas(64) float Q[BLOCK_Q * HEAD_DIM];
    alignas(64) float K[BLOCK_K * HEAD_DIM];
    alignas(64) float V[BLOCK_K * HEAD_DIM];
    alignas(64) float output_ref[BLOCK_Q * HEAD_DIM];
    alignas(64) float output_asm[BLOCK_Q * HEAD_DIM];
    alignas(64) uint8_t tree_mask[BLOCK_Q * BLOCK_K];
    
    // Initialize test data
    for (uint32_t i = 0; i < BLOCK_Q * HEAD_DIM; i++) {
        Q[i] = static_cast<float>(i % 7) * 0.1f;
    }
    for (uint32_t i = 0; i < BLOCK_K * HEAD_DIM; i++) {
        K[i] = static_cast<float>(i % 5) * 0.15f;
        V[i] = static_cast<float>(i % 3) * 0.2f;
    }
    for (uint32_t i = 0; i < BLOCK_Q * BLOCK_K; i++) {
        tree_mask[i] = (i % 3 != 0) ? 1 : 0;  // Some sparsity
    }
    
    warmup_cpu();
    
    // Run reference implementation
    printf("Running C++ reference...\n");
    reference_attention(output_ref, Q, K, V, BLOCK_Q, BLOCK_K, tree_mask);
    
    // Run ASM implementation
    printf("Running VAL-038 MASM kernel...\n");
    TreeAttention_Fused_VAL038(output_asm, Q, K, V, BLOCK_Q, BLOCK_K, tree_mask);
    
    // Validate
    printf("\n");
    bool valid = validate_results(output_ref, output_asm, BLOCK_Q * HEAD_DIM);
    printf("\n");
    
    if (!valid) {
        return 1;
    }
    
    // Benchmark
    printf("=============================================================================\n");
    printf("Benchmark Results (%u iterations)\n", BENCHMARK_ITERATIONS);
    printf("=============================================================================\n\n");
    
    // Benchmark reference (single iteration for comparison)
    printf("C++ Reference (scalar):\n");
    auto ref_result = benchmark_kernel(
        [](float* o, const float* q, const float* k, const float* v,
           uint32_t nq, uint32_t nk, const uint8_t* m) {
            reference_attention(o, q, k, v, nq, nk, m);
        },
        output_ref, Q, K, V, BLOCK_Q, BLOCK_K, tree_mask, "reference"
    );
    printf("  Cycles: min=%llu avg=%llu max=%llu\n",
           ref_result.cycles_min, ref_result.cycles_avg, ref_result.cycles_max);
    printf("  Latency: %.2f ns\n", ref_result.latency_ns);
    printf("  Throughput: %.2f kops/sec\n", ref_result.throughput_kops_per_sec);
    printf("\n");
    
    // Benchmark VAL-038
    printf("VAL-038 MASM (AVX-512):\n");
    auto asm_result = benchmark_kernel(
        TreeAttention_Fused_VAL038,
        output_asm, Q, K, V, BLOCK_Q, BLOCK_K, tree_mask, "VAL-038"
    );
    printf("  Cycles: min=%llu avg=%llu max=%llu\n",
           asm_result.cycles_min, asm_result.cycles_avg, asm_result.cycles_max);
    printf("  Latency: %.2f ns (%.3f us)\n", 
           asm_result.latency_ns, asm_result.latency_ns / 1000.0);
    printf("  Throughput: %.2f kops/sec\n", asm_result.throughput_kops_per_sec);
    printf("\n");
    
    // Speedup
    double speedup = static_cast<double>(ref_result.cycles_min) / asm_result.cycles_min;
    printf("Speedup: %.2fx\n", speedup);
    printf("\n");
    
    // Target check
    printf("=============================================================================\n");
    printf("Target Analysis\n");
    printf("=============================================================================\n");
    printf("Current:  %.2f ns (%.3f us)\n", asm_result.latency_ns, asm_result.latency_ns / 1000.0);
    printf("Target:   <500 ns (<0.5 us)\n");
    printf("Gap:      %.2fx %s\n",
           asm_result.latency_ns / 500.0,
           asm_result.latency_ns < 500.0 ? "✓ TARGET MET" : "✗ NEEDS OPTIMIZATION");
    printf("\n");
    
    return (asm_result.latency_ns < 500.0) ? 0 : 2;
}
