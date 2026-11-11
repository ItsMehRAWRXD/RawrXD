// ═══════════════════════════════════════════════════════════════════════════════
// VAL-038.1: MASM Mechanical Translation - C++ Wrapper
// ═══════════════════════════════════════════════════════════════════════════════
// Calls the MASM kernel and validates against C++ reference

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>
#include <cmath>

// AVX-512 intrinsics for reference implementation
#include <immintrin.h>

// ═══════════════════════════════════════════════════════════════════════════════
// External MASM function declaration
// ═══════════════════════════════════════════════════════════════════════════════
extern "C" {
    // MASM kernel: TreeAttention_FusedSparse_MASM
    // Parameters:
    //   RCX = Q pointer
    //   RDX = K pointer  
    //   R8  = V pointer
    //   R9  = output pointer
    //   [RSP+0x28] = edge list pointer
    //   [RSP+0x30] = num_edges
    //   [RSP+0x38] = head_dim
    //   [RSP+0x40] = scale
    void TreeAttention_FusedSparse_MASM(
        const float* Q,
        const float* K,
        const float* V,
        float* output,
        const uint16_t* edge_list,  // [num_edges * 2] array of [q_idx, k_idx] pairs
        uint32_t num_edges,
        uint32_t head_dim,
        float scale
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Edge list structure
// ═══════════════════════════════════════════════════════════════════════════════
struct Edge {
    uint16_t q_idx;
    uint16_t k_idx;
};

void BuildEdgeList(std::vector<Edge>& edges, uint32_t num_nodes) {
    edges.clear();
    for (uint32_t q = 0; q < num_nodes; q++) {
        // Self
        edges.push_back({(uint16_t)q, (uint16_t)q});
        
        // Ancestors (4-ary tree)
        uint32_t current = q;
        while (current > 0) {
            uint32_t parent = (current - 1) / 4;
            edges.push_back({(uint16_t)q, (uint16_t)parent});
            current = parent;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════════
constexpr uint32_t TEST_HEAD_DIM = 64;
constexpr uint32_t TEST_NUM_NODES = 16;
constexpr uint32_t TEST_ITERATIONS = 10000;

// ═══════════════════════════════════════════════════════════════════════════════
// Utility Functions
// ═══════════════════════════════════════════════════════════════════════════════
void InitializeMatrix(float* data, uint32_t rows, uint32_t cols, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    for (uint32_t i = 0; i < rows * cols; i++) {
        data[i] = dist(rng);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// C++ Reference Implementation (VAL-037.1)
// ═══════════════════════════════════════════════════════════════════════════════
void Reference_FusedSparse(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    const std::vector<Edge>& edges,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    float scale = 1.0f / sqrtf((float)head_dim);
    const uint32_t simd_width = 16;
    
    // Process edges grouped by query
    for (uint32_t q = 0; q < num_nodes; q++) {
        float max_val = -1e30f;
        float exp_sum = 0.0f;
        float accum[64];
        for (uint32_t d = 0; d < head_dim; d++) accum[d] = 0.0f;
        
        // Find all edges for this query
        for (const auto& edge : edges) {
            if (edge.q_idx != q) continue;
            
            uint32_t k = edge.k_idx;
            
            // QK dot product
            __m512 sum_vec = _mm512_setzero_ps();
            uint32_t d = 0;
            for (; d + simd_width <= head_dim; d += simd_width) {
                __m512 q_vec = _mm512_loadu_ps(&Q[q * head_dim + d]);
                __m512 k_vec = _mm512_loadu_ps(&K[k * head_dim + d]);
                sum_vec = _mm512_fmadd_ps(q_vec, k_vec, sum_vec);
            }
            
            __m256 vlow = _mm512_castps512_ps256(sum_vec);
            __m256 vhigh = _mm512_extractf32x8_ps(sum_vec, 1);
            vlow = _mm256_add_ps(vlow, vhigh);
            __m128 vlow128 = _mm256_castps256_ps128(vlow);
            __m128 vhigh128 = _mm256_extractf128_ps(vlow, 1);
            vlow128 = _mm_add_ps(vlow128, vhigh128);
            vlow128 = _mm_hadd_ps(vlow128, vlow128);
            vlow128 = _mm_hadd_ps(vlow128, vlow128);
            float score = _mm_cvtss_f32(vlow128);
            
            for (; d < head_dim; d++) {
                score += Q[q * head_dim + d] * K[k * head_dim + d];
            }
            
            score *= scale;
            
            // Online softmax
            float weight;
            if (score > max_val) {
                float scale_factor = expf(max_val - score);
                for (uint32_t d = 0; d < head_dim; d++) accum[d] *= scale_factor;
                exp_sum *= scale_factor;
                max_val = score;
                weight = 1.0f;
            } else {
                weight = expf(score - max_val);
            }
            
            exp_sum += weight;
            for (uint32_t d = 0; d < head_dim; d++) {
                accum[d] += weight * V[k * head_dim + d];
            }
        }
        
        for (uint32_t d = 0; d < head_dim; d++) {
            output[q * head_dim + d] = accum[d] / exp_sum;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════
int main() {
    printf("=============================================================================\n");
    printf("VAL-038.1: MASM Mechanical Translation\n");
    printf("=============================================================================\n");
    printf("\n");
    printf("Validating MASM kernel against C++ reference...\n");
    printf("\n");
    
    // Allocate aligned memory
    float* Q = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* K = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* V = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* output_cpp = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* output_masm = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    
    // Initialize data
    InitializeMatrix(Q, TEST_NUM_NODES, TEST_HEAD_DIM, 42);
    InitializeMatrix(K, TEST_NUM_NODES, TEST_HEAD_DIM, 43);
    InitializeMatrix(V, TEST_NUM_NODES, TEST_HEAD_DIM, 44);
    
    // Build edge list
    std::vector<Edge> edges;
    BuildEdgeList(edges, TEST_NUM_NODES);
    
    printf("Configuration:\n");
    printf("  Nodes: %u\n", TEST_NUM_NODES);
    printf("  Head dim: %u\n", TEST_HEAD_DIM);
    printf("  Edges: %zu\n", edges.size());
    printf("\n");
    
    // Test 1: Correctness validation (single run)
    printf("=== Test 1: Correctness Validation ===\n");
    
    // Run C++ reference
    Reference_FusedSparse(Q, K, V, output_cpp, edges, TEST_NUM_NODES, TEST_HEAD_DIM);
    
    // Run MASM kernel
    float scale = 1.0f / sqrtf((float)TEST_HEAD_DIM);
    TreeAttention_FusedSparse_MASM(Q, K, V, output_masm, 
        (const uint16_t*)edges.data(), (uint32_t)edges.size(), TEST_HEAD_DIM, scale);
    
    // Compare results
    float max_diff = 0.0f;
    for (uint32_t i = 0; i < TEST_NUM_NODES * TEST_HEAD_DIM; i++) {
        float diff = std::abs(output_cpp[i] - output_masm[i]);
        max_diff = std::max(max_diff, diff);
    }
    
    printf("  Max difference: %.6f\n", max_diff);
    printf("  Correctness: %s\n", (max_diff < 0.001f) ? "PASS" : "FAIL");
    printf("\n");
    
    // Test 2: Performance benchmark
    printf("=== Test 2: Performance Benchmark ===\n");
    
    // Warmup
    for (uint32_t i = 0; i < 100; i++) {
        Reference_FusedSparse(Q, K, V, output_cpp, edges, TEST_NUM_NODES, TEST_HEAD_DIM);
        TreeAttention_FusedSparse_MASM(Q, K, V, output_masm, 
            (const uint16_t*)edges.data(), (uint32_t)edges.size(), TEST_HEAD_DIM, scale);
    }
    
    // Benchmark C++
    auto start_cpp = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        Reference_FusedSparse(Q, K, V, output_cpp, edges, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    auto end_cpp = std::chrono::high_resolution_clock::now();
    auto duration_cpp = std::chrono::duration_cast<std::chrono::nanoseconds>(end_cpp - start_cpp).count();
    
    // Benchmark MASM
    auto start_masm = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        TreeAttention_FusedSparse_MASM(Q, K, V, output_masm, 
            (const uint16_t*)edges.data(), (uint32_t)edges.size(), TEST_HEAD_DIM, scale);
    }
    auto end_masm = std::chrono::high_resolution_clock::now();
    auto duration_masm = std::chrono::duration_cast<std::chrono::nanoseconds>(end_masm - start_masm).count();
    
    double time_cpp_us = duration_cpp / 1000.0 / TEST_ITERATIONS;
    double time_masm_us = duration_masm / 1000.0 / TEST_ITERATIONS;
    double speedup = time_cpp_us / time_masm_us;
    
    printf("  C++ Reference:  %.3f us\n", time_cpp_us);
    printf("  MASM Kernel:    %.3f us\n", time_masm_us);
    printf("  Speedup:        %.2fx\n", speedup);
    printf("\n");
    
    printf("=== Target Comparison ===\n");
    printf("  Target:         0.500 us\n");
    printf("  Current MASM:   %.3f us\n", time_masm_us);
    printf("  Gap to target:  %.1fx\n", time_masm_us / 0.5);
    printf("\n");
    
    // Cleanup
    _aligned_free(Q);
    _aligned_free(K);
    _aligned_free(V);
    _aligned_free(output_cpp);
    _aligned_free(output_masm);
    
    return (max_diff < 0.001f) ? 0 : 1;
}
