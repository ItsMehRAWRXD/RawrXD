// ═══════════════════════════════════════════════════════════════════════════════
// VAL-037: Tree Sparsity Exploitation
// ═══════════════════════════════════════════════════════════════════════════════
// Instead of computing full 16x16 attention matrix, compute only valid tree edges
// A 4x4 tree has ~30-50 valid edges vs 256 dense entries

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>
#include <cmath>
#include <immintrin.h>
#include <intrin.h>

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════════
constexpr uint32_t TEST_HEAD_DIM = 64;
constexpr uint32_t TEST_NUM_NODES = 16;  // 4x4 tree
constexpr uint32_t TEST_ITERATIONS = 10000;

// ═══════════════════════════════════════════════════════════════════════════════
// Tree Structure Definition
// ═══════════════════════════════════════════════════════════════════════════════
struct TreeEdge {
    uint32_t query_idx;  // Node computing attention
    uint32_t key_idx;    // Node being attended to
};

// Build valid edges for a 4x4 tree structure
// Level 0: 1 node (root)
// Level 1: 4 nodes (children of root)
// Level 2: 9 nodes (grandchildren)
// Level 3: 16 nodes (great-grandchildren)
// Actually for 4x4: 1 + 4 + 16 = 21 nodes, but we use 16 for simplicity
void BuildTreeEdges(std::vector<TreeEdge>& edges, uint32_t num_nodes) {
    edges.clear();
    // For a simple tree: each node can attend to itself and ancestors
    for (uint32_t q = 0; q < num_nodes; q++) {
        for (uint32_t k = 0; k <= q; k++) {
            edges.push_back({q, k});
        }
    }
}

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
// DENSE Q@K^T (baseline - computes all 256 entries)
// ═══════════════════════════════════════════════════════════════════════════════
void QK_Dense(
    const float* Q,
    const float* K,
    float* scores,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    const uint32_t simd_width = 16;
    
    for (uint32_t q_idx = 0; q_idx < num_nodes; q_idx++) {
        for (uint32_t k_idx = 0; k_idx < num_nodes; k_idx++) {
            __m512 sum_vec = _mm512_setzero_ps();
            
            uint32_t d = 0;
            for (; d + simd_width <= head_dim; d += simd_width) {
                __m512 q_vec = _mm512_load_ps(&Q[q_idx * head_dim + d]);
                __m512 k_vec = _mm512_load_ps(&K[k_idx * head_dim + d]);
                sum_vec = _mm512_fmadd_ps(q_vec, k_vec, sum_vec);
            }
            
            // Horizontal sum
            __m256 vlow = _mm512_castps512_ps256(sum_vec);
            __m256 vhigh = _mm512_extractf32x8_ps(sum_vec, 1);
            vlow = _mm256_add_ps(vlow, vhigh);
            __m128 vlow128 = _mm256_castps256_ps128(vlow);
            __m128 vhigh128 = _mm256_extractf128_ps(vlow, 1);
            vlow128 = _mm_add_ps(vlow128, vhigh128);
            vlow128 = _mm_hadd_ps(vlow128, vlow128);
            vlow128 = _mm_hadd_ps(vlow128, vlow128);
            float sum = _mm_cvtss_f32(vlow128);
            
            for (; d < head_dim; d++) {
                sum += Q[q_idx * head_dim + d] * K[k_idx * head_dim + d];
            }
            
            scores[q_idx * num_nodes + k_idx] = sum;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SPARSE Q@K^T (VAL-037 - computes only valid edges)
// ═══════════════════════════════════════════════════════════════════════════════
void QK_Sparse(
    const float* Q,
    const float* K,
    float* scores,
    const std::vector<TreeEdge>& edges,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    const uint32_t simd_width = 16;
    
    // Initialize scores to -inf (for masked positions)
    for (uint32_t i = 0; i < num_nodes * num_nodes; i++) {
        scores[i] = -1e30f;
    }
    
    // Compute only valid edges
    for (const auto& edge : edges) {
        uint32_t q_idx = edge.query_idx;
        uint32_t k_idx = edge.key_idx;
        
        __m512 sum_vec = _mm512_setzero_ps();
        
        uint32_t d = 0;
        for (; d + simd_width <= head_dim; d += simd_width) {
            __m512 q_vec = _mm512_load_ps(&Q[q_idx * head_dim + d]);
            __m512 k_vec = _mm512_load_ps(&K[k_idx * head_dim + d]);
            sum_vec = _mm512_fmadd_ps(q_vec, k_vec, sum_vec);
        }
        
        // Horizontal sum
        __m256 vlow = _mm512_castps512_ps256(sum_vec);
        __m256 vhigh = _mm512_extractf32x8_ps(sum_vec, 1);
        vlow = _mm256_add_ps(vlow, vhigh);
        __m128 vlow128 = _mm256_castps256_ps128(vlow);
        __m128 vhigh128 = _mm256_extractf128_ps(vlow, 1);
        vlow128 = _mm_add_ps(vlow128, vhigh128);
        vlow128 = _mm_hadd_ps(vlow128, vlow128);
        vlow128 = _mm_hadd_ps(vlow128, vlow128);
        float sum = _mm_cvtss_f32(vlow128);
        
        for (; d < head_dim; d++) {
            sum += Q[q_idx * head_dim + d] * K[k_idx * head_dim + d];
        }
        
        scores[q_idx * num_nodes + k_idx] = sum;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Softmax (same for both)
// ═══════════════════════════════════════════════════════════════════════════════
void Softmax(
    float* scores,
    uint32_t num_nodes,
    float scale
) {
    for (uint32_t row = 0; row < num_nodes; row++) {
        // Find max
        float max_val = -1e30f;
        for (uint32_t col = 0; col < num_nodes; col++) {
            float val = scores[row * num_nodes + col];
            if (val > max_val) max_val = val;
        }
        
        // Compute exp and sum
        float sum = 0.0f;
        for (uint32_t col = 0; col < num_nodes; col++) {
            float val = scores[row * num_nodes + col];
            if (val > -1e20f) {  // Valid entry
                float exp_val = expf(val * scale - max_val * scale);
                scores[row * num_nodes + col] = exp_val;
                sum += exp_val;
            } else {
                scores[row * num_nodes + col] = 0.0f;
            }
        }
        
        // Normalize
        for (uint32_t col = 0; col < num_nodes; col++) {
            scores[row * num_nodes + col] /= sum;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// A@V (same for both)
// ═══════════════════════════════════════════════════════════════════════════════
void AV_Computation(
    const float* scores,
    const float* V,
    float* output,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    const uint32_t simd_width = 16;
    
    for (uint32_t row = 0; row < num_nodes; row++) {
        uint32_t d = 0;
        for (; d + simd_width <= head_dim; d += simd_width) {
            __m512 sum_vec = _mm512_setzero_ps();
            
            for (uint32_t k = 0; k < num_nodes; k++) {
                float score = scores[row * num_nodes + k];
                __m512 score_vec = _mm512_set1_ps(score);
                __m512 v_vec = _mm512_load_ps(&V[k * head_dim + d]);
                sum_vec = _mm512_fmadd_ps(score_vec, v_vec, sum_vec);
            }
            
            _mm512_store_ps(&output[row * head_dim + d], sum_vec);
        }
        
        for (; d < head_dim; d++) {
            float sum = 0.0f;
            for (uint32_t k = 0; k < num_nodes; k++) {
                sum += scores[row * num_nodes + k] * V[k * head_dim + d];
            }
            output[row * head_dim + d] = sum;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Complete Forward Pass - DENSE
// ═══════════════════════════════════════════════════════════════════════════════
void Forward_Dense(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    float* scores,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    QK_Dense(Q, K, scores, num_nodes, head_dim);
    
    float scale = 1.0f / sqrtf((float)head_dim);
    Softmax(scores, num_nodes, scale);
    
    AV_Computation(scores, V, output, num_nodes, head_dim);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Complete Forward Pass - SPARSE
// ═══════════════════════════════════════════════════════════════════════════════
void Forward_Sparse(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    float* scores,
    const std::vector<TreeEdge>& edges,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    QK_Sparse(Q, K, scores, edges, num_nodes, head_dim);
    
    float scale = 1.0f / sqrtf((float)head_dim);
    Softmax(scores, num_nodes, scale);
    
    AV_Computation(scores, V, output, num_nodes, head_dim);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════
int main() {
    printf("=============================================================================\n");
    printf("VAL-037: Tree Sparsity Exploitation\n");
    printf("=============================================================================\n");
    printf("Strategy: Compute only valid tree edges vs dense 16x16 matrix\n");
    printf("\n");
    
    // Build tree edges
    std::vector<TreeEdge> edges;
    BuildTreeEdges(edges, TEST_NUM_NODES);
    printf("Tree structure: %u nodes\n", TEST_NUM_NODES);
    printf("Valid edges: %zu (vs %u dense)\n", edges.size(), TEST_NUM_NODES * TEST_NUM_NODES);
    printf("Sparsity: %.1f%% reduction\n", 100.0f * (1.0f - (float)edges.size() / (TEST_NUM_NODES * TEST_NUM_NODES)));
    printf("\n");
    
    // Allocate memory
    float* Q = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* K = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* V = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* output_dense = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* output_sparse = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* scores = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_NUM_NODES * sizeof(float), 64);
    
    // Initialize
    InitializeMatrix(Q, TEST_NUM_NODES, TEST_HEAD_DIM, 42);
    InitializeMatrix(K, TEST_NUM_NODES, TEST_HEAD_DIM, 43);
    InitializeMatrix(V, TEST_NUM_NODES, TEST_HEAD_DIM, 44);
    
    // Warmup
    printf("Warming up...\n");
    for (uint32_t i = 0; i < 100; i++) {
        Forward_Dense(Q, K, V, output_dense, scores, TEST_NUM_NODES, TEST_HEAD_DIM);
        Forward_Sparse(Q, K, V, output_sparse, scores, edges, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    // Benchmark Dense
    printf("\nBenchmarking DENSE (256 entries)...\n");
    auto start_dense = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        Forward_Dense(Q, K, V, output_dense, scores, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    auto end_dense = std::chrono::high_resolution_clock::now();
    auto duration_dense = std::chrono::duration_cast<std::chrono::nanoseconds>(end_dense - start_dense).count();
    
    // Benchmark Sparse
    printf("Benchmarking SPARSE (%zu entries)...\n", edges.size());
    auto start_sparse = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        Forward_Sparse(Q, K, V, output_sparse, scores, edges, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    auto end_sparse = std::chrono::high_resolution_clock::now();
    auto duration_sparse = std::chrono::duration_cast<std::chrono::nanoseconds>(end_sparse - start_sparse).count();
    
    // Calculate statistics
    double time_dense_us = duration_dense / 1e3 / TEST_ITERATIONS;
    double time_sparse_us = duration_sparse / 1e3 / TEST_ITERATIONS;
    double speedup = time_dense_us / time_sparse_us;
    
    // Verify correctness
    float max_diff = 0.0f;
    for (uint32_t i = 0; i < TEST_NUM_NODES * TEST_HEAD_DIM; i++) {
        float diff = std::abs(output_dense[i] - output_sparse[i]);
        if (diff > max_diff) max_diff = diff;
    }
    
    // Print results
    printf("\n");
    printf("=== VAL-037 Results ===\n");
    printf("  Dense (256 entries):  %.2f us\n", time_dense_us);
    printf("  Sparse (%zu entries):   %.2f us\n", edges.size(), time_sparse_us);
    printf("  Speedup:              %.2fx\n", speedup);
    printf("  Max diff:             %.6f\n", max_diff);
    printf("\n");
    
    // Target comparison
    printf("=== Target Comparison ===\n");
    printf("  Target: 0.50 us\n");
    printf("  Current (sparse): %.2f us\n", time_sparse_us);
    printf("  Gap to target: %.1fx\n", time_sparse_us / 0.50);
    printf("\n");
    
    // Cleanup
    _aligned_free(Q);
    _aligned_free(K);
    _aligned_free(V);
    _aligned_free(output_dense);
    _aligned_free(output_sparse);
    _aligned_free(scores);
    
    return 0;
}
