// ═══════════════════════════════════════════════════════════════════════════════
// VAL-037.1: Fused Online Softmax with Block-Sparse Attention
// ═══════════════════════════════════════════════════════════════════════════════
// Eliminates intermediate tensors: no score buffer, no attention matrix
// Uses online softmax algorithm + block-sparse processing

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>
#include <cmath>
#include <immintrin.h>

// ═══════════════════════════════════════════════════════════════════════════════
// Block-Sparse Tree Structure
// ═══════════════════════════════════════════════════════════════════════════════
constexpr uint32_t BLOCK_SIZE = 4;  // Process 4 nodes at a time

struct TreeEdgeBlock {
    uint16_t q_idx;           // Query node index
    uint16_t k_count;         // Number of valid keys
    uint16_t k_indices[16];   // Key indices (max 16 for 4x4 tree)
};

// Build block-sparse structure for 4x4 tree
void BuildBlockSparseTree(std::vector<TreeEdgeBlock>& blocks, uint32_t num_nodes) {
    blocks.clear();
    
    // For a 4x4 tree with 16 nodes:
    // Level 0: node 0 (root)
    // Level 1: nodes 1-4 (children of root)
    // Level 2: nodes 5-20 (would be 16 nodes, but we have 16 total)
    
    // Simplified: each node can attend to itself and ancestors
    for (uint32_t q = 0; q < num_nodes; q++) {
        TreeEdgeBlock block;
        block.q_idx = q;
        block.k_count = 0;
        
        // Add self
        block.k_indices[block.k_count++] = q;
        
        // Add ancestors (simplified tree structure)
        uint32_t current = q;
        while (current > 0 && block.k_count < 16) {
            // Parent is roughly (current-1)/4 for a 4-ary tree
            uint32_t parent = (current - 1) / 4;
            if (parent < current) {
                block.k_indices[block.k_count++] = parent;
                current = parent;
            } else {
                break;
            }
        }
        
        blocks.push_back(block);
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
// Reference: Masked Dense Baseline (for correctness verification)
// ═══════════════════════════════════════════════════════════════════════════════
void MaskedDense_Forward(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    const std::vector<TreeEdgeBlock>& blocks,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    // Allocate scratch buffers
    float* scores = (float*)_aligned_malloc(num_nodes * num_nodes * sizeof(float), 64);
    
    // Initialize scores to -inf (masked)
    for (uint32_t i = 0; i < num_nodes * num_nodes; i++) {
        scores[i] = -1e30f;
    }
    
    // Q @ K^T (only for valid edges)
    for (const auto& block : blocks) {
        uint32_t q = block.q_idx;
        for (uint32_t ki = 0; ki < block.k_count; ki++) {
            uint32_t k = block.k_indices[ki];
            float sum = 0.0f;
            for (uint32_t d = 0; d < head_dim; d++) {
                sum += Q[q * head_dim + d] * K[k * head_dim + d];
            }
            scores[q * num_nodes + k] = sum;
        }
    }
    
    // Softmax (masked)
    float scale = 1.0f / sqrtf((float)head_dim);
    for (uint32_t row = 0; row < num_nodes; row++) {
        float max_val = -1e30f;
        for (uint32_t col = 0; col < num_nodes; col++) {
            max_val = std::max(max_val, scores[row * num_nodes + col]);
        }
        
        float sum = 0.0f;
        for (uint32_t col = 0; col < num_nodes; col++) {
            if (scores[row * num_nodes + col] > -1e29f) {  // Valid edge
                scores[row * num_nodes + col] = expf((scores[row * num_nodes + col] - max_val) * scale);
                sum += scores[row * num_nodes + col];
            }
        }
        
        for (uint32_t col = 0; col < num_nodes; col++) {
            if (scores[row * num_nodes + col] > -1e29f) {
                scores[row * num_nodes + col] /= sum;
            } else {
                scores[row * num_nodes + col] = 0.0f;
            }
        }
    }
    
    // A @ V
    for (uint32_t row = 0; row < num_nodes; row++) {
        for (uint32_t d = 0; d < head_dim; d++) {
            float sum = 0.0f;
            for (uint32_t k = 0; k < num_nodes; k++) {
                sum += scores[row * num_nodes + k] * V[k * head_dim + d];
            }
            output[row * head_dim + d] = sum;
        }
    }
    
    _aligned_free(scores);
}

// ═══════════════════════════════════════════════════════════════════════════════
// VAL-037.1: Fused Block-Sparse with Online Softmax
// ═══════════════════════════════════════════════════════════════════════════════
void FusedSparse_Forward(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    const std::vector<TreeEdgeBlock>& blocks,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    float scale = 1.0f / sqrtf((float)head_dim);
    const uint32_t simd_width = 16;
    
    // Process each query node's block
    for (const auto& block : blocks) {
        uint32_t q = block.q_idx;
        
        // Online softmax state
        float max_val = -1e30f;
        float exp_sum = 0.0f;
        
        // Accumulators for output (head_dim elements)
        float accum[64];  // Max head_dim
        for (uint32_t d = 0; d < head_dim; d++) {
            accum[d] = 0.0f;
        }
        
        // Process each valid key in the block
        for (uint32_t ki = 0; ki < block.k_count; ki++) {
            uint32_t k = block.k_indices[ki];
            
            // Compute Q[q] @ K[k] (dot product)
            __m512 sum_vec = _mm512_setzero_ps();
            uint32_t d = 0;
            for (; d + simd_width <= head_dim; d += simd_width) {
                __m512 q_vec = _mm512_loadu_ps(&Q[q * head_dim + d]);
                __m512 k_vec = _mm512_loadu_ps(&K[k * head_dim + d]);
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
            float score = _mm_cvtss_f32(vlow128);
            
            for (; d < head_dim; d++) {
                score += Q[q * head_dim + d] * K[k * head_dim + d];
            }
            
            // Scale score
            score *= scale;
            
            // Online softmax update (numerically stable)
            float weight;
            if (score > max_val) {
                // New maximum found - need to rescale previous accumulations
                float scale_factor = expf(max_val - score);  // < 1.0
                for (uint32_t d = 0; d < head_dim; d++) {
                    accum[d] *= scale_factor;
                }
                exp_sum *= scale_factor;
                max_val = score;
                weight = 1.0f;  // exp(0) = 1
            } else {
                weight = expf(score - max_val);  // < 1.0
            }
            
            exp_sum += weight;
            
            // Accumulate weighted V[k] into output
            for (uint32_t d = 0; d < head_dim; d++) {
                accum[d] += weight * V[k * head_dim + d];
            }
        }
        
        // Normalize and store output
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
    printf("VAL-037.1: Fused Online Softmax + Block-Sparse Attention\n");
    printf("=============================================================================\n");
    printf("\n");
    printf("Key optimizations:\n");
    printf("  1. Online softmax (no score buffer)\n");
    printf("  2. Block-sparse processing (compressed edge lists)\n");
    printf("  3. Fused accumulation (no attention matrix)\n");
    printf("  4. Single-pass output computation\n");
    printf("\n");
    
    // Allocate aligned memory
    float* Q = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* K = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* V = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* output_dense = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* output_fused = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    
    // Initialize data
    InitializeMatrix(Q, TEST_NUM_NODES, TEST_HEAD_DIM, 42);
    InitializeMatrix(K, TEST_NUM_NODES, TEST_HEAD_DIM, 43);
    InitializeMatrix(V, TEST_NUM_NODES, TEST_HEAD_DIM, 44);
    
    // Build block-sparse structure
    std::vector<TreeEdgeBlock> blocks;
    BuildBlockSparseTree(blocks, TEST_NUM_NODES);
    
    // Count total edges
    size_t total_edges = 0;
    for (const auto& block : blocks) {
        total_edges += block.k_count;
    }
    
    printf("Configuration:\n");
    printf("  Nodes: %u\n", TEST_NUM_NODES);
    printf("  Head dim: %u\n", TEST_HEAD_DIM);
    printf("  Dense edges: %u\n", TEST_NUM_NODES * TEST_NUM_NODES);
    printf("  Sparse edges: %zu (%.1f%% reduction)\n", total_edges, 
           100.0f * (1.0f - (float)total_edges / (TEST_NUM_NODES * TEST_NUM_NODES)));
    printf("  Iterations: %u\n", TEST_ITERATIONS);
    printf("\n");
    
    // Warmup
    printf("Warming up...\n");
    for (uint32_t i = 0; i < 100; i++) {
        MaskedDense_Forward(Q, K, V, output_dense, blocks, TEST_NUM_NODES, TEST_HEAD_DIM);
        FusedSparse_Forward(Q, K, V, output_fused, blocks, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    // Benchmark Masked Dense
    printf("Benchmarking MASKED DENSE...\n");
    auto start_dense = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        MaskedDense_Forward(Q, K, V, output_dense, blocks, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    auto end_dense = std::chrono::high_resolution_clock::now();
    auto duration_dense = std::chrono::duration_cast<std::chrono::nanoseconds>(end_dense - start_dense).count();
    
    // Benchmark Fused Sparse
    printf("Benchmarking FUSED SPARSE...\n");
    auto start_fused = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        FusedSparse_Forward(Q, K, V, output_fused, blocks, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    auto end_fused = std::chrono::high_resolution_clock::now();
    auto duration_fused = std::chrono::duration_cast<std::chrono::nanoseconds>(end_fused - start_fused).count();
    
    // Calculate results
    double time_dense_us = duration_dense / 1000.0 / TEST_ITERATIONS;
    double time_fused_us = duration_fused / 1000.0 / TEST_ITERATIONS;
    double speedup = time_dense_us / time_fused_us;
    
    // Verify correctness
    float max_diff = 0.0f;
    for (uint32_t i = 0; i < TEST_NUM_NODES * TEST_HEAD_DIM; i++) {
        float diff = std::abs(output_dense[i] - output_fused[i]);
        max_diff = std::max(max_diff, diff);
    }
    bool correct = max_diff < 0.01f;
    
    // Print results
    printf("\n");
    printf("=== VAL-037.1 Results ===\n");
    printf("  Dense (baseline):     %.3f us\n", time_dense_us);
    printf("  Fused Sparse:         %.3f us\n", time_fused_us);
    printf("  Speedup:              %.2fx\n", speedup);
    printf("  Max error vs dense:   %.6f\n", max_diff);
    printf("  Correctness:          %s\n", correct ? "PASS" : "FAIL");
    printf("\n");
    
    printf("=== Target Comparison ===\n");
    printf("  Target:               0.500 us\n");
    printf("  Current (fused):      %.3f us\n", time_fused_us);
    printf("  Gap to target:        %.1fx\n", time_fused_us / 0.5);
    printf("\n");
    
    // Memory traffic analysis
    printf("=== Memory Traffic Reduction ===\n");
    size_t dense_reads = TEST_NUM_NODES * TEST_HEAD_DIM * 3;  // Q, K, V
    size_t dense_writes = TEST_NUM_NODES * TEST_HEAD_DIM;      // output
    size_t dense_scratch = TEST_NUM_NODES * TEST_NUM_NODES * 2; // scores + attention
    size_t dense_total = dense_reads + dense_writes + dense_scratch;
    
    size_t fused_reads = total_edges * TEST_HEAD_DIM / TEST_NUM_NODES * 2 + TEST_NUM_NODES * TEST_HEAD_DIM; // Q, K, V
    size_t fused_writes = TEST_NUM_NODES * TEST_HEAD_DIM;
    size_t fused_scratch = 0;  // No intermediate buffers
    size_t fused_total = fused_reads + fused_writes + fused_scratch;
    
    printf("  Dense memory traffic:  %zu KB/pass\n", dense_total * sizeof(float) / 1024);
    printf("  Fused memory traffic:  %zu KB/pass\n", fused_total * sizeof(float) / 1024);
    printf("  Reduction:             %.1f%%\n", 100.0f * (1.0f - (float)fused_total / dense_total));
    printf("\n");
    
    // Cleanup
    _aligned_free(Q);
    _aligned_free(K);
    _aligned_free(V);
    _aligned_free(output_dense);
    _aligned_free(output_fused);
    
    return 0;
}
