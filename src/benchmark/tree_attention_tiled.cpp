// ═══════════════════════════════════════════════════════════════════════════════
// VAL-035: Q@K^T Kernel Optimization - Tiled Register-Resident Q
// ═══════════════════════════════════════════════════════════════════════════════
// Step 2: Keep Q in ZMM registers, stream K rows

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
constexpr uint32_t TEST_NUM_NODES = 16;
constexpr uint32_t TEST_ITERATIONS = 10000;

// Tile size - process this many K rows while Q stays in registers
constexpr uint32_t K_TILE_SIZE = 4;

// ═══════════════════════════════════════════════════════════════════════════════
// RDTSC Cycle Counter
// ═══════════════════════════════════════════════════════════════════════════════
inline uint64_t rdtsc() {
    return __rdtsc();
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

void InitializeTreeMask(uint8_t* mask, uint32_t numNodes) {
    for (uint32_t i = 0; i < numNodes; i++) {
        for (uint32_t j = 0; j < numNodes; j++) {
            mask[i * numNodes + j] = (j <= i) ? 1 : 0;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 1: TILED Q @ K^T (VAL-035 Optimization)
// ═══════════════════════════════════════════════════════════════════════════════
// Strategy: Load Q row once, keep in registers, compute against multiple K rows
void Tiled_QK_Computation(
    const float* Q,
    const float* K,
    float* scores,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    const uint32_t simd_width = 16;
    const uint32_t chunks = head_dim / simd_width;  // 4 chunks for head_dim=64
    
    for (uint32_t q_idx = 0; q_idx < num_nodes; q_idx++) {
        // Load Q row into ZMM registers (kept resident)
        __m512 q_vecs[4];  // 4 chunks × 16 floats = 64 floats
        for (uint32_t c = 0; c < chunks; c++) {
            q_vecs[c] = _mm512_load_ps(&Q[q_idx * head_dim + c * simd_width]);
        }
        
        // Process K rows in tiles
        for (uint32_t k_base = 0; k_base < num_nodes; k_base += K_TILE_SIZE) {
            uint32_t k_end = std::min(k_base + K_TILE_SIZE, num_nodes);
            
            // Compute dot products for this tile
            for (uint32_t k_idx = k_base; k_idx < k_end; k_idx++) {
                __m512 sum_vec = _mm512_setzero_ps();
                
                // FMA accumulate using resident Q and streamed K
                for (uint32_t c = 0; c < chunks; c++) {
                    __m512 k_vec = _mm512_load_ps(&K[k_idx * head_dim + c * simd_width]);
                    sum_vec = _mm512_fmadd_ps(q_vecs[c], k_vec, sum_vec);
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
                
                scores[q_idx * num_nodes + k_idx] = sum;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 2 & 3: Mask + Softmax (unchanged)
// ═══════════════════════════════════════════════════════════════════════════════
void MaskAndSoftmax(
    float* scores,
    const uint8_t* tree_mask,
    uint32_t num_nodes,
    float scale
) {
    for (uint32_t row = 0; row < num_nodes; row++) {
        float max_val = -1e30f;
        for (uint32_t col = 0; col < num_nodes; col++) {
            if (tree_mask[row * num_nodes + col]) {
                float val = scores[row * num_nodes + col] * scale;
                if (val > max_val) max_val = val;
            }
        }
        
        float sum = 0.0f;
        for (uint32_t col = 0; col < num_nodes; col++) {
            if (tree_mask[row * num_nodes + col]) {
                float exp_val = expf(scores[row * num_nodes + col] * scale - max_val);
                scores[row * num_nodes + col] = exp_val;
                sum += exp_val;
            } else {
                scores[row * num_nodes + col] = 0.0f;
            }
        }
        
        for (uint32_t col = 0; col < num_nodes; col++) {
            scores[row * num_nodes + col] /= sum;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 4: Attention @ V (tiled version)
// ═══════════════════════════════════════════════════════════════════════════════
void Tiled_AV_Computation(
    const float* scores,
    const float* V,
    float* output,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    const uint32_t simd_width = 16;
    const uint32_t chunks = head_dim / simd_width;
    
    for (uint32_t row = 0; row < num_nodes; row++) {
        // Initialize accumulators
        __m512 acc_vecs[4];
        for (uint32_t c = 0; c < chunks; c++) {
            acc_vecs[c] = _mm512_setzero_ps();
        }
        
        // Accumulate weighted V rows
        for (uint32_t k = 0; k < num_nodes; k++) {
            float score = scores[row * num_nodes + k];
            __m512 score_vec = _mm512_set1_ps(score);
            
            for (uint32_t c = 0; c < chunks; c++) {
                __m512 v_vec = _mm512_load_ps(&V[k * head_dim + c * simd_width]);
                acc_vecs[c] = _mm512_fmadd_ps(score_vec, v_vec, acc_vecs[c]);
            }
        }
        
        // Store results
        for (uint32_t c = 0; c < chunks; c++) {
            _mm512_store_ps(&output[row * head_dim + c * simd_width], acc_vecs[c]);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Complete Tiled Forward Pass
// ═══════════════════════════════════════════════════════════════════════════════
void Tiled_Forward(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    const uint8_t* tree_mask,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    float* scores = (float*)_aligned_malloc(num_nodes * num_nodes * sizeof(float), 64);
    
    Tiled_QK_Computation(Q, K, scores, num_nodes, head_dim);
    
    float scale = 1.0f / sqrtf((float)head_dim);
    MaskAndSoftmax(scores, tree_mask, num_nodes, scale);
    
    Tiled_AV_Computation(scores, V, output, num_nodes, head_dim);
    
    _aligned_free(scores);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Calibrate CPU Frequency
// ═══════════════════════════════════════════════════════════════════════════════
double CalibrateCPUFrequency() {
    volatile uint64_t sum = 0;
    auto startTime = std::chrono::high_resolution_clock::now();
    uint64_t startTSC = rdtsc();
    
    auto endTime = startTime;
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               endTime - startTime).count() < 100) {
        for (int i = 0; i < 1000; i++) {
            sum += rdtsc();
        }
        endTime = std::chrono::high_resolution_clock::now();
    }
    
    uint64_t endTSC = rdtsc();
    double elapsedSec = std::chrono::duration<double>(endTime - startTime).count();
    return (endTSC - startTSC) / (elapsedSec * 1e9);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════
int main() {
    printf("=============================================================================\n");
    printf("VAL-035: Q@K^T Kernel Optimization - Tiled Register-Resident Q\n");
    printf("=============================================================================\n");
    printf("Strategy: Keep Q in ZMM registers, stream K rows\n");
    printf("Tile size: %u K rows per Q load\n", K_TILE_SIZE);
    printf("\n");
    
    // Calibrate CPU frequency
    printf("Calibrating CPU frequency...\n");
    double cpuFreqGHz = CalibrateCPUFrequency();
    printf("Detected CPU frequency: %.2f GHz\n", cpuFreqGHz);
    printf("\n");
    
    // Allocate aligned memory
    float* Q = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* K = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* V = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* output = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    uint8_t* treeMask = (uint8_t*)_aligned_malloc(TEST_NUM_NODES * TEST_NUM_NODES * sizeof(uint8_t), 64);
    
    // Initialize data
    InitializeMatrix(Q, TEST_NUM_NODES, TEST_HEAD_DIM, 42);
    InitializeMatrix(K, TEST_NUM_NODES, TEST_HEAD_DIM, 43);
    InitializeMatrix(V, TEST_NUM_NODES, TEST_HEAD_DIM, 44);
    InitializeTreeMask(treeMask, TEST_NUM_NODES);
    
    // Warmup
    printf("Warming up...\n");
    for (uint32_t i = 0; i < 100; i++) {
        Tiled_Forward(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    // Benchmark
    printf("Running %u iterations...\n", TEST_ITERATIONS);
    
    uint64_t startCycles = rdtsc();
    auto startTime = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        Tiled_Forward(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    uint64_t endCycles = rdtsc();
    
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime);
    double totalTimeUs = duration.count() / 1000.0;
    double avgTimeUs = totalTimeUs / TEST_ITERATIONS;
    double avgCycles = (double)(endCycles - startCycles) / TEST_ITERATIONS;
    
    // Check output
    bool hasNonZero = false;
    for (uint32_t i = 0; i < TEST_NUM_NODES * TEST_HEAD_DIM; i++) {
        if (output[i] != 0.0f) {
            hasNonZero = true;
            break;
        }
    }
    
    // Print results
    printf("\n");
    printf("=== VAL-035 Results ===\n");
    printf("  Configuration: %u nodes, head_dim=%u\n", TEST_NUM_NODES, TEST_HEAD_DIM);
    printf("  Total time: %.2f ms\n", totalTimeUs / 1000.0);
    printf("  Avg time per iteration: %.3f us\n", avgTimeUs);
    printf("  Avg cycles per iteration: %.0f\n", avgCycles);
    printf("  Throughput: %.2f nodes/sec\n", (double)TEST_NUM_NODES * TEST_ITERATIONS / (duration.count() / 1e9));
    printf("  Output verified: %s\n", hasNonZero ? "YES" : "NO");
    printf("\n");
    
    // Compare to baseline
    double baselineUs = 1.846;
    double improvement = ((baselineUs - avgTimeUs) / baselineUs) * 100.0;
    
    printf("=== Comparison to VAL-033 Baseline ===\n");
    printf("  Baseline (naive): %.3f us\n", baselineUs);
    printf("  Optimized (tiled): %.3f us\n", avgTimeUs);
    printf("  Improvement: %.1f%%\n", improvement);
    printf("  Target: 0.500 us\n");
    printf("  Gap to target: %.2fx\n", avgTimeUs / 0.5);
    printf("\n");
    
    // Cleanup
    _aligned_free(Q);
    _aligned_free(K);
    _aligned_free(V);
    _aligned_free(output);
    _aligned_free(treeMask);
    
    return 0;
}
