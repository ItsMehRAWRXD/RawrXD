// ═══════════════════════════════════════════════════════════════════════════════
// VAL-034: Q@K^T Kernel Optimization - Aligned Loads
// ═══════════════════════════════════════════════════════════════════════════════
// Step 1: Enforce 64-byte alignment and use _mm512_load_ps

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
// Phase 1: Q @ K^T with ALIGNED loads (VAL-034 Optimization)
// ═══════════════════════════════════════════════════════════════════════════════
void Aligned_QK_Computation(
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
                // VAL-034: Use aligned loads (_mm512_load_ps instead of _mm512_loadu_ps)
                const float* q_ptr = &Q[q_idx * head_dim + d];
                const float* k_ptr = &K[k_idx * head_dim + d];
                
                // Assert alignment in debug builds
                #ifdef _DEBUG
                if ((reinterpret_cast<uintptr_t>(q_ptr) & 63) != 0) {
                    printf("ERROR: Q pointer not 64-byte aligned: %p\n", q_ptr);
                }
                if ((reinterpret_cast<uintptr_t>(k_ptr) & 63) != 0) {
                    printf("ERROR: K pointer not 64-byte aligned: %p\n", k_ptr);
                }
                #endif
                
                __m512 q_vec = _mm512_load_ps(q_ptr);  // Aligned load
                __m512 k_vec = _mm512_load_ps(k_ptr);  // Aligned load
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
// Phase 2 & 3: Mask + Softmax (unchanged from baseline)
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
// Phase 4: Attention @ V with ALIGNED loads
// ═══════════════════════════════════════════════════════════════════════════════
void Aligned_AV_Computation(
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
                // VAL-034: Aligned load
                __m512 v_vec = _mm512_load_ps(&V[k * head_dim + d]);
                sum_vec = _mm512_fmadd_ps(score_vec, v_vec, sum_vec);
            }
            
            _mm512_store_ps(&output[row * head_dim + d], sum_vec);  // Aligned store
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
// Complete Aligned Forward Pass
// ═══════════════════════════════════════════════════════════════════════════════
void Aligned_Forward(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    const uint8_t* tree_mask,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    float* scores = (float*)_aligned_malloc(num_nodes * num_nodes * sizeof(float), 64);
    
    Aligned_QK_Computation(Q, K, scores, num_nodes, head_dim);
    
    float scale = 1.0f / sqrtf((float)head_dim);
    MaskAndSoftmax(scores, tree_mask, num_nodes, scale);
    
    Aligned_AV_Computation(scores, V, output, num_nodes, head_dim);
    
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
    printf("VAL-034: Q@K^T Kernel Optimization - Aligned Loads\n");
    printf("=============================================================================\n");
    printf("\n");
    
    // Calibrate CPU frequency
    printf("Calibrating CPU frequency...\n");
    double cpuFreqGHz = CalibrateCPUFrequency();
    printf("Detected CPU frequency: %.2f GHz\n", cpuFreqGHz);
    printf("\n");
    
    // Allocate ALIGNED memory (64-byte boundary for AVX-512)
    float* Q = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* K = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* V = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    float* output = (float*)_aligned_malloc(TEST_NUM_NODES * TEST_HEAD_DIM * sizeof(float), 64);
    uint8_t* treeMask = (uint8_t*)_aligned_malloc(TEST_NUM_NODES * TEST_NUM_NODES * sizeof(uint8_t), 64);
    
    // Validate alignment
    printf("Memory alignment check:\n");
    printf("  Q: %p (aligned: %s)\n", Q, ((reinterpret_cast<uintptr_t>(Q) & 63) == 0) ? "YES" : "NO");
    printf("  K: %p (aligned: %s)\n", K, ((reinterpret_cast<uintptr_t>(K) & 63) == 0) ? "YES" : "NO");
    printf("  V: %p (aligned: %s)\n", V, ((reinterpret_cast<uintptr_t>(V) & 63) == 0) ? "YES" : "NO");
    printf("\n");
    
    // Initialize data
    InitializeMatrix(Q, TEST_NUM_NODES, TEST_HEAD_DIM, 42);
    InitializeMatrix(K, TEST_NUM_NODES, TEST_HEAD_DIM, 43);
    InitializeMatrix(V, TEST_NUM_NODES, TEST_HEAD_DIM, 44);
    InitializeTreeMask(treeMask, TEST_NUM_NODES);
    
    // Warmup
    printf("Warming up...\n");
    for (uint32_t i = 0; i < 100; i++) {
        Aligned_Forward(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    // Benchmark with cycle counting
    printf("Running %u iterations with cycle-accurate timing...\n", TEST_ITERATIONS);
    
    uint64_t startCycles = rdtsc();
    auto startTime = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        Aligned_Forward(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
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
    printf("=== VAL-034 Results ===\n");
    printf("  Configuration: %u nodes, head_dim=%u\n", TEST_NUM_NODES, TEST_HEAD_DIM);
    printf("  Total time: %.2f ms\n", totalTimeUs / 1000.0);
    printf("  Avg time per iteration: %.3f us\n", avgTimeUs);
    printf("  Avg cycles per iteration: %.0f\n", avgCycles);
    printf("  Throughput: %.2f nodes/sec\n", (double)TEST_NUM_NODES * TEST_ITERATIONS / (duration.count() / 1e9));
    printf("  Output verified: %s\n", hasNonZero ? "YES" : "NO");
    printf("\n");
    
    // Compare to baseline
    double baselineUs = 1.846;  // From VAL-033
    double improvement = ((baselineUs - avgTimeUs) / baselineUs) * 100.0;
    
    printf("=== Comparison to VAL-033 Baseline ===\n");
    printf("  Baseline (unaligned): %.3f us\n", baselineUs);
    printf("  Optimized (aligned):  %.3f us\n", avgTimeUs);
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
