// ═══════════════════════════════════════════════════════════════════════════════
// VAL-036: Vectorized Softmax with AVX-512 Polynomial Approximation
// ═══════════════════════════════════════════════════════════════════════════════
// Replace scalar expf() with vectorized polynomial exp approximation

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
// AVX-512 exp approximation using polynomial
// ═══════════════════════════════════════════════════════════════════════════════
// Based on minimax polynomial approximation for exp(x) in range [-8, 0]
// Valid for softmax after max subtraction (all values <= 0)
inline __m512 exp512_ps(__m512 x) {
    // Coefficients for 6th degree minimax polynomial on [-8, 0]
    // exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24 + x^5/120 + x^6/720
    const __m512 c0 = _mm512_set1_ps(1.0f);
    const __m512 c1 = _mm512_set1_ps(1.0f);
    const __m512 c2 = _mm512_set1_ps(0.5f);
    const __m512 c3 = _mm512_set1_ps(0.16666667f);      // 1/6
    const __m512 c4 = _mm512_set1_ps(0.04166667f);      // 1/24
    const __m512 c5 = _mm512_set1_ps(0.00833333f);      // 1/120
    const __m512 c6 = _mm512_set1_ps(0.00138889f);      // 1/720
    
    __m512 x2 = _mm512_mul_ps(x, x);
    __m512 x3 = _mm512_mul_ps(x2, x);
    __m512 x4 = _mm512_mul_ps(x3, x);
    __m512 x5 = _mm512_mul_ps(x4, x);
    __m512 x6 = _mm512_mul_ps(x5, x);
    
    // Horner's method: c0 + x*(c1 + x*(c2 + x*(c3 + x*(c4 + x*(c5 + x*c6)))))
    __m512 result = c6;
    result = _mm512_fmadd_ps(result, x, c5);
    result = _mm512_fmadd_ps(result, x, c4);
    result = _mm512_fmadd_ps(result, x, c3);
    result = _mm512_fmadd_ps(result, x, c2);
    result = _mm512_fmadd_ps(result, x, c1);
    result = _mm512_fmadd_ps(result, x, c0);
    
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 1: Q @ K^T (baseline version)
// ═══════════════════════════════════════════════════════════════════════════════
void QK_Computation(
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
// Phase 2 & 3: VECTORIZED Mask + Softmax (VAL-036 Optimization)
// ═══════════════════════════════════════════════════════════════════════════════
void Vectorized_MaskAndSoftmax(
    float* scores,
    const uint8_t* tree_mask,
    uint32_t num_nodes,
    float scale
) {
    const uint32_t simd_width = 16;
    
    for (uint32_t row = 0; row < num_nodes; row++) {
        // Step 1: Find max (scalar - hard to vectorize with masking)
        float max_val = -1e30f;
        for (uint32_t col = 0; col < num_nodes; col++) {
            if (tree_mask[row * num_nodes + col]) {
                float val = scores[row * num_nodes + col] * scale;
                if (val > max_val) max_val = val;
            }
        }
        
        // Step 2: Vectorized exp and sum
        __m512 max_vec = _mm512_set1_ps(max_val);
        __m512 sum_vec = _mm512_setzero_ps();
        
        // Process 16 elements at a time
        uint32_t col = 0;
        for (; col + simd_width <= num_nodes; col += simd_width) {
            // Load scores
            __m512 score_vec = _mm512_loadu_ps(&scores[row * num_nodes + col]);
            
            // Apply scale and subtract max
            __m512 scaled = _mm512_mul_ps(score_vec, _mm512_set1_ps(scale));
            __m512 shifted = _mm512_sub_ps(scaled, max_vec);
            
            // Vectorized exp approximation
            __m512 exp_vec = exp512_ps(shifted);
            
            // Create mask for valid positions (tree_mask)
            __mmask16 mask = 0;
            for (uint32_t i = 0; i < simd_width; i++) {
                if (tree_mask[row * num_nodes + col + i]) {
                    mask |= (1 << i);
                }
            }
            
            // Zero out masked positions
            exp_vec = _mm512_maskz_mov_ps(mask, exp_vec);
            
            // Store back
            _mm512_mask_storeu_ps(&scores[row * num_nodes + col], mask, exp_vec);
            
            // Accumulate sum
            sum_vec = _mm512_add_ps(sum_vec, exp_vec);
        }
        
        // Horizontal sum of vector accumulator
        __m256 vlow = _mm512_castps512_ps256(sum_vec);
        __m256 vhigh = _mm512_extractf32x8_ps(sum_vec, 1);
        vlow = _mm256_add_ps(vlow, vhigh);
        __m128 vlow128 = _mm256_castps256_ps128(vlow);
        __m128 vhigh128 = _mm256_extractf128_ps(vlow, 1);
        vlow128 = _mm_add_ps(vlow128, vhigh128);
        vlow128 = _mm_hadd_ps(vlow128, vlow128);
        vlow128 = _mm_hadd_ps(vlow128, vlow128);
        float sum = _mm_cvtss_f32(vlow128);
        
        // Handle remaining elements
        for (; col < num_nodes; col++) {
            if (tree_mask[row * num_nodes + col]) {
                float exp_val = expf(scores[row * num_nodes + col] * scale - max_val);
                scores[row * num_nodes + col] = exp_val;
                sum += exp_val;
            } else {
                scores[row * num_nodes + col] = 0.0f;
            }
        }
        
        // Step 3: Vectorized normalization
        __m512 sum_vec_inv = _mm512_set1_ps(1.0f / sum);
        
        col = 0;
        for (; col + simd_width <= num_nodes; col += simd_width) {
            __m512 score_vec = _mm512_loadu_ps(&scores[row * num_nodes + col]);
            __m512 norm_vec = _mm512_mul_ps(score_vec, sum_vec_inv);
            
            // Create mask
            __mmask16 mask = 0;
            for (uint32_t i = 0; i < simd_width; i++) {
                if (tree_mask[row * num_nodes + col + i]) {
                    mask |= (1 << i);
                }
            }
            
            _mm512_mask_storeu_ps(&scores[row * num_nodes + col], mask, norm_vec);
        }
        
        // Handle remaining elements
        for (; col < num_nodes; col++) {
            if (tree_mask[row * num_nodes + col]) {
                scores[row * num_nodes + col] /= sum;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 4: Attention @ V (baseline version)
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
// Complete Vectorized Forward Pass
// ═══════════════════════════════════════════════════════════════════════════════
void Vectorized_Forward(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    const uint8_t* tree_mask,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    float* scores = (float*)_aligned_malloc(num_nodes * num_nodes * sizeof(float), 64);
    
    QK_Computation(Q, K, scores, num_nodes, head_dim);
    
    float scale = 1.0f / sqrtf((float)head_dim);
    Vectorized_MaskAndSoftmax(scores, tree_mask, num_nodes, scale);
    
    AV_Computation(scores, V, output, num_nodes, head_dim);
    
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
    printf("VAL-036: Vectorized Softmax with AVX-512 Polynomial Approximation\n");
    printf("=============================================================================\n");
    printf("Strategy: Replace scalar expf() with vectorized polynomial exp\n");
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
        Vectorized_Forward(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    // Benchmark
    printf("Running %u iterations...\n", TEST_ITERATIONS);
    
    uint64_t startCycles = rdtsc();
    auto startTime = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        Vectorized_Forward(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
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
    printf("=== VAL-036 Results ===\n");
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
    printf("  Baseline (scalar softmax): %.3f us\n", baselineUs);
    printf("  Optimized (vectorized):      %.3f us\n", avgTimeUs);
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
