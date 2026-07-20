// ═══════════════════════════════════════════════════════════════════════════════
// VAL-033: TreeAttention Profiling Instrumentation
// ═══════════════════════════════════════════════════════════════════════════════
// Measures per-stage timings using RDTSC cycle counters

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>
#include <cmath>
#include <immintrin.h>
#include <intrin.h>  // For __rdtsc on MSVC

// ═══════════════════════════════════════════════════════════════════════════════
// RDTSC Cycle Counter
// ═══════════════════════════════════════════════════════════════════════════════
inline uint64_t rdtsc() {
    return __rdtsc();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Profile Statistics
// ═══════════════════════════════════════════════════════════════════════════════
struct ProfileStats {
    const char* name;
    uint64_t totalCycles;
    uint64_t minCycles;
    uint64_t maxCycles;
    uint64_t count;
    
    void reset() {
        totalCycles = 0;
        minCycles = UINT64_MAX;
        maxCycles = 0;
        count = 0;
    }
    
    void add(uint64_t cycles) {
        totalCycles += cycles;
        if (cycles < minCycles) minCycles = cycles;
        if (cycles > maxCycles) maxCycles = cycles;
        count++;
    }
    
    double avg() const {
        return count > 0 ? (double)totalCycles / count : 0.0;
    }
    
    double avgUs(double freqGHz) const {
        return avg() / (freqGHz * 1000.0);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Global Profile Data
// ═══════════════════════════════════════════════════════════════════════════════
ProfileStats statsQK = {"Q@K^T (FMA)", 0, UINT64_MAX, 0, 0};
ProfileStats statsMask = {"Tree Mask", 0, UINT64_MAX, 0, 0};
ProfileStats statsSoftmax = {"Softmax", 0, UINT64_MAX, 0, 0};
ProfileStats statsAV = {"A@V (FMA)", 0, UINT64_MAX, 0, 0};
ProfileStats statsTotal = {"Total", 0, UINT64_MAX, 0, 0};

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

void InitializeTreeMask(uint8_t* mask, uint32_t numNodes) {
    for (uint32_t i = 0; i < numNodes; i++) {
        for (uint32_t j = 0; j < numNodes; j++) {
            mask[i * numNodes + j] = (j <= i) ? 1 : 0;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 1: Q @ K^T with profiling
// ═══════════════════════════════════════════════════════════════════════════════
void Profiled_QK_Computation(
    const float* Q,
    const float* K,
    float* scores,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    uint64_t start = rdtsc();
    
    const uint32_t simd_width = 16;
    
    for (uint32_t q_idx = 0; q_idx < num_nodes; q_idx++) {
        for (uint32_t k_idx = 0; k_idx < num_nodes; k_idx++) {
            __m512 sum_vec = _mm512_setzero_ps();
            
            uint32_t d = 0;
            for (; d + simd_width <= head_dim; d += simd_width) {
                __m512 q_vec = _mm512_loadu_ps(&Q[q_idx * head_dim + d]);
                __m512 k_vec = _mm512_loadu_ps(&K[k_idx * head_dim + d]);
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
    
    uint64_t end = rdtsc();
    statsQK.add(end - start);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 2 & 3: Mask + Softmax with profiling
// ═══════════════════════════════════════════════════════════════════════════════
void Profiled_MaskAndSoftmax(
    float* scores,
    const uint8_t* tree_mask,
    uint32_t num_nodes,
    float scale
) {
    uint64_t start = rdtsc();
    
    for (uint32_t row = 0; row < num_nodes; row++) {
        // Find max for numerical stability
        float max_val = -1e30f;
        for (uint32_t col = 0; col < num_nodes; col++) {
            if (tree_mask[row * num_nodes + col]) {
                float val = scores[row * num_nodes + col] * scale;
                if (val > max_val) max_val = val;
            }
        }
        
        // Compute exp and sum
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
        
        // Normalize
        for (uint32_t col = 0; col < num_nodes; col++) {
            scores[row * num_nodes + col] /= sum;
        }
    }
    
    uint64_t end = rdtsc();
    statsSoftmax.add(end - start);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 4: Attention @ V with profiling
// ═══════════════════════════════════════════════════════════════════════════════
void Profiled_AV_Computation(
    const float* scores,
    const float* V,
    float* output,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    uint64_t start = rdtsc();
    
    const uint32_t simd_width = 16;
    
    for (uint32_t row = 0; row < num_nodes; row++) {
        uint32_t d = 0;
        for (; d + simd_width <= head_dim; d += simd_width) {
            __m512 sum_vec = _mm512_setzero_ps();
            
            for (uint32_t k = 0; k < num_nodes; k++) {
                float score = scores[row * num_nodes + k];
                __m512 score_vec = _mm512_set1_ps(score);
                __m512 v_vec = _mm512_loadu_ps(&V[k * head_dim + d]);
                sum_vec = _mm512_fmadd_ps(score_vec, v_vec, sum_vec);
            }
            
            _mm512_storeu_ps(&output[row * head_dim + d], sum_vec);
        }
        
        // Handle remaining elements
        for (; d < head_dim; d++) {
            float sum = 0.0f;
            for (uint32_t k = 0; k < num_nodes; k++) {
                sum += scores[row * num_nodes + k] * V[k * head_dim + d];
            }
            output[row * head_dim + d] = sum;
        }
    }
    
    uint64_t end = rdtsc();
    statsAV.add(end - start);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Complete Profiled Forward Pass
// ═══════════════════════════════════════════════════════════════════════════════
void Profiled_Forward(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    const uint8_t* tree_mask,
    uint32_t num_nodes,
    uint32_t head_dim
) {
    float* scores = (float*)_aligned_malloc(num_nodes * num_nodes * sizeof(float), 64);
    
    uint64_t startTotal = rdtsc();
    
    Profiled_QK_Computation(Q, K, scores, num_nodes, head_dim);
    
    float scale = 1.0f / sqrtf((float)head_dim);
    Profiled_MaskAndSoftmax(scores, tree_mask, num_nodes, scale);
    
    Profiled_AV_Computation(scores, V, output, num_nodes, head_dim);
    
    uint64_t endTotal = rdtsc();
    statsTotal.add(endTotal - startTotal);
    
    _aligned_free(scores);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Print Profile Report
// ═══════════════════════════════════════════════════════════════════════════════
void PrintProfileReport(double cpuFreqGHz) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                    VAL-033: PROFILE REPORT                                   ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ Phase              │ Avg (cycles) │ Avg (µs)   │ Min (µs)   │ Max (µs)   │ %% Total ║\n");
    printf("╠════════════════════╪══════════════╪════════════╪════════════╪════════════╪══════════╣\n");
    
    auto printStat = [cpuFreqGHz](const ProfileStats& s, double totalCycles) {
        double avgUs = s.avg() / (cpuFreqGHz * 1000.0);
        double minUs = s.minCycles / (cpuFreqGHz * 1000.0);
        double maxUs = s.maxCycles / (cpuFreqGHz * 1000.0);
        double pct = totalCycles > 0 ? (s.totalCycles / totalCycles) * 100.0 : 0.0;
        
        printf("║ %-18s │ %12.0f │ %10.3f │ %10.3f │ %10.3f │ %7.1f%% ║\n",
               s.name, s.avg(), avgUs, minUs, maxUs, pct);
    };
    
    double totalCycles = statsTotal.totalCycles;
    printStat(statsQK, totalCycles);
    printStat(statsSoftmax, totalCycles);
    printStat(statsAV, totalCycles);
    
    printf("╠════════════════════╪══════════════╪════════════╪════════════╪════════════╪══════════╣\n");
    printStat(statsTotal, totalCycles);
    
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("CPU Frequency: %.2f GHz\n", cpuFreqGHz);
    printf("Target: 500 ns (%.0f cycles @ %.2f GHz)\n", 500.0 * cpuFreqGHz / 1000.0, cpuFreqGHz);
    printf("\n");
    
    // Identify bottleneck
    printf("BOTTLENECK ANALYSIS:\n");
    if (statsSoftmax.totalCycles > statsQK.totalCycles && 
        statsSoftmax.totalCycles > statsAV.totalCycles) {
        printf("  → Softmax is the PRIMARY bottleneck (%.1f%% of total)\n", 
               (statsSoftmax.totalCycles / totalCycles) * 100.0);
        printf("  → Recommendation: Vectorize softmax, use exp approximation\n");
    } else if (statsQK.totalCycles > statsAV.totalCycles) {
        printf("  → Q@K^T is the PRIMARY bottleneck (%.1f%% of total)\n",
               (statsQK.totalCycles / totalCycles) * 100.0);
        printf("  → Recommendation: Align memory, unroll loops\n");
    } else {
        printf("  → A@V is the PRIMARY bottleneck (%.1f%% of total)\n",
               (statsAV.totalCycles / totalCycles) * 100.0);
        printf("  → Recommendation: Optimize memory access pattern\n");
    }
    
    // Check for unaccounted time
    double accountedCycles = statsQK.totalCycles + statsSoftmax.totalCycles + statsAV.totalCycles;
    double unaccountedPct = ((totalCycles - accountedCycles) / totalCycles) * 100.0;
    if (unaccountedPct > 5.0) {
        printf("  → WARNING: %.1f%% of time unaccounted for (memory allocation, overhead)\n", unaccountedPct);
    }
    printf("\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Calibrate CPU Frequency
// ═══════════════════════════════════════════════════════════════════════════════
double CalibrateCPUFrequency() {
    // Warm up
    for (int i = 0; i < 1000; i++) {
        __rdtsc();
    }
    
    // Measure RDTSC over a known time interval
    auto startTime = std::chrono::high_resolution_clock::now();
    uint64_t startTSC = rdtsc();
    
    // Spin for ~100ms
    volatile uint64_t sum = 0;
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
    double freqGHz = (endTSC - startTSC) / (elapsedSec * 1e9);
    
    return freqGHz;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════
int main() {
    printf("=============================================================================\n");
    printf("VAL-033: TreeAttention Profiling Instrumentation\n");
    printf("=============================================================================\n");
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
    
    // Reset stats
    statsQK.reset();
    statsSoftmax.reset();
    statsAV.reset();
    statsTotal.reset();
    
    // Warmup
    printf("Warming up...\n");
    for (uint32_t i = 0; i < 100; i++) {
        Profiled_Forward(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    // Reset stats after warmup
    statsQK.reset();
    statsMask.reset();
    statsSoftmax.reset();
    statsAV.reset();
    statsTotal.reset();
    
    // Benchmark
    printf("Running %u iterations...\n", TEST_ITERATIONS);
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        Profiled_Forward(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    // Print report
    PrintProfileReport(cpuFreqGHz);
    
    // Cleanup
    _aligned_free(Q);
    _aligned_free(K);
    _aligned_free(V);
    _aligned_free(output);
    _aligned_free(treeMask);
    
    return 0;
}
