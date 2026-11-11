// ═══════════════════════════════════════════════════════════════════════════════
// VAL-032: Simple Tree Attention Benchmark
// ═══════════════════════════════════════════════════════════════════════════════
// Measures actual AVX-512 performance using intrinsics

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>
#include <cmath>

// External functions from intrinsics implementation
extern "C" {
    void TreeAttention_Forward_AVX512(
        const float* Q,
        const float* K,
        const float* V,
        float* output,
        const uint8_t* tree_mask,
        uint32_t num_nodes,
        uint32_t head_dim
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test Configuration
// ═══════════════════════════════════════════════════════════════════════════════
constexpr uint32_t TEST_HEAD_DIM = 64;      // Standard head dimension
constexpr uint32_t TEST_NUM_NODES = 16;     // 4x4 tree = 16 nodes
constexpr uint32_t TEST_ITERATIONS = 10000; // Number of iterations for timing

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
    // Causal mask: node i can attend to nodes j where j <= i
    for (uint32_t i = 0; i < numNodes; i++) {
        for (uint32_t j = 0; j < numNodes; j++) {
            mask[i * numNodes + j] = (j <= i) ? 1 : 0;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main Benchmark
// ═══════════════════════════════════════════════════════════════════════════════
int main() {
    printf("=============================================================================\n");
    printf("VAL-032: Tree Attention AVX-512 Benchmark (Intrinsics)\n");
    printf("=============================================================================\n");
    printf("\n");
    printf("Configuration:\n");
    printf("  Nodes: %u (4x4 tree)\n", TEST_NUM_NODES);
    printf("  Head Dim: %u\n", TEST_HEAD_DIM);
    printf("  Iterations: %u\n", TEST_ITERATIONS);
    printf("\n");
    
    // Allocate aligned memory for AVX-512
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
        TreeAttention_Forward_AVX512(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    // Benchmark
    printf("Running benchmark...\n");
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < TEST_ITERATIONS; i++) {
        TreeAttention_Forward_AVX512(Q, K, V, output, treeMask, TEST_NUM_NODES, TEST_HEAD_DIM);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    
    // Calculate statistics
    double totalTimeMs = duration.count() / 1e6;
    double avgTimeUs = duration.count() / 1e3 / TEST_ITERATIONS;
    double throughputNodesPerSec = (double)TEST_NUM_NODES * TEST_ITERATIONS / (duration.count() / 1e9);
    
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
    printf("=== Results ===\n");
    printf("  Total time: %.2f ms\n", totalTimeMs);
    printf("  Avg time per iteration: %.2f us\n", avgTimeUs);
    printf("  Throughput: %.2f nodes/sec\n", throughputNodesPerSec);
    printf("  Output has non-zero values: %s\n", hasNonZero ? "YES" : "NO");
    printf("\n");
    
    // Compare to target
    double targetTimeUs = 500.0; // 500ns target
    printf("=== Target Comparison ===\n");
    printf("  Target: %.2f us\n", targetTimeUs / 1000.0);
    printf("  Actual: %.2f us\n", avgTimeUs);
    printf("  Status: %s\n", (avgTimeUs <= targetTimeUs / 1000.0) ? "PASS" : "FAIL");
    printf("\n");
    
    // Cleanup
    _aligned_free(Q);
    _aligned_free(K);
    _aligned_free(V);
    _aligned_free(output);
    _aligned_free(treeMask);
    
    return 0;
}
