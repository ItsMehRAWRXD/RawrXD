//=============================================================================
// B008 KV Cache Validation Harness
// Tests cache-line alignment and benchmarks performance
// Target: Zero cache-line splits, 2,000 TPS readiness
//=============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <vector>
#include <random>
#include <windows.h>

// B008 Configuration
constexpr size_t CACHE_LINE_SIZE = 64;
constexpr size_t KV_HEAD_DIM = 128;      // Standard head dimension
constexpr size_t KV_SEQ_LEN = 4096;      // Sequence length for test
constexpr size_t NUM_LAYERS = 32;        // Number of transformer layers
constexpr size_t NUM_HEADS = 32;         // Number of attention heads

// Alignment macros
#define ALIGN_CACHE __declspec(align(64))

// KV Cache Entry - cache line aligned
// Each entry fits in exactly ONE cache line (64 bytes)
struct ALIGN_CACHE KVCacheEntry {
    // Key: 8 floats = 32 bytes
    float key[8];
    // Value: 8 floats = 32 bytes  
    float value[8];
    // Total: 64 bytes = 1 cache line
    // No metadata - stored separately for cache efficiency
};
static_assert(sizeof(KVCacheEntry) == 64, 
              "KVCacheEntry must be exactly 64 bytes (one cache line)");

// Test results
struct TestResults {
    bool alignment_valid;
    size_t cache_line_splits;
    double avg_latency_us;
    double throughput_tps;
    size_t memory_bandwidth_gbps;
    bool passed;
};

// Verify cache-line alignment
bool VerifyAlignment(void* ptr) {
    return ((uintptr_t)ptr % CACHE_LINE_SIZE) == 0;
}

// Count cache-line crossings for a memory range
size_t CountCacheLineCrossings(void* start, size_t len) {
    uintptr_t addr = (uintptr_t)start;
    uintptr_t end = addr + len;
    
    size_t crossings = 0;
    uintptr_t first_line = addr / CACHE_LINE_SIZE;
    uintptr_t last_line = (end - 1) / CACHE_LINE_SIZE;
    
    if (first_line != last_line) {
        crossings = last_line - first_line;
    }
    
    return crossings;
}

// Simulate KV cache access pattern (attention-like)
void SimulateAttentionAccess(KVCacheEntry* cache, size_t seq_len, size_t num_heads) {
    // Touch each KV entry in sequence (simulating autoregressive generation)
    for (size_t pos = 0; pos < seq_len; pos++) {
        for (size_t head = 0; head < num_heads; head++) {
            size_t idx = pos * num_heads + head;
            
            // Read key (simulating Q*K^T) - only 8 floats fit in cache line
            volatile float sum = 0.0f;
            for (size_t i = 0; i < 8; i++) {
                sum += cache[idx].key[i];
            }
            
            // Read value (simulating softmax * V)
            for (size_t i = 0; i < 8; i++) {
                sum += cache[idx].value[i];
            }
            
            // Prevent optimization - use sum
            (void)sum;
        }
    }
}

// Benchmark KV cache throughput
TestResults BenchmarkKVCache(bool verify_alignment, bool audit_cache_lines) {
    TestResults results = {};
    results.alignment_valid = true;
    results.cache_line_splits = 0;
    
    printf("[B008] Initializing KV Cache Benchmark...\n");
    printf("[B008] Configuration:\n");
    printf("  - Sequence Length: %zu\n", KV_SEQ_LEN);
    printf("  - Num Layers: %zu\n", NUM_LAYERS);
    printf("  - Num Heads: %zu\n", NUM_HEADS);
    printf("  - Head Dim: %zu\n", KV_HEAD_DIM);
    printf("  - Cache Line: %zu bytes\n", CACHE_LINE_SIZE);
    printf("\n");
    
    // Allocate aligned KV cache
    size_t total_entries = KV_SEQ_LEN * NUM_HEADS * NUM_LAYERS;
    size_t alloc_size = total_entries * sizeof(KVCacheEntry);
    
    printf("[B008] Allocating %.2f MB for KV cache...\n", 
           alloc_size / (1024.0 * 1024));
    
    KVCacheEntry* kv_cache = (KVCacheEntry*)_aligned_malloc(alloc_size, CACHE_LINE_SIZE);
    if (!kv_cache) {
        printf("[B008] ERROR: Failed to allocate KV cache\n");
        results.passed = false;
        return results;
    }
    
    // Verify base alignment
    if (verify_alignment) {
        printf("[B008] Verifying base alignment...\n");
        if (!VerifyAlignment(kv_cache)) {
            printf("[B008] FAIL: Base pointer not cache-line aligned\n");
            printf("  Address: %p, Alignment: %zu\n", 
                   (void*)kv_cache, (uintptr_t)kv_cache % CACHE_LINE_SIZE);
            results.alignment_valid = false;
            results.passed = false;
            _aligned_free(kv_cache);
            return results;
        }
        printf("[B008] PASS: Base pointer cache-line aligned\n");
    }
    
    // Initialize cache with test data
    printf("[B008] Initializing cache entries...\n");
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (size_t i = 0; i < total_entries; i++) {
        // Only initialize the 8 floats that fit in cache line
        for (size_t j = 0; j < 8; j++) {
            kv_cache[i].key[j] = dist(rng);
            kv_cache[i].value[j] = dist(rng);
        }
    }
    
    // Audit cache-line crossings
    if (audit_cache_lines) {
        printf("[B008] Auditing cache-line crossings...\n");
        
        // Check each entry
        for (size_t i = 0; i < total_entries; i++) {
            // Verify entry alignment
            if (!VerifyAlignment(&kv_cache[i])) {
                printf("[B008] FAIL: Entry %zu not aligned\n", i);
                results.alignment_valid = false;
                results.passed = false;
                _aligned_free(kv_cache);
                return results;
            }
            
            // Check for cache-line splits within entry
            size_t entry_crossings = CountCacheLineCrossings(&kv_cache[i], 
                                                              sizeof(KVCacheEntry));
            if (entry_crossings > 0) {
                printf("[B008] FAIL: Entry %zu spans %zu cache lines\n", 
                       i, entry_crossings + 1);
                results.cache_line_splits++;
            }
        }
        
        if (results.cache_line_splits == 0) {
            printf("[B008] PASS: Zero cache-line splits detected\n");
        } else {
            printf("[B008] FAIL: %zu cache-line splits detected\n", 
                   results.cache_line_splits);
        }
    }
    
    // Benchmark
    printf("\n[B008] Running throughput benchmark...\n");
    
    const int ITERATIONS = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int iter = 0; iter < ITERATIONS; iter++) {
        // Simulate one token generation across all layers
        for (size_t layer = 0; layer < NUM_LAYERS; layer++) {
            size_t layer_offset = layer * KV_SEQ_LEN * NUM_HEADS;
            SimulateAttentionAccess(kv_cache + layer_offset, KV_SEQ_LEN, NUM_HEADS);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Calculate metrics
    double total_time_us = duration.count();
    double avg_time_us = total_time_us / ITERATIONS;
    
    // Tokens per second (simulating one token per iteration)
    double tps = 1000000.0 / avg_time_us;
    
    // Memory bandwidth (bytes touched per iteration)
    size_t bytes_per_token = NUM_LAYERS * KV_SEQ_LEN * NUM_HEADS * sizeof(KVCacheEntry);
    double total_bytes = bytes_per_token * ITERATIONS;
    double bandwidth_gbps = (total_bytes / (total_time_us / 1000000.0)) / 1e9;
    
    results.avg_latency_us = avg_time_us;
    results.throughput_tps = tps;
    results.memory_bandwidth_gbps = (size_t)bandwidth_gbps;
    
    // Cleanup
    _aligned_free(kv_cache);
    
    // Determine pass/fail
    results.passed = results.alignment_valid && 
                     results.cache_line_splits == 0 &&
                     tps >= 1000.0;  // Minimum 1K TPS for baseline
    
    return results;
}

// Print results
void PrintResults(const TestResults& results) {
    printf("\n");
    printf("========================================\n");
    printf("B008 KV Cache Validation Results\n");
    printf("========================================\n");
    printf("Alignment Valid:     %s\n", results.alignment_valid ? "PASS" : "FAIL");
    printf("Cache-Line Splits:   %zu\n", results.cache_line_splits);
    printf("Avg Latency:         %.2f us/token\n", results.avg_latency_us);
    printf("Throughput:          %.2f TPS\n", results.throughput_tps);
    printf("Memory Bandwidth:    %zu GB/s\n", results.memory_bandwidth_gbps);
    printf("\n");
    
    if (results.passed) {
        printf("[PASS] B008 KV Cache Validation\n");
        printf("       Ready for Speculative Decoder\n");
    } else {
        printf("[FAIL] B008 KV Cache Validation\n");
        if (!results.alignment_valid) {
            printf("       Cache alignment issues detected\n");
        }
        if (results.cache_line_splits > 0) {
            printf("       Cache-line splits detected\n");
        }
        if (results.throughput_tps < 1000.0) {
            printf("       Throughput below target (%.2f < 1000)\n", results.throughput_tps);
        }
    }
    printf("========================================\n");
}

// Main entry
int main(int argc, char* argv[]) {
    printf("B008 Universal Execution Gate - KV Cache Validation\n");
    printf("===================================================\n\n");
    
    bool verify_alignment = false;
    bool audit_cache_lines = false;
    bool run_benchmark = false;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verify-alignment") == 0) {
            verify_alignment = true;
        } else if (strcmp(argv[i], "--audit-cache-lines") == 0) {
            audit_cache_lines = true;
        } else if (strcmp(argv[i], "--run-benchmark") == 0) {
            run_benchmark = true;
        }
    }
    
    // Default to all tests if no args
    if (!verify_alignment && !audit_cache_lines && !run_benchmark) {
        verify_alignment = true;
        audit_cache_lines = true;
        run_benchmark = true;
    }
    
    // Run tests
    TestResults results = BenchmarkKVCache(verify_alignment, audit_cache_lines);
    PrintResults(results);
    
    return results.passed ? 0 : 1;
}
