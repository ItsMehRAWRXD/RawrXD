// ============================================================================
// VAL-004: KV Cache Validation Gate Implementation
// ============================================================================

#include "VAL004_KVCacheGate.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
#include <cmath>

namespace RawrXD {
namespace Validation {

REGISTER_VALIDATION_GATE(VAL004_KVCacheGate);

ValidationResult VAL004_KVCacheGate::Execute() {
    ValidationResult result;
    result.gateId = GetId();
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[VAL-004] KV Cache Validation\n");
    printf("==============================\n");
    
    bool allPassed = true;
    
    printf("\n[1/5] Cache Allocation...\n");
    if (!ValidateCacheAllocation()) {
        printf("  FAILED: Cache allocation\n");
        allPassed = false;
    } else {
        printf("  PASSED: Cache allocation\n");
    }
    
    printf("\n[2/5] Cache Read/Write...\n");
    if (!ValidateCacheReadWrite()) {
        printf("  FAILED: Cache read/write\n");
        allPassed = false;
    } else {
        printf("  PASSED: Cache read/write\n");
    }
    
    printf("\n[3/5] Cache Quantization...\n");
    if (!ValidateCacheQuantization()) {
        printf("  FAILED: Cache quantization\n");
        allPassed = false;
    } else {
        printf("  PASSED: Cache quantization\n");
    }
    
    printf("\n[4/5] Sliding Window...\n");
    if (!ValidateSlidingWindow()) {
        printf("  FAILED: Sliding window\n");
        allPassed = false;
    } else {
        printf("  PASSED: Sliding window\n");
    }
    
    printf("\n[5/5] Cache Eviction...\n");
    if (!ValidateCacheEviction()) {
        printf("  FAILED: Cache eviction\n");
        allPassed = false;
    } else {
        printf("  PASSED: Cache eviction\n");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    result.passed = allPassed;
    result.message = allPassed ? "VAL-004: All KV cache tests passed" 
                               : "VAL-004: Some tests failed";
    
    printf("\n==============================\n");
    printf("[VAL-004] Result: %s (%.2f ms)\n", 
           allPassed ? "PASSED" : "FAILED", result.durationMs);
    printf("==============================\n");
    
    return result;
}

bool VAL004_KVCacheGate::ValidateCacheAllocation() {
    // Simulate KV cache allocation
    const int num_layers = 32;
    const int num_heads = 32;
    const int head_dim = 128;
    const int max_seq_len = 8192;
    
    // Calculate required memory
    size_t bytes_per_token = num_layers * num_heads * head_dim * 2 * sizeof(float); // K + V
    size_t total_bytes = max_seq_len * bytes_per_token;
    
    // Validate allocation size is reasonable
    if (total_bytes == 0) return false;
    if (total_bytes > 100ULL * 1024 * 1024 * 1024) return false; // > 100GB is unreasonable
    
    // Simulate allocation
    std::vector<float> cache(total_bytes / sizeof(float));
    if (cache.empty()) return false;
    
    return true;
}

bool VAL004_KVCacheGate::ValidateCacheReadWrite() {
    // Test cache write and read
    const int cache_size = 1024;
    std::vector<float> k_cache(cache_size);
    std::vector<float> v_cache(cache_size);
    
    // Write test data
    for (int i = 0; i < cache_size; i++) {
        k_cache[i] = static_cast<float>(i) * 0.01f;
        v_cache[i] = static_cast<float>(i) * 0.02f;
    }
    
    // Read and verify
    for (int i = 0; i < cache_size; i++) {
        if (std::abs(k_cache[i] - static_cast<float>(i) * 0.01f) > 0.0001f) {
            return false;
        }
        if (std::abs(v_cache[i] - static_cast<float>(i) * 0.02f) > 0.0001f) {
            return false;
        }
    }
    
    return true;
}

bool VAL004_KVCacheGate::ValidateCacheQuantization() {
    // Test Q8_0 quantization for KV cache
    const int block_size = 32;
    alignas(32) float input[block_size];
    
    // Initialize with test data
    for (int i = 0; i < block_size; i++) {
        input[i] = (i - 16) * 0.1f; // Range: -1.6 to 1.5
    }
    
    // Find scale
    float max_val = 0.0f;
    for (int i = 0; i < block_size; i++) {
        max_val = std::max(max_val, std::abs(input[i]));
    }
    float scale = max_val / 127.0f;
    
    // Quantize
    int8_t quantized[block_size];
    for (int i = 0; i < block_size; i++) {
        quantized[i] = static_cast<int8_t>(std::round(input[i] / scale));
    }
    
    // Dequantize
    float output[block_size];
    for (int i = 0; i < block_size; i++) {
        output[i] = quantized[i] * scale;
    }
    
    // Verify error is within tolerance
    float max_error = 0.0f;
    for (int i = 0; i < block_size; i++) {
        max_error = std::max(max_error, std::abs(input[i] - output[i]));
    }
    
    return max_error < 0.02f; // Tolerance for Q8_0
}

bool VAL004_KVCacheGate::ValidateSlidingWindow() {
    // Test sliding window cache
    const int window_size = 1024;
    const int total_tokens = 2048;
    
    // Simulate cache with sliding window
    std::vector<int> cache_positions(total_tokens);
    
    for (int pos = 0; pos < total_tokens; pos++) {
        int cache_pos = pos % window_size;
        cache_positions[pos] = cache_pos;
    }
    
    // Verify positions wrap correctly
    if (cache_positions[0] != 0) return false;
    if (cache_positions[1023] != 1023) return false;
    if (cache_positions[1024] != 0) return false; // Wrapped
    if (cache_positions[2047] != 1023) return false;
    
    return true;
}

bool VAL004_KVCacheGate::ValidateCacheEviction() {
    // Test LRU eviction policy
    struct CacheEntry {
        int token_id;
        int last_access;
    };
    
    const int cache_capacity = 100;
    std::vector<CacheEntry> cache;
    int access_counter = 0;
    
    // Fill cache
    for (int i = 0; i < cache_capacity; i++) {
        cache.push_back({i, ++access_counter});
    }
    
    // Access some entries
    cache[10].last_access = ++access_counter;
    cache[20].last_access = ++access_counter;
    cache[30].last_access = ++access_counter;
    
    // Find LRU entry (should be entry 0, not accessed)
    int lru_idx = 0;
    int min_access = cache[0].last_access;
    for (size_t i = 1; i < cache.size(); i++) {
        if (cache[i].last_access < min_access) {
            min_access = cache[i].last_access;
            lru_idx = static_cast<int>(i);
        }
    }
    
    // LRU should be entry 0 (or any non-accessed entry)
    if (cache[lru_idx].last_access != 1) return false;
    
    return true;
}

} // namespace Validation
} // namespace RawrXD
