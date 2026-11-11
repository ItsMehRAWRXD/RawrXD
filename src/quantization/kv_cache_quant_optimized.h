// =============================================================================
// kv_cache_quant_optimized.h
// Header for Optimized KV Cache with Q4_K Quantization
// =============================================================================

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Configuration
// =============================================================================

typedef struct {
    uint32_t full_precision_tokens;   // Tokens kept in higher precision
    uint32_t standard_tokens;             // Tokens in Q4_K
    uint32_t compressed_tokens;           // Tokens in Q2_K
} KVCacheSlidingWindowConfig;

typedef struct {
    size_t current_memory_mb;
    size_t max_memory_mb;
    float compression_ratio;
    uint32_t tokens_cached;
    float avg_dequant_latency_us;
} KVCacheStats;

// =============================================================================
// API Functions
// =============================================================================

// Enable/disable Q4_K KV cache (default: Q8_0)
__declspec(dllexport) void KVCache_EnableQ4K(bool enable);

// Configure sliding window compression
__declspec(dllexport) void KVCache_SetSlidingWindow(
    uint32_t full_precision_tokens,
    uint32_t standard_tokens,
    uint32_t compressed_tokens
);

// Get current memory usage in MB
__declspec(dllexport) size_t KVCache_GetMemoryUsageMB(void);

// Set maximum cache size
__declspec(dllexport) void KVCache_SetMaxSizeMB(size_t max_size_mb);

// Get cache statistics
__declspec(dllexport) void KVCache_GetStats(KVCacheStats* stats);

// =============================================================================
// Constants
// =============================================================================

#define KV_CACHE_Q4K_ENABLED_DEFAULT    true
#define KV_CACHE_MAX_SIZE_MB_DEFAULT    512
#define KV_CACHE_FP_TOKENS_DEFAULT      512
#define KV_CACHE_STD_TOKENS_DEFAULT       2048
#define KV_CACHE_COMP_TOKENS_DEFAULT    1536

#ifdef __cplusplus
}
#endif
