// kv_runtime_bridge.cpp - KV Cache Bridge Implementation
// Phase 8.1 - Gate G5: KV cache append/retrieve
// NO DEPENDENCIES - Pure Win32 API

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include "sovereign_runtime.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// G5: KV CACHE INITIALIZATION
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_KVCache_Init(
    ModelContext* ctx,
    int n_layers,
    int n_heads,
    int head_dim,
    int max_seq_len
) {
    if (!ctx) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    KVCache* cache = &ctx->kv_cache;
    
    // Validate parameters
    if (n_layers <= 0 || n_heads <= 0 || head_dim <= 0 || max_seq_len <= 0) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    // Calculate cache size
    size_t elements_per_layer = max_seq_len * n_heads * head_dim;
    size_t total_elements = n_layers * elements_per_layer;
    size_t cache_size = total_elements * sizeof(float);
    
    // Allocate K cache
    cache->k_cache = (float*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cache_size);
    if (!cache->k_cache) {
        return SOVEREIGN_RUNTIME_ERROR_OUT_OF_MEMORY;
    }
    
    // Allocate V cache
    cache->v_cache = (float*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cache_size);
    if (!cache->v_cache) {
        HeapFree(GetProcessHeap(), 0, cache->k_cache);
        cache->k_cache = NULL;
        return SOVEREIGN_RUNTIME_ERROR_OUT_OF_MEMORY;
    }
    
    // Initialize cache metadata
    cache->n_layers = n_layers;
    cache->n_heads = n_heads;
    cache->head_dim = head_dim;
    cache->max_seq_len = max_seq_len;
    cache->current_len = 0;
    cache->size = cache_size;
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// G5: KV CACHE APPEND
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_KVCache_Append(
    ModelContext* ctx,
    int layer_idx,
    const float* key,
    const float* value,
    int seq_len
) {
    if (!ctx || !key || !value) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    KVCache* cache = &ctx->kv_cache;
    
    // Validate layer index
    if (layer_idx < 0 || layer_idx >= cache->n_layers) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    // Validate sequence length
    if (seq_len < 0 || seq_len >= cache->max_seq_len) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    // Calculate offsets
    int elements_per_position = cache->n_heads * cache->head_dim;
    size_t layer_offset = layer_idx * cache->max_seq_len * elements_per_position;
    size_t position_offset = seq_len * elements_per_position;
    size_t total_offset = layer_offset + position_offset;
    
    // Copy key
    memcpy(cache->k_cache + total_offset, key, elements_per_position * sizeof(float));
    
    // Copy value
    memcpy(cache->v_cache + total_offset, value, elements_per_position * sizeof(float));
    
    // Update current length if this is the newest position
    if (seq_len >= cache->current_len) {
        cache->current_len = seq_len + 1;
    }
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// G5: KV CACHE RETRIEVE
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_KVCache_Retrieve(
    ModelContext* ctx,
    int layer_idx,
    float* key,
    float* value,
    int position
) {
    if (!ctx || !key || !value) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    KVCache* cache = &ctx->kv_cache;
    
    // Validate layer index
    if (layer_idx < 0 || layer_idx >= cache->n_layers) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    // Validate position
    if (position < 0 || position >= cache->max_seq_len) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    // Calculate offsets
    int elements_per_position = cache->n_heads * cache->head_dim;
    size_t layer_offset = layer_idx * cache->max_seq_len * elements_per_position;
    size_t position_offset = position * elements_per_position;
    size_t total_offset = layer_offset + position_offset;
    
    // Copy key
    memcpy(key, cache->k_cache + total_offset, elements_per_position * sizeof(float));
    
    // Copy value
    memcpy(value, cache->v_cache + total_offset, elements_per_position * sizeof(float));
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// G5: KV CACHE RETRIEVE RANGE (for attention)
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_KVCache_RetrieveRange(
    ModelContext* ctx,
    int layer_idx,
    float* keys,
    float* values,
    int start_pos,
    int end_pos
) {
    if (!ctx || !keys || !values) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    KVCache* cache = &ctx->kv_cache;
    
    // Validate layer index
    if (layer_idx < 0 || layer_idx >= cache->n_layers) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    // Validate range
    if (start_pos < 0 || end_pos > cache->max_seq_len || start_pos >= end_pos) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    // Calculate offsets
    int elements_per_position = cache->n_heads * cache->head_dim;
    size_t layer_offset = layer_idx * cache->max_seq_len * elements_per_position;
    size_t start_offset = layer_offset + start_pos * elements_per_position;
    
    int num_positions = end_pos - start_pos;
    size_t total_elements = num_positions * elements_per_position;
    
    // Copy keys
    memcpy(keys, cache->k_cache + start_offset, total_elements * sizeof(float));
    
    // Copy values
    memcpy(values, cache->v_cache + start_offset, total_elements * sizeof(float));
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// G5: KV CACHE CLEAR
// ============================================================================

SOVEREIGN_RUNTIME_API void Sovereign_Runtime_KVCache_Clear(ModelContext* ctx) {
    if (!ctx) return;
    
    KVCache* cache = &ctx->kv_cache;
    
    if (cache->k_cache) {
        size_t total_elements = cache->n_layers * cache->max_seq_len * 
                                cache->n_heads * cache->head_dim;
        memset(cache->k_cache, 0, total_elements * sizeof(float));
    }
    
    if (cache->v_cache) {
        size_t total_elements = cache->n_layers * cache->max_seq_len * 
                                cache->n_heads * cache->head_dim;
        memset(cache->v_cache, 0, total_elements * sizeof(float));
    }
    
    cache->current_len = 0;
}

// ============================================================================
// G5: KV CACHE FREE
// ============================================================================

SOVEREIGN_RUNTIME_API void Sovereign_Runtime_KVCache_Free(ModelContext* ctx) {
    if (!ctx) return;
    
    KVCache* cache = &ctx->kv_cache;
    
    if (cache->k_cache) {
        HeapFree(GetProcessHeap(), 0, cache->k_cache);
        cache->k_cache = NULL;
    }
    
    if (cache->v_cache) {
        HeapFree(GetProcessHeap(), 0, cache->v_cache);
        cache->v_cache = NULL;
    }
    
    cache->n_layers = 0;
    cache->n_heads = 0;
    cache->head_dim = 0;
    cache->max_seq_len = 0;
    cache->current_len = 0;
    cache->size = 0;
}

// ============================================================================
// G5: KV CACHE UTILITIES
// ============================================================================

SOVEREIGN_RUNTIME_API int Sovereign_Runtime_KVCache_GetCurrentLen(ModelContext* ctx) {
    if (!ctx) return 0;
    return ctx->kv_cache.current_len;
}

SOVEREIGN_RUNTIME_API int Sovereign_Runtime_KVCache_GetMaxLen(ModelContext* ctx) {
    if (!ctx) return 0;
    return ctx->kv_cache.max_seq_len;
}

SOVEREIGN_RUNTIME_API size_t Sovereign_Runtime_KVCache_GetSize(ModelContext* ctx) {
    if (!ctx) return 0;
    return ctx->kv_cache.size;
}