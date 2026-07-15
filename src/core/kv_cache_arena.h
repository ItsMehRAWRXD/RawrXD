/**
 * @file kv_cache_arena.h
 * @brief KV-Cache Arena Interface - Zero-Allocation Fixed Buffer
 * @version 1.0.0
 * 
 * Provides C++ interface to the MASM-implemented KV-cache arena.
 * Optimized for latency: pre-allocated, page-locked, cache-aligned.
 * 
 * @copyright (c) 2025 RawrXD Project
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>

// ============================================================================
// C INTERFACE (MASM Bridge)
// ============================================================================

extern "C" {

/**
 * @brief Opaque handle to KV-cache arena
 */
typedef struct KV_Cache_Arena* KVCacheHandle;

/**
 * @brief Create a fixed-size KV-cache arena
 * @param max_tokens Maximum number of tokens to cache
 * @param head_dim Dimension per attention head
 * @param num_heads Number of attention heads
 * @return Arena handle or nullptr on failure
 */
KVCacheHandle __cdecl KVCache_Arena_Create(uint32_t max_tokens, 
                                            uint32_t head_dim, 
                                            uint32_t num_heads);

/**
 * @brief Lock arena pages in physical memory (prevents swapping)
 * @param arena Arena handle
 * @return 1 on success, 0 on failure
 */
int __cdecl KVCache_Arena_Pin(KVCacheHandle arena);

/**
 * @brief Write token K/V data to cache
 * @param arena Arena handle
 * @param token_index Token position in sequence
 * @param key_data Pointer to key tensor (head_dim * num_heads floats)
 * @param value_data Pointer to value tensor (head_dim * num_heads floats)
 * @return 1 on success, 0 on failure
 */
int __cdecl KVCache_Arena_Write(KVCacheHandle arena,
                                 uint32_t token_index,
                                 const float* key_data,
                                 const float* value_data);

/**
 * @brief Read token K/V data from cache
 * @param arena Arena handle
 * @param token_index Token position in sequence
 * @param key_data Output buffer for key tensor
 * @param value_data Output buffer for value tensor
 * @return 1 on success, 0 on failure
 */
int __cdecl KVCache_Arena_Read(KVCacheHandle arena,
                                uint32_t token_index,
                                float* key_data,
                                float* value_data);

/**
 * @brief Clear cache without deallocating (fast reset)
 * @param arena Arena handle
 */
void __cdecl KVCache_Arena_Clear(KVCacheHandle arena);

/**
 * @brief Destroy arena and free memory
 * @param arena Arena handle
 */
void __cdecl KVCache_Arena_Destroy(KVCacheHandle arena);

} // extern "C"

// ============================================================================
// C++ WRAPPER
// ============================================================================

namespace RawrXD::Inference {

/**
 * @brief RAII wrapper for KV-cache arena
 * 
 * Usage:
 * @code
 *   KVCacheArena cache(2048, 128, 32);  // 2K tokens, 128 dim, 32 heads
 *   cache.Pin();  // Lock in memory
 *   
 *   // Write token data
 *   std::vector<float> key(128 * 32), value(128 * 32);
 *   cache.Write(token_idx, key.data(), value.data());
 *   
 *   // Read token data
 *   cache.Read(token_idx, key.data(), value.data());
 * @endcode
 */
class KVCacheArena {
public:
    /**
     * @brief Construct arena with specified capacity
     * @param max_tokens Maximum sequence length
     * @param head_dim Head dimension
     * @param num_heads Number of attention heads
     */
    KVCacheArena(uint32_t max_tokens, uint32_t head_dim, uint32_t num_heads);
    
    /**
     * @brief Destructor - automatically frees resources
     */
    ~KVCacheArena();
    
    // Non-copyable (unique resource)
    KVCacheArena(const KVCacheArena&) = delete;
    KVCacheArena& operator=(const KVCacheArena&) = delete;
    
    // Movable
    KVCacheArena(KVCacheArena&& other) noexcept;
    KVCacheArena& operator=(KVCacheArena&& other) noexcept;
    
    /**
     * @brief Lock pages in physical memory (prevents swapping)
     * @return true on success
     */
    bool Pin();
    
    /**
     * @brief Check if pages are pinned
     */
    bool IsPinned() const;
    
    /**
     * @brief Write token K/V data
     * @param token_index Token position
     * @param key_data Key tensor (head_dim * num_heads elements)
     * @param value_data Value tensor (head_dim * num_heads elements)
     * @return true on success
     */
    bool Write(uint32_t token_index, const float* key_data, const float* value_data);
    
    /**
     * @brief Read token K/V data
     * @param token_index Token position
     * @param key_data Output buffer for key tensor
     * @param value_data Output buffer for value tensor
     * @return true on success
     */
    bool Read(uint32_t token_index, float* key_data, float* value_data) const;
    
    /**
     * @brief Clear cache (fast reset without deallocation)
     */
    void Clear();
    
    /**
     * @brief Get current number of cached tokens
     */
    uint32_t GetCurrentSize() const;
    
    /**
     * @brief Get maximum capacity
     */
    uint32_t GetMaxTokens() const;
    
    /**
     * @brief Get head dimension
     */
    uint32_t GetHeadDim() const;
    
    /**
     * @brief Get number of heads
     */
    uint32_t GetNumHeads() const;
    
    /**
     * @brief Calculate memory usage in bytes
     */
    size_t GetMemoryUsage() const;
    
    /**
     * @brief Check if arena is valid
     */
    bool IsValid() const { return handle_ != nullptr; }
    
    /**
     * @brief Get raw handle (for advanced use)
     */
    KVCacheHandle GetHandle() const { return handle_; }

private:
    KVCacheHandle handle_;
    uint32_t max_tokens_;
    uint32_t head_dim_;
    uint32_t num_heads_;
    bool pinned_;
};

/**
 * @brief Smart pointer alias for KV-cache arena
 */
using KVCacheArenaPtr = std::unique_ptr<KVCacheArena>;

/**
 * @brief Factory function for creating arena
 */
inline KVCacheArenaPtr CreateKVCacheArena(uint32_t max_tokens,
                                           uint32_t head_dim,
                                           uint32_t num_heads) {
    return std::make_unique<KVCacheArena>(max_tokens, head_dim, num_heads);
}

// ============================================================================
// LATENCY OPTIMIZATION HELPERS
// ============================================================================

/**
 * @brief Pre-allocate and pin cache for maximum performance
 * 
 * This function creates a cache with optimal settings for latency-critical
 * inference and immediately pins it in physical memory.
 * 
 * @param max_context_length Maximum expected context length
 * @param head_dim Head dimension (typically 64, 128)
 * @param num_heads Number of attention heads
 * @return Pinned arena ready for inference
 */
KVCacheArenaPtr CreatePinnedCache(uint32_t max_context_length,
                                   uint32_t head_dim,
                                   uint32_t num_heads);

/**
 * @brief Calculate optimal cache size for a model
 * @param num_layers Number of transformer layers
 * @param max_seq_len Maximum sequence length
 * @param head_dim Head dimension
 * @param num_heads Number of heads
 * @return Memory required in bytes
 */
size_t CalculateKVCacheSize(uint32_t num_layers,
                            uint32_t max_seq_len,
                            uint32_t head_dim,
                            uint32_t num_heads);

/**
 * @brief Prefetch cache slots for upcoming tokens
 * 
 * Hints to the CPU to load cache lines for upcoming tokens,
 * reducing latency during token generation.
 * 
 * @param arena Cache arena
 * @param start_token Starting token index
 * @param num_tokens Number of tokens to prefetch
 */
void PrefetchCacheSlots(const KVCacheArena& arena,
                        uint32_t start_token,
                        uint32_t num_tokens);

} // namespace RawrXD::Inference

// ============================================================================
// PERFORMANCE METRICS
// ============================================================================

namespace RawrXD::Metrics {

/**
 * @brief KV-cache performance statistics
 */
struct KVCacheMetrics {
    uint64_t write_count;           ///< Total writes performed
    uint64_t read_count;            ///< Total reads performed
    double avg_write_latency_us;    ///< Average write latency
    double avg_read_latency_us;     ///< Average read latency
    double min_write_latency_us;    ///< Minimum write latency
    double min_read_latency_us;     ///< Minimum read latency
    double max_write_latency_us;    ///< Maximum write latency
    double max_read_latency_us;     ///< Maximum read latency
    size_t cache_hits;              ///< Number of cache hits
    size_t cache_misses;            ///< Number of cache misses
};

/**
 * @brief Enable latency tracking for cache operations
 */
void EnableKVCacheMetrics();

/**
 * @brief Get current metrics
 */
KVCacheMetrics GetKVCacheMetrics();

/**
 * @brief Reset metrics counters
 */
void ResetKVCacheMetrics();

} // namespace RawrXD::Metrics
