// RawrXD KV Cache Manager
// Phase AO: KV Cache Optimization

#pragma once

#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <queue>

namespace rawrxd {
namespace cache {

// Cache eviction policies
enum class EvictionPolicy {
    LRU,                // Least Recently Used
    LFU,                // Least Frequently Used
    FIFO,               // First In First Out
    RANDOM,             // Random eviction
    ADAPTIVE            // Adaptive policy
};

// Cache entry state
enum class CacheEntryState {
    ACTIVE,             // Currently in use
    IDLE,               // Available for reuse
    EVICTED,            // Marked for eviction
    PREFETCHED          // Prefetched but not used
};

// KV cache entry
struct KVCacheEntry {
    int layer_id;
    int head_id;
    int seq_len;
    int head_dim;
    
    std::vector<float> key_cache;
    std::vector<float> value_cache;
    
    size_t last_access;
    size_t access_count;
    CacheEntryState state;
    
    size_t size() const {
        return (key_cache.size() + value_cache.size()) * sizeof(float);
    }
    
    KVCacheEntry() : layer_id(0), head_id(0), seq_len(0), head_dim(0), 
                     last_access(0), access_count(0), state(CacheEntryState::IDLE) {}
};

// Cache configuration
struct KVCacheConfig {
    size_t max_cache_size;          // Maximum cache size in bytes
    size_t max_seq_len;             // Maximum sequence length
    int num_layers;                 // Number of transformer layers
    int num_heads;                  // Number of attention heads
    int head_dim;                   // Dimension per head
    EvictionPolicy eviction_policy; // Eviction policy
    bool enable_compression;        // Enable cache compression
    float compression_ratio;        // Target compression ratio
    bool enable_prefetch;           // Enable prefetching
    size_t prefetch_distance;       // Prefetch distance
    
    KVCacheConfig()
        : max_cache_size(1024 * 1024 * 1024)  // 1GB default
        , max_seq_len(8192)
        , num_layers(32)
        , num_heads(32)
        , head_dim(128)
        , eviction_policy(EvictionPolicy::LRU)
        , enable_compression(false)
        , compression_ratio(0.5f)
        , enable_prefetch(true)
        , prefetch_distance(256) {}
};

// Cache statistics
struct KVCacheStats {
    size_t current_size;
    size_t max_size;
    size_t hits;
    size_t misses;
    size_t evictions;
    size_t prefetches;
    float hit_rate;
    size_t compression_savings;
    
    KVCacheStats()
        : current_size(0)
        , max_size(0)
        , hits(0)
        , misses(0)
        , evictions(0)
        , prefetches(0)
        , hit_rate(0.0f)
        , compression_savings(0) {}
};

// Forward declarations
class KVCacheManager;
class CacheCompressor;

/**
 * KVCacheManager - Key-Value cache management for transformer attention
 */
class KVCacheManager {
public:
    KVCacheManager();
    ~KVCacheManager();
    
    // Initialize cache
    bool initialize(const KVCacheConfig& config);
    void shutdown();
    
    // Cache operations
    KVCacheEntry* allocate(int layer_id, int head_id, int seq_len);
    void release(KVCacheEntry* entry);
    void markUsed(KVCacheEntry* entry);
    
    // Query cache
    KVCacheEntry* lookup(int layer_id, int head_id, int seq_start, int seq_end);
    bool contains(int layer_id, int head_id, int seq_len);
    
    // Prefetch
    void prefetch(int layer_id, int head_id, int seq_start, int seq_len);
    
    // Eviction
    void evictIfNeeded(size_t required_size);
    void evictEntry(KVCacheEntry* entry);
    void clear();
    
    // Compression
    void compressEntry(KVCacheEntry* entry);
    void decompressEntry(KVCacheEntry* entry);
    
    // Statistics
    KVCacheStats getStats() const;
    void resetStats();
    void printStats() const;
    
    // Configuration
    void setEvictionPolicy(EvictionPolicy policy);
    void setMaxSize(size_t max_size);
    
    // Memory management
    size_t getCurrentSize() const;
    size_t getMaxSize() const { return config_.max_cache_size; }
    float getUtilization() const;
    
private:
    KVCacheConfig config_;
    KVCacheStats stats_;
    
    std::unordered_map<std::string, std::unique_ptr<KVCacheEntry>> cache_;
    std::queue<KVCacheEntry*> lru_queue_;
    std::unordered_map<KVCacheEntry*, size_t> access_frequency_;
    
    mutable std::mutex mutex_;
    size_t current_size_;
    size_t access_counter_;
    
    std::unique_ptr<CacheCompressor> compressor_;
    
    bool initialized_;
    
    // Internal methods
    std::string makeKey(int layer_id, int head_id, int seq_start, int seq_end);
    KVCacheEntry* evictLRU();
    KVCacheEntry* evictLFU();
    KVCacheEntry* evictFIFO();
    KVCacheEntry* evictRandom();
    void updateLRU(KVCacheEntry* entry);
};

/**
 * CacheCompressor - KV cache compression
 */
class CacheCompressor {
public:
    CacheCompressor();
    
    // Quantization compression
    void quantizeFP16(std::vector<float>& data);
    void quantizeINT8(std::vector<float>& data);
    
    // Dequantization
    void dequantizeFP16(std::vector<float>& data);
    void dequantizeINT8(std::vector<float>& data);
    
    // Sparse compression
    void sparsify(std::vector<float>& data, float threshold);
    void densify(std::vector<float>& data);
    
    // Get compression ratio
    float getCompressionRatio() const { return compression_ratio_; }
    
private:
    float compression_ratio_;
};

// Global KV cache manager accessor
KVCacheManager* getKVCacheManager();
void setKVCacheManager(std::unique_ptr<KVCacheManager> manager);

} // namespace cache
} // namespace rawrxd
