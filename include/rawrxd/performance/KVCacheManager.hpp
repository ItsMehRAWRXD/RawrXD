#pragma once

#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <queue>

namespace rawrxd {
namespace performance {

// KV cache entry
struct KVCacheEntry {
    std::vector<float> keyCache;
    std::vector<float> valueCache;
    int sequenceLength = 0;
    int numLayers = 0;
    int numHeads = 0;
    int headDim = 0;
    std::chrono::system_clock::time_point lastAccess;
    int accessCount = 0;
    
    size_t GetSizeBytes() const {
        return (keyCache.size() + valueCache.size()) * sizeof(float);
    }
};

// KV cache configuration
struct KVCacheConfig {
    size_t maxCacheSizeMB = 4096;  // 4GB default
    int maxEntries = 100;
    bool enableEviction = true;
    std::string evictionPolicy = "lru";  // lru, lfu, fifo
    bool compressCache = false;
    float compressionRatio = 0.5f;
};

// KV Cache Manager for efficient attention
class KVCacheManager {
public:
    KVCacheManager();
    ~KVCacheManager();

    // Initialize
    bool Initialize(const KVCacheConfig& config);
    
    // Allocate cache for a sequence
    int AllocateCache(int numLayers, int numHeads, int headDim, int maxSeqLen);
    
    // Get cache for a sequence
    std::shared_ptr<KVCacheEntry> GetCache(int cacheId);
    
    // Update cache (append new tokens)
    bool AppendToCache(int cacheId, const std::vector<float>& newKeys, 
                      const std::vector<float>& newValues,
                      int numNewTokens);
    
    // Free cache
    void FreeCache(int cacheId);
    
    // Get cache statistics
    struct Stats {
        size_t totalSizeBytes = 0;
        size_t maxSizeBytes = 0;
        int numEntries = 0;
        int numHits = 0;
        int numMisses = 0;
        float hitRate = 0.0f;
        int evictions = 0;
    };
    Stats GetStats() const;
    
    // Clear all caches
    void Clear();
    
    // Compact cache (remove fragmentation)
    void Compact();
    
    // Get memory usage
    size_t GetMemoryUsage() const;

private:
    KVCacheConfig config_;
    std::unordered_map<int, std::shared_ptr<KVCacheEntry>> caches_;
    std::queue<int> freeIds_;
    int nextId_ = 1;
    
    mutable std::mutex mutex_;
    Stats stats_;
    
    // Eviction
    void EvictIfNeeded();
    int SelectEvictionCandidate() const;
    void EvictEntry(int cacheId);
};

// Paged attention cache (for very long sequences)
class PagedKVCache {
public:
    static constexpr int PAGE_SIZE = 256;  // Tokens per page
    
    struct Page {
        std::vector<float> keyData;
        std::vector<float> valueData;
        bool allocated = false;
    };
    
    PagedKVCache();
    ~PagedKVCache();
    
    bool Initialize(int numLayers, int numHeads, int headDim, int maxPages);
    
    // Allocate pages for sequence
    std::vector<int> AllocatePages(int numTokens);
    
    // Get page
    Page* GetPage(int pageId);
    
    // Free pages
    void FreePages(const std::vector<int>& pageIds);
    
    // Get memory usage
    size_t GetMemoryUsage() const;
    
    // Get stats
    struct Stats {
        int totalPages = 0;
        int allocatedPages = 0;
        int freePages = 0;
        size_t pageSizeBytes = 0;
    };
    Stats GetStats() const;

private:
    int numLayers_ = 0;
    int numHeads_ = 0;
    int headDim_ = 0;
    int maxPages_ = 0;
    
    std::vector<Page> pages_;
    std::vector<int> freePageList_;
    
    mutable std::mutex mutex_;
};

} // namespace performance
} // namespace rawrxd
