// RawrXD Model Cache
// Phase 9 - Task 10: Model Caching

#include <windows.h>
#include <string>
#include <map>
#include <list>
#include <mutex>
#include <chrono>

// Cache entry state
enum CacheEntryState {
    CACHE_LOADING,
    CACHE_READY,
    CACHE_EVICTING,
    CACHE_ERROR
};

// Model cache entry
struct ModelCacheEntry {
    std::string modelId;
    std::string modelPath;
    void* modelData;
    size_t modelSize;
    CacheEntryState state;
    std::chrono::steady_clock::time_point loaded;
    std::chrono::steady_clock::time_point lastAccess;
    uint64_t accessCount;
    uint64_t inferenceCount;
    std::list<std::string>::iterator lruIter;
};

// Cache statistics
struct CacheStats {
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t totalSize;
    uint64_t maxSize;
    size_t entryCount;
};

// Model cache
class ModelCache {
private:
    std::map<std::string, ModelCacheEntry> cache;
    std::list<std::string> lruList;
    std::mutex cacheMutex;
    CacheStats stats;
    uint64_t maxCacheSize;
    uint64_t maxMemoryUsage;
    std::string cacheDir;
    bool preloadEnabled;
    
public:
    ModelCache() : maxCacheSize(10), maxMemoryUsage(8ULL * 1024 * 1024 * 1024), // 8GB
                   preloadEnabled(false) {
        stats = {};
    }
    
    bool Initialize(const std::string& directory, uint64_t maxSize, uint64_t maxMemory) {
        cacheDir = directory;
        maxCacheSize = maxSize;
        maxMemoryUsage = maxMemory;
        
        // Create cache directory
        CreateDirectoryA(cacheDir.c_str(), nullptr);
        
        printf("Model cache initialized:\n");
        printf("  Cache directory: %s\n", cacheDir.c_str());
        printf("  Max entries: %llu\n", maxCacheSize);
        printf("  Max memory: %llu MB\n", maxMemoryUsage / (1024 * 1024));
        
        return true;
    }
    
    // Get model from cache
    void* GetModel(const std::string& modelId, size_t& size) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        
        auto it = cache.find(modelId);
        if (it != cache.end()) {
            if (it->second.state == CACHE_READY) {
                // Update LRU
                UpdateLRU(it->second);
                
                it->second.lastAccess = std::chrono::steady_clock::now();
                it->second.accessCount++;
                
                stats.hits++;
                size = it->second.modelSize;
                return it->second.modelData;
            }
        }
        
        stats.misses++;
        size = 0;
        return nullptr;
    }
    
    // Put model in cache
    bool PutModel(const std::string& modelId, const std::string& modelPath,
                   void* data, size_t size) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        
        // Check if we need to evict
        while (cache.size() >= maxCacheSize || 
               (stats.totalSize + size) > maxMemoryUsage) {
            if (!EvictLRU()) {
                return false;  // Cannot make room
            }
        }
        
        // Create new entry
        ModelCacheEntry entry;
        entry.modelId = modelId;
        entry.modelPath = modelPath;
        entry.modelData = data;
        entry.modelSize = size;
        entry.state = CACHE_READY;
        entry.loaded = std::chrono::steady_clock::now();
        entry.lastAccess = entry.loaded;
        entry.accessCount = 0;
        entry.inferenceCount = 0;
        
        // Add to LRU list
        lruList.push_front(modelId);
        entry.lruIter = lruList.begin();
        
        cache[modelId] = entry;
        stats.totalSize += size;
        stats.entryCount = cache.size();
        
        printf("Cached model: %s (size: %llu MB)\n", modelId.c_str(), size / (1024 * 1024));
        return true;
    }
    
    // Preload model into cache
    bool PreloadModel(const std::string& modelId, const std::string& modelPath) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        
        // Check if already cached
        if (cache.find(modelId) != cache.end()) {
            return true;
        }
        
        // Mark as loading
        ModelCacheEntry entry;
        entry.modelId = modelId;
        entry.modelPath = modelPath;
        entry.modelData = nullptr;
        entry.modelSize = 0;
        entry.state = CACHE_LOADING;
        entry.loaded = std::chrono::steady_clock::now();
        entry.lastAccess = entry.loaded;
        entry.accessCount = 0;
        
        cache[modelId] = entry;
        
        // Start async load (simplified - would use thread pool)
        printf("Preloading model: %s\n", modelId.c_str());
        
        return true;
    }
    
    // Invalidate cache entry
    bool Invalidate(const std::string& modelId) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        
        auto it = cache.find(modelId);
        if (it == cache.end()) {
            return false;
        }
        
        // Remove from LRU list
        lruList.erase(it->second.lruIter);
        
        // Free memory
        if (it->second.modelData) {
            VirtualFree(it->second.modelData, 0, MEM_RELEASE);
        }
        
        stats.totalSize -= it->second.modelSize;
        cache.erase(it);
        stats.entryCount = cache.size();
        
        printf("Invalidated cache entry: %s\n", modelId.c_str());
        return true;
    }
    
    // Clear entire cache
    void Clear() {
        std::lock_guard<std::mutex> lock(cacheMutex);
        
        for (auto& pair : cache) {
            if (pair.second.modelData) {
                VirtualFree(pair.second.modelData, 0, MEM_RELEASE);
            }
        }
        
        cache.clear();
        lruList.clear();
        stats.totalSize = 0;
        stats.entryCount = 0;
        
        printf("Cache cleared\n");
    }
    
    // Get cache statistics
    void GetStats(CacheStats& outStats) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        outStats = stats;
    }
    
    // Get cache hit rate
    double GetHitRate() {
        std::lock_guard<std::mutex> lock(cacheMutex);
        uint64_t total = stats.hits + stats.misses;
        return total > 0 ? (double)stats.hits / total : 0.0;
    }
    
    // Check if model is cached
    bool IsCached(const std::string& modelId) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = cache.find(modelId);
        return it != cache.end() && it->second.state == CACHE_READY;
    }
    
    // Get cache size
    size_t GetSize() {
        std::lock_guard<std::mutex> lock(cacheMutex);
        return cache.size();
    }
    
    // Get memory usage
    uint64_t GetMemoryUsage() {
        std::lock_guard<std::mutex> lock(cacheMutex);
        return stats.totalSize;
    }
    
private:
    void UpdateLRU(ModelCacheEntry& entry) {
        // Move to front of LRU list
        lruList.erase(entry.lruIter);
        lruList.push_front(entry.modelId);
        entry.lruIter = lruList.begin();
    }
    
    bool EvictLRU() {
        if (lruList.empty()) {
            return false;
        }
        
        // Get least recently used
        std::string lruId = lruList.back();
        lruList.pop_back();
        
        auto it = cache.find(lruId);
        if (it != cache.end()) {
            // Free memory
            if (it->second.modelData) {
                VirtualFree(it->second.modelData, 0, MEM_RELEASE);
            }
            
            stats.totalSize -= it->second.modelSize;
            cache.erase(it);
            stats.evictions++;
            
            printf("Evicted model: %s\n", lruId.c_str());
        }
        
        return true;
    }
};

// Global instance
static ModelCache g_ModelCache;

// C API
extern "C" {

bool ModelCache_Init(const char* cacheDir, uint64_t maxEntries, uint64_t maxMemoryMB) {
    return g_ModelCache.Initialize(cacheDir, maxEntries, maxMemoryMB * 1024 * 1024);
}

void* ModelCache_Get(const char* modelId, size_t* size) {
    return g_ModelCache.GetModel(modelId, *size);
}

bool ModelCache_Put(const char* modelId, const char* modelPath, void* data, size_t size) {
    return g_ModelCache.PutModel(modelId, modelPath, data, size);
}

bool ModelCache_Preload(const char* modelId, const char* modelPath) {
    return g_ModelCache.PreloadModel(modelId, modelPath);
}

bool ModelCache_Invalidate(const char* modelId) {
    return g_ModelCache.Invalidate(modelId);
}

void ModelCache_Clear() {
    g_ModelCache.Clear();
}

bool ModelCache_IsCached(const char* modelId) {
    return g_ModelCache.IsCached(modelId);
}

size_t ModelCache_GetSize() {
    return g_ModelCache.GetSize();
}

uint64_t ModelCache_GetMemoryUsage() {
    return g_ModelCache.GetMemoryUsage();
}

double ModelCache_GetHitRate() {
    return g_ModelCache.GetHitRate();
}

} // extern "C"
