/**
 * CacheManager.hpp
 *
 * Phase M Batch 2/5: Caching Layer
 *
 * Multi-tier caching system with support for in-memory, distributed,
 * and persistent caching with cache invalidation strategies.
 */

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <future>

namespace Data {

// ============================================================================
// Forward Declarations
// ============================================================================

class CacheEntry;
class CachePolicy;
class CacheManager;
class DistributedCache;
class CacheWarmer;

// ============================================================================
// Cache Types
// ============================================================================

enum class CacheType {
    MEMORY_LRU,
    MEMORY_LFU,
    MEMORY_FIFO,
    REDIS,
    MEMCACHED,
    DISK,
    HYBRID,
    MULTI_TIER
};

// ============================================================================
// Cache Entry
// ============================================================================

/**
 * Cache entry with metadata.
 */
class CacheEntry {
public:
    using ValueType = std::vector<uint8_t>;
    
    struct Config {
        std::string key;
        ValueType value;
        std::chrono::seconds ttl;
        std::optional<std::chrono::system_clock::time_point> expiresAt;
        std::map<std::string, std::string> metadata;
        uint64_t sizeBytes;
        uint64_t accessCount;
        std::chrono::system_clock::time_point lastAccess;
        std::chrono::system_clock::time_point createdAt;
    };
    
    explicit CacheEntry(const Config& config);
    
    // Accessors
    const std::string& GetKey() const { return config_.key; }
    const ValueType& GetValue() const { return config_.value; }
    ValueType& GetValue() { return config_.value; }
    
    // TTL
    bool IsExpired() const;
    std::chrono::seconds GetTTL() const;
    void SetTTL(std::chrono::seconds ttl);
    void ExtendTTL(std::chrono::seconds extension);
    
    // Metadata
    void SetMetadata(const std::string& key, const std::string& value);
    std::optional<std::string> GetMetadata(const std::string& key) const;
    const std::map<std::string, std::string>& GetMetadata() const { return config_.metadata; }
    
    // Statistics
    void Touch();
    uint64_t GetAccessCount() const { return config_.accessCount; }
    std::chrono::system_clock::time_point GetLastAccess() const { return config_.lastAccess; }
    uint64_t GetSize() const { return config_.sizeBytes; }
    
    // Serialization
    std::vector<uint8_t> Serialize() const;
    static CacheEntry Deserialize(const std::vector<uint8_t>& data);
    
private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Cache Policy
// ============================================================================

/**
 * Cache eviction policy interface.
 */
class CachePolicy {
public:
    virtual ~CachePolicy() = default;
    
    // Policy name
    virtual std::string GetName() const = 0;
    
    // Entry management
    virtual void OnInsert(const std::string& key) = 0;
    virtual void OnAccess(const std::string& key) = 0;
    virtual void OnRemove(const std::string& key) = 0;
    virtual void OnUpdate(const std::string& key) = 0;
    
    // Eviction
    virtual std::optional<std::string> GetEvictionCandidate() = 0;
    virtual std::vector<std::string> GetEvictionCandidates(size_t count) = 0;
    
    // Reset
    virtual void Clear() = 0;
};

/**
 * LRU (Least Recently Used) policy.
 */
class LRUPolicy : public CachePolicy {
public:
    std::string GetName() const override { return "LRU"; }
    
    void OnInsert(const std::string& key) override;
    void OnAccess(const std::string& key) override;
    void OnRemove(const std::string& key) override;
    void OnUpdate(const std::string& key) override;
    
    std::optional<std::string> GetEvictionCandidate() override;
    std::vector<std::string> GetEvictionCandidates(size_t count) override;
    
    void Clear() override;
    
private:
    std::list<std::string> accessOrder_;
    std::map<std::string, std::list<std::string>::iterator> keyPositions_;
    mutable std::mutex mutex_;
};

/**
 * LFU (Least Frequently Used) policy.
 */
class LFUPolicy : public CachePolicy {
public:
    std::string GetName() const override { return "LFU"; }
    
    void OnInsert(const std::string& key) override;
    void OnAccess(const std::string& key) override;
    void OnRemove(const std::string& key) override;
    void OnUpdate(const std::string& key) override;
    
    std::optional<std::string> GetEvictionCandidate() override;
    std::vector<std::string> GetEvictionCandidates(size_t count) override;
    
    void Clear() override;
    
private:
    std::map<std::string, uint64_t> frequencies_;
    std::map<uint64_t, std::set<std::string>> frequencyGroups_;
    mutable std::mutex mutex_;
};

/**
 * FIFO (First In First Out) policy.
 */
class FIFOPolicy : public CachePolicy {
public:
    std::string GetName() const override { return "FIFO"; }
    
    void OnInsert(const std::string& key) override;
    void OnAccess(const std::string& key) override;
    void OnRemove(const std::string& key) override;
    void OnUpdate(const std::string& key) override;
    
    std::optional<std::string> GetEvictionCandidate() override;
    std::vector<std::string> GetEvictionCandidates(size_t count) override;
    
    void Clear() override;
    
private:
    std::queue<std::string> insertionOrder_;
    std::set<std::string> keys_;
    mutable std::mutex mutex_;
};

/**
 * TTL-aware policy.
 */
class TTLPolicy : public CachePolicy {
public:
    explicit TTLPolicy(std::shared_ptr<CachePolicy> basePolicy);
    
    std::string GetName() const override { return "TTL+" + basePolicy_->GetName(); }
    
    void OnInsert(const std::string& key) override;
    void OnAccess(const std::string& key) override;
    void OnRemove(const std::string& key) override;
    void OnUpdate(const std::string& key) override;
    
    std::optional<std::string> GetEvictionCandidate() override;
    std::vector<std::string> GetEvictionCandidates(size_t count) override;
    
    void Clear() override;
    
    void SetExpiration(const std::string& key, std::chrono::system_clock::time_point expiresAt);
    std::vector<std::string> GetExpiredKeys() const;
    
private:
    std::shared_ptr<CachePolicy> basePolicy_;
    std::map<std::string, std::chrono::system_clock::time_point> expirations_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Cache Backend
// ============================================================================

/**
 * Cache backend interface.
 */
class CacheBackend {
public:
    virtual ~CacheBackend() = default;
    
    // Lifecycle
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual bool IsInitialized() const = 0;
    
    // Basic operations
    virtual bool Get(const std::string& key, CacheEntry::ValueType& value) = 0;
    virtual bool Set(const std::string& key, const CacheEntry::ValueType& value,
                     std::optional<std::chrono::seconds> ttl = std::nullopt) = 0;
    virtual bool Delete(const std::string& key) = 0;
    virtual bool Exists(const std::string& key) = 0;
    
    // Batch operations
    virtual std::map<std::string, CacheEntry::ValueType> GetBatch(
        const std::vector<std::string>& keys) = 0;
    virtual bool SetBatch(const std::map<std::string, CacheEntry::ValueType>& entries,
                          std::optional<std::chrono::seconds> ttl = std::nullopt) = 0;
    virtual bool DeleteBatch(const std::vector<std::string>& keys) = 0;
    
    // Advanced operations
    virtual bool Increment(const std::string& key, int64_t delta = 1) = 0;
    virtual bool Decrement(const std::string& key, int64_t delta = 1) = 0;
    virtual bool Expire(const std::string& key, std::chrono::seconds ttl) = 0;
    virtual std::optional<std::chrono::seconds> GetTTL(const std::string& key) = 0;
    
    // Statistics
    virtual size_t GetSize() const = 0;
    virtual size_t GetMemoryUsage() const = 0;
    virtual std::vector<std::string> GetKeys() const = 0;
    virtual void Clear() = 0;
    
    // Info
    virtual std::string GetName() const = 0;
    virtual CacheType GetType() const = 0;
};

// ============================================================================
// Memory Cache
// ============================================================================

/**
 * In-memory cache implementation.
 */
class MemoryCache : public CacheBackend {
public:
    struct Config {
        size_t maxSize;
        size_t maxMemoryBytes;
        std::shared_ptr<CachePolicy> policy;
        bool enableStatistics;
    };
    
    explicit MemoryCache(const Config& config);
    
    bool Initialize() override;
    void Shutdown() override;
    bool IsInitialized() const override;
    
    bool Get(const std::string& key, CacheEntry::ValueType& value) override;
    bool Set(const std::string& key, const CacheEntry::ValueType& value,
             std::optional<std::chrono::seconds> ttl = std::nullopt) override;
    bool Delete(const std::string& key) override;
    bool Exists(const std::string& key) override;
    
    std::map<std::string, CacheEntry::ValueType> GetBatch(
        const std::vector<std::string>& keys) override;
    bool SetBatch(const std::map<std::string, CacheEntry::ValueType>& entries,
                  std::optional<std::chrono::seconds> ttl = std::nullopt) override;
    bool DeleteBatch(const std::vector<std::string>& keys) override;
    
    bool Increment(const std::string& key, int64_t delta = 1) override;
    bool Decrement(const std::string& key, int64_t delta = 1) override;
    bool Expire(const std::string& key, std::chrono::seconds ttl) override;
    std::optional<std::chrono::seconds> GetTTL(const std::string& key) override;
    
    size_t GetSize() const override;
    size_t GetMemoryUsage() const override;
    std::vector<std::string> GetKeys() const override;
    void Clear() override;
    
    std::string GetName() const override { return "MemoryCache"; }
    CacheType GetType() const override { return CacheType::MEMORY_LRU; }
    
    // Statistics
    struct CacheStats {
        uint64_t hits;
        uint64_t misses;
        uint64_t evictions;
        uint64_t expirations;
        double hitRate;
        size_t currentSize;
        size_t currentMemory;
    };
    CacheStats GetStats() const;
    void ResetStats();
    
private:
    Config config_;
    bool initialized_;
    std::map<std::string, std::shared_ptr<CacheEntry>> entries_;
    mutable std::mutex mutex_;
    size_t currentMemory_;
    CacheStats stats_;
    mutable std::mutex statsMutex_;
    
    void EvictIfNeeded();
    void RemoveExpired();
};

// ============================================================================
// Redis Cache
// ============================================================================

/**
 * Redis cache implementation.
 */
class RedisCache : public CacheBackend {
public:
    struct Config {
        std::string host;
        uint16_t port;
        std::optional<std::string> password;
        int32_t database;
        std::chrono::seconds connectionTimeout;
        std::chrono::seconds socketTimeout;
        uint32_t poolSize;
        bool useSsl;
    };
    
    explicit RedisCache(const Config& config);
    
    bool Initialize() override;
    void Shutdown() override;
    bool IsInitialized() const override;
    
    bool Get(const std::string& key, CacheEntry::ValueType& value) override;
    bool Set(const std::string& key, const CacheEntry::ValueType& value,
             std::optional<std::chrono::seconds> ttl = std::nullopt) override;
    bool Delete(const std::string& key) override;
    bool Exists(const std::string& key) override;
    
    std::map<std::string, CacheEntry::ValueType> GetBatch(
        const std::vector<std::string>& keys) override;
    bool SetBatch(const std::map<std::string, CacheEntry::ValueType>& entries,
                  std::optional<std::chrono::seconds> ttl = std::nullopt) override;
    bool DeleteBatch(const std::vector<std::string>& keys) override;
    
    bool Increment(const std::string& key, int64_t delta = 1) override;
    bool Decrement(const std::string& key, int64_t delta = 1) override;
    bool Expire(const std::string& key, std::chrono::seconds ttl) override;
    std::optional<std::chrono::seconds> GetTTL(const std::string& key) override;
    
    size_t GetSize() const override;
    size_t GetMemoryUsage() const override;
    std::vector<std::string> GetKeys() const override;
    void Clear() override;
    
    std::string GetName() const override { return "RedisCache"; }
    CacheType GetType() const override { return CacheType::REDIS; }
    
    // Redis-specific operations
    bool Publish(const std::string& channel, const std::string& message);
    std::optional<std::string> Subscribe(const std::string& channel);
    bool SetHash(const std::string& key, const std::map<std::string, std::string>& fields);
    std::map<std::string, std::string> GetHash(const std::string& key);
    bool AddToSet(const std::string& key, const std::string& member);
    std::set<std::string> GetSet(const std::string& key);
    
private:
    Config config_;
    bool initialized_;
    void* redisContext_;  // redisContext*
    mutable std::mutex mutex_;
};

// ============================================================================
// Multi-Tier Cache
// ============================================================================

/**
 * Multi-tier cache with L1 (memory) and L2 (distributed) layers.
 */
class MultiTierCache : public CacheBackend {
public:
    struct Config {
        std::shared_ptr<CacheBackend> l1Cache;
        std::shared_ptr<CacheBackend> l2Cache;
        bool l1PromoteOnAccess;
        bool l2BackupOnEvict;
        std::chrono::seconds l1DefaultTTL;
        std::chrono::seconds l2DefaultTTL;
    };
    
    explicit MultiTierCache(const Config& config);
    
    bool Initialize() override;
    void Shutdown() override;
    bool IsInitialized() const override;
    
    bool Get(const std::string& key, CacheEntry::ValueType& value) override;
    bool Set(const std::string& key, const CacheEntry::ValueType& value,
             std::optional<std::chrono::seconds> ttl = std::nullopt) override;
    bool Delete(const std::string& key) override;
    bool Exists(const std::string& key) override;
    
    std::map<std::string, CacheEntry::ValueType> GetBatch(
        const std::vector<std::string>& keys) override;
    bool SetBatch(const std::map<std::string, CacheEntry::ValueType>& entries,
                  std::optional<std::chrono::seconds> ttl = std::nullopt) override;
    bool DeleteBatch(const std::vector<std::string>& keys) override;
    
    bool Increment(const std::string& key, int64_t delta = 1) override;
    bool Decrement(const std::string& key, int64_t delta = 1) override;
    bool Expire(const std::string& key, std::chrono::seconds ttl) override;
    std::optional<std::chrono::seconds> GetTTL(const std::string& key) override;
    
    size_t GetSize() const override;
    size_t GetMemoryUsage() const override;
    std::vector<std::string> GetKeys() const override;
    void Clear() override;
    
    std::string GetName() const override { return "MultiTierCache"; }
    CacheType GetType() const override { return CacheType::MULTI_TIER; }
    
    // Tier-specific operations
    bool PromoteToL1(const std::string& key);
    bool EvictFromL1(const std::string& key);
    void WarmL1FromL2(const std::vector<std::string>& keys);
    
    // Statistics
    struct TierStats {
        uint64_t l1Hits;
        uint64_t l2Hits;
        uint64_t misses;
        uint64_t promotions;
        uint64_t evictions;
        double overallHitRate;
        double l1HitRate;
        double l2HitRate;
    };
    TierStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    TierStats stats_;
    mutable std::mutex statsMutex_;
};

// ============================================================================
// Cache Manager
// ============================================================================

/**
 * Central cache manager.
 */
class CacheManager {
public:
    struct Config {
        std::map<std::string, std::shared_ptr<CacheBackend>> caches;
        std::string defaultCache;
        bool enableMetrics;
        std::chrono::seconds cleanupInterval;
    };
    
    explicit CacheManager(const Config& config);
    ~CacheManager();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Cache management
    bool RegisterCache(const std::string& name, std::shared_ptr<CacheBackend> cache);
    void UnregisterCache(const std::string& name);
    std::shared_ptr<CacheBackend> GetCache(const std::string& name);
    std::shared_ptr<CacheBackend> GetDefaultCache();
    
    // Convenience methods
    template<typename T>
    std::optional<T> Get(const std::string& key);
    
    template<typename T>
    bool Set(const std::string& key, const T& value,
             std::optional<std::chrono::seconds> ttl = std::nullopt);
    
    bool Delete(const std::string& key);
    bool Exists(const std::string& key);
    
    // Namespaced operations
    template<typename T>
    std::optional<T> Get(const std::string& namespace_, const std::string& key);
    
    template<typename T>
    bool Set(const std::string& namespace_, const std::string& key, const T& value,
             std::optional<std::chrono::seconds> ttl = std::nullopt);
    
    bool Delete(const std::string& namespace_, const std::string& key);
    
    // Pattern operations
    std::vector<std::string> GetKeys(const std::string& pattern);
    bool DeletePattern(const std::string& pattern);
    
    // Cache-aside pattern
    template<typename T>
    std::optional<T> GetOrCompute(const std::string& key,
                                   std::function<T()> compute,
                                   std::optional<std::chrono::seconds> ttl = std::nullopt);
    
    // Cache warming
    void WarmCache(const std::vector<std::string>& keys);
    void ScheduleWarmCache(const std::vector<std::string>& keys,
                           std::chrono::seconds interval);
    
    // Invalidation
    void Invalidate(const std::string& key);
    void InvalidatePattern(const std::string& pattern);
    void InvalidateNamespace(const std::string& namespace_);
    void InvalidateAll();
    
    // Statistics
    struct ManagerStats {
        uint64_t totalGets;
        uint64_t totalSets;
        uint64_t totalDeletes;
        uint64_t hits;
        uint64_t misses;
        double hitRate;
        std::map<std::string, CacheBackend::CacheStats> cacheStats;
    };
    ManagerStats GetStats() const;
    void ResetStats();
    
    // Health check
    bool HealthCheck() const;
    std::map<std::string, bool> GetCacheHealth() const;
    
private:
    Config config_;
    bool initialized_;
    std::map<std::string, std::shared_ptr<CacheBackend>> caches_;
    std::shared_ptr<CacheBackend> defaultCache_;
    mutable std::mutex mutex_;
    
    ManagerStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread cleanupThread_;
    std::atomic<bool> stopCleanup_;
    
    std::string MakeNamespacedKey(const std::string& namespace_, const std::string& key);
    void CleanupLoop();
    void UpdateStats(bool hit);
};

// ============================================================================
// Cache Warmer
// ============================================================================

/**
 * Cache warming utility.
 */
class CacheWarmer {
public:
    struct Config {
        std::shared_ptr<CacheManager> cacheManager;
        std::chrono::seconds warmupInterval;
        size_t batchSize;
        bool enablePrefetching;
    };
    
    explicit CacheWarmer(const Config& config);
    
    // Registration
    void RegisterKey(const std::string& key, std::function<std::vector<uint8_t()> loader);
    void RegisterKeys(const std::vector<std::string>& keys,
                      std::function<std::map<std::string, std::vector<uint8_t>>()> loader);
    void UnregisterKey(const std::string& key);
    
    // Warming
    void WarmKey(const std::string& key);
    void WarmKeys(const std::vector<std::string>& keys);
    void WarmAll();
    
    // Scheduled warming
    void StartScheduledWarming();
    void StopScheduledWarming();
    
    // Prefetching
    void PrefetchRelated(const std::string& key, const std::vector<std::string>& relatedKeys);
    void EnablePrefetching(bool enable);
    
    // Statistics
    struct WarmerStats {
        uint64_t keysWarmed;
        uint64_t keysFailed;
        uint64_t prefetchHits;
        std::chrono::seconds totalWarmTime;
    };
    WarmerStats GetStats() const;
    
private:
    Config config_;
    std::map<std::string, std::function<std::vector<uint8_t>()>> loaders_;
    std::map<std::string, std::vector<std::string>> prefetchMap_;
    mutable std::mutex mutex_;
    
    WarmerStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread warmupThread_;
    std::atomic<bool> stopWarming_;
    
    void WarmupLoop();
};

// ============================================================================
// Serialization Helpers
// ============================================================================

template<typename T>
std::vector<uint8_t> Serialize(const T& value);

template<typename T>
T Deserialize(const std::vector<uint8_t>& data);

// Specializations for common types
template<>
std::vector<uint8_t> Serialize<std::string>(const std::string& value);

template<>
std::string Deserialize<std::string>(const std::vector<uint8_t>& data);

template<>
std::vector<uint8_t> Serialize<int64_t>(const int64_t& value);

template<>
int64_t Deserialize<int64_t>(const std::vector<uint8_t>& data);

template<>
std::vector<uint8_t> Serialize<double>(const double& value);

template<>
double Deserialize<double>(const std::vector<uint8_t>& data);

} // namespace Data
