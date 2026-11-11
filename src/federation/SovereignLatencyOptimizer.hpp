// Phase D.5 Batch 5/5: Latency Optimization
// Edge Caching and Request Routing
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignGlobalLoadBalancer.hpp"
#include "SovereignCrossRegionReplication.hpp"
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Federation {

// ============================================================================
// Edge Cache Types
// ============================================================================

enum class CachePolicy {
    LRU = 0,            // Least Recently Used
    LFU = 1,            // Least Frequently Used
    FIFO = 2,           // First In First Out
    TTL = 3,            // Time To Live
    ADAPTIVE = 4        // Adaptive based on access patterns
};

struct CacheEntry {
    std::string key;
    std::vector<uint8_t> data;
    int64_t size_bytes = 0;
    int access_count = 0;
    std::chrono::steady_clock::time_point created;
    std::chrono::steady_clock::time_point last_access;
    std::chrono::steady_clock::time_point expires;
    std::string source_region;
    int version = 0;
    bool compressed = false;
};

struct EdgeCache {
    std::string cache_id;
    std::string region_id;
    std::string endpoint;
    int64_t capacity_bytes = 0;
    int64_t used_bytes = 0;
    int64_t hit_count = 0;
    int64_t miss_count = 0;
    double hit_ratio = 0.0;
    CachePolicy policy = CachePolicy::LRU;
    
    std::map<std::string, CacheEntry> entries;
    std::chrono::steady_clock::time_point last_sync;
};

// ============================================================================
// Request Routing
// ============================================================================

struct RoutingPreference {
    std::string client_region;
    std::string preferred_region;
    int max_latency_ms = 100;
    bool require_consistency = false;
    bool allow_stale_reads = true;
    int max_staleness_ms = 1000;
};

struct RoutingDecisionV2 {
    std::string target_region;
    std::string target_endpoint;
    bool cache_hit = false;
    std::string cache_id;
    double estimated_latency_ms = 0.0;
    bool is_stale = false;
    int staleness_ms = 0;
    std::vector<std::string> fallback_regions;
};

// ============================================================================
// Edge Cache Manager
// ============================================================================

class EdgeCacheManager {
public:
    struct Config {
        int64_t default_cache_size_mb = 1024;  // 1GB
        CachePolicy default_policy = CachePolicy::ADAPTIVE;
        int ttl_seconds = 300;
        int sync_interval_ms = 10000;
        bool compress_large_entries = true;
        int64_t compression_threshold_bytes = 1024;
        bool enable_invalidation = true;
    };
    
    explicit EdgeCacheManager(const Config& config);
    ~EdgeCacheManager();
    
    bool Initialize();
    void Shutdown();
    
    // Cache management
    bool RegisterCache(const EdgeCache& cache);
    bool DeregisterCache(const std::string& cache_id);
    std::vector<EdgeCache> GetCaches() const;
    std::vector<EdgeCache> GetCachesForRegion(const std::string& region_id) const;
    
    // Cache operations
    bool Put(const std::string& cache_id, const std::string& key, 
             const std::vector<uint8_t>& data, int ttl_seconds = 0);
    std::vector<uint8_t> Get(const std::string& cache_id, const std::string& key);
    bool Invalidate(const std::string& cache_id, const std::string& key);
    bool InvalidatePattern(const std::string& cache_id, const std::string& pattern);
    bool InvalidateRegion(const std::string& region_id);
    
    // Cache warming
    bool WarmCache(const std::string& cache_id, 
                   const std::vector<std::string>& keys);
    bool PreloadHotData(const std::string& region_id);
    
    // Statistics
    struct Stats {
        int64_t total_hits = 0;
        int64_t total_misses = 0;
        double global_hit_ratio = 0.0;
        int64_t bytes_cached = 0;
        int64_t invalidations_sent = 0;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread sync_thread_;
    
    mutable std::mutex caches_mutex_;
    std::map<std::string, EdgeCache> caches_;
    
    std::atomic<int64_t> total_hits_{0};
    std::atomic<int64_t> total_misses_{0};
    std::atomic<int64_t> invalidations_sent_{0};
    
    void SyncLoop();
    void EvictIfNeeded(EdgeCache& cache, int64_t required_space);
    void UpdateHitRatio(EdgeCache& cache);
    std::vector<uint8_t> Compress(const std::vector<uint8_t>& data);
    std::vector<uint8_t> Decompress(const std::vector<uint8_t>& data);
};

// ============================================================================
// Smart Router
// ============================================================================

class SmartRouter {
public:
    struct Config {
        int max_hops = 3;
        int circuit_breaker_threshold = 5;
        int circuit_breaker_timeout_ms = 30000;
        bool enable_retry = true;
        int max_retries = 3;
        int retry_base_delay_ms = 100;
        bool enable_shadow_traffic = false;
        int shadow_traffic_percent = 1;
    };
    
    explicit SmartRouter(const Config& config);
    
    bool Initialize(GlobalLoadBalancer* load_balancer,
                    EdgeCacheManager* cache_manager,
                    CrossRegionReplication* replication);
    
    // Routing
    RoutingDecisionV2 Route(const std::string& client_region,
                            const std::string& key,
                            const RoutingPreference& preference);
    
    // Circuit breaker
    void ReportSuccess(const std::string& region_id);
    void ReportFailure(const std::string& region_id);
    bool IsCircuitOpen(const std::string& region_id);
    void ResetCircuit(const std::string& region_id);
    
    // Retry logic
    template<typename Func>
    auto ExecuteWithRetry(Func&& operation, const std::vector<std::string>& fallback_regions)
        -> decltype(operation());
    
private:
    Config config_;
    GlobalLoadBalancer* load_balancer_ = nullptr;
    EdgeCacheManager* cache_manager_ = nullptr;
    CrossRegionReplication* replication_ = nullptr;
    
    struct CircuitState {
        int failure_count = 0;
        bool open = false;
        std::chrono::steady_clock::time_point last_failure;
    };
    
    mutable std::mutex circuits_mutex_;
    std::map<std::string, CircuitState> circuits_;
    
    void OpenCircuit(const std::string& region_id);
    void CloseCircuit(const std::string& region_id);
};

// ============================================================================
// Data Locality Manager
// ============================================================================

class DataLocalityManager {
public:
    struct Config {
        int locality_threshold_ms = 50;
        bool auto_migrate = true;
        int migration_cooldown_ms = 3600000;  // 1 hour
        double hot_data_threshold = 0.8;  // 80% of requests
    };
    
    explicit DataLocalityManager(const Config& config);
    
    bool Initialize(CrossRegionReplication* replication);
    
    // Access tracking
    void RecordAccess(const std::string& key, const std::string& region_id);
    void RecordAccessPattern(const std::string& key, 
                             const std::vector<std::string>& regions);
    
    // Locality analysis
    std::string GetOptimalRegionForKey(const std::string& key);
    std::vector<std::string> GetHotKeys(const std::string& region_id);
    std::map<std::string, std::string> GetKeyLocalityMap();
    
    // Migration
    bool ShouldMigrate(const std::string& key, 
                       const std::string& current_region,
                       const std::string& target_region);
    bool InitiateMigration(const std::string& key,
                           const std::string& source_region,
                           const std::string& target_region);
    
    // Prefetching
    std::vector<std::string> PredictAccesses(const std::string& region_id);
    bool PrefetchToRegion(const std::vector<std::string>& keys,
                          const std::string& region_id);
    
private:
    Config config_;
    CrossRegionReplication* replication_ = nullptr;
    
    struct AccessStats {
        std::map<std::string, int64_t> region_accesses;
        int64_t total_accesses = 0;
        std::chrono::steady_clock::time_point last_access;
    };
    
    mutable std::mutex stats_mutex_;
    std::map<std::string, AccessStats> key_stats_;
    std::map<std::string, std::chrono::steady_clock::time_point> last_migration_;
    
    void CleanupOldStats();
};

// ============================================================================
// Latency Monitor V2
// ============================================================================

class LatencyMonitorV2 {
public:
    struct Config {
        int probe_interval_ms = 5000;
        int probe_timeout_ms = 2000;
        int history_size = 1000;
        bool enable_adaptive_probing = true;
        int min_probe_interval_ms = 1000;
        int max_probe_interval_ms = 30000;
    };
    
    explicit LatencyMonitorV2(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Probing
    void AddTarget(const std::string& region_id, const std::string& endpoint);
    void RemoveTarget(const std::string& region_id);
    
    // Measurements
    void RecordLatency(const std::string& region_id, double latency_ms);
    double GetLatency(const std::string& region_id) const;
    double GetLatencyPercentile(const std::string& region_id, double percentile) const;
    
    // Adaptive probing
    void AdjustProbeInterval(const std::string& region_id);
    int GetProbeInterval(const std::string& region_id) const;
    
    // Anomaly detection
    bool IsAnomaly(const std::string& region_id, double latency_ms);
    std::vector<std::string> GetAnomalousRegions() const;
    
    // Statistics
    struct Stats {
        std::map<std::string, double> avg_latencies;
        std::map<std::string, double> p99_latencies;
        std::map<std::string, int> probe_intervals;
        int64_t total_probes = 0;
        int64_t failed_probes = 0;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread probe_thread_;
    
    struct LatencyHistory {
        std::vector<double> latencies;
        double ewma = 0.0;  // Exponentially weighted moving average
        int probe_interval_ms;
        int64_t failed_probes = 0;
    };
    
    mutable std::mutex history_mutex_;
    std::map<std::string, LatencyHistory> histories_;
    std::map<std::string, std::string> targets_;
    
    std::atomic<int64_t> total_probes_{0};
    std::atomic<int64_t> failed_probes_{0};
    
    void ProbeLoop();
    double ProbeTarget(const std::string& endpoint);
    void UpdateEWMA(LatencyHistory& history, double latency);
};

} // namespace Federation
} // namespace Sovereign
