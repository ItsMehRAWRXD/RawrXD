// Phase D.13 Batch 2/5: Feature Store
// Centralized feature management and serving
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace AIML {

// ============================================================================
// Feature Types
// ============================================================================

enum class FeatureType {
    NUMERIC = 0,
    CATEGORICAL = 1,
    BINARY = 2,
    TEXT = 3,
    EMBEDDING = 4,
    TIMESTAMP = 5,
    ARRAY = 6,
    JSON = 7
};

enum class FeatureSource {
    BATCH = 0,
    STREAM = 1,
    COMPUTED = 2,
    EXTERNAL = 3
};

struct FeatureMetadata {
    std::string name;
    std::string description;
    FeatureType type;
    FeatureSource source;
    std::string entity_type;
    std::string owner;
    std::vector<std::string> tags;
    std::map<std::string, std::string> labels;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::string data_type;
    std::any default_value;
    bool nullable = true;
    std::vector<std::string> validation_rules;
    std::map<std::string, std::any> statistics;
};

struct FeatureValue {
    std::string feature_name;
    std::string entity_id;
    std::any value;
    std::chrono::steady_clock::time_point timestamp;
    std::chrono::steady_clock::time_point event_timestamp;
    std::map<std::string, std::string> metadata;
};

// ============================================================================
// Feature Registry
// ============================================================================

class FeatureRegistry {
public:
    struct Config {
        std::string storage_path;
        bool enable_versioning = true;
        bool enable_lineage = true;
    };
    
    explicit FeatureRegistry(const Config& config);
    ~FeatureRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Feature registration
    bool RegisterFeature(const FeatureMetadata& metadata);
    bool UpdateFeature(const std::string& name, const FeatureMetadata& metadata);
    bool DeleteFeature(const std::string& name);
    FeatureMetadata GetFeature(const std::string& name) const;
    
    // Discovery
    std::vector<FeatureMetadata> GetAllFeatures() const;
    std::vector<FeatureMetadata> GetFeaturesByType(FeatureType type) const;
    std::vector<FeatureMetadata> GetFeaturesBySource(FeatureSource source) const;
    std::vector<FeatureMetadata> GetFeaturesByEntity(const std::string& entity_type) const;
    std::vector<FeatureMetadata> GetFeaturesByTag(const std::string& tag) const;
    
    // Search
    std::vector<FeatureMetadata> Search(const std::string& query) const;
    std::vector<FeatureMetadata> SearchByPattern(const std::string& pattern) const;
    
    // Validation
    bool ValidateFeatureName(const std::string& name) const;
    bool CheckFeatureExists(const std::string& name) const;
    bool ValidateFeatureValue(const std::string& name, const std::any& value) const;
    
    // Lineage
    void RecordLineage(const std::string& feature_name, 
                       const std::vector<std::string>& source_features);
    std::vector<std::string> GetFeatureLineage(const std::string& feature_name) const;
    std::vector<std::string> GetDownstreamFeatures(const std::string& feature_name) const;
    
private:
    Config config_;
    std::map<std::string, FeatureMetadata> features_;
    std::map<std::string, std::vector<std::string>> lineage_;
    mutable std::mutex features_mutex_;
};

// ============================================================================
// Online Feature Store
// ============================================================================

class OnlineFeatureStore {
public:
    struct Config {
        std::string backend_type = "redis";  // redis, dynamodb, bigtable
        std::string connection_string;
        int max_connections = 100;
        std::chrono::seconds ttl{86400};  // 24 hours default
        bool enable_caching = true;
        size_t cache_size_mb = 1024;
    };
    
    explicit OnlineFeatureStore(const Config& config);
    ~OnlineFeatureStore();
    
    bool Initialize();
    void Shutdown();
    
    // Write operations
    bool WriteFeature(const FeatureValue& value);
    bool WriteFeatures(const std::vector<FeatureValue>& values);
    bool WriteFeatureVector(const std::string& entity_id, 
                            const std::map<std::string, std::any>& features,
                            std::chrono::steady_clock::time_point timestamp);
    
    // Read operations
    std::optional<std::any> GetFeature(const std::string& entity_id, 
                                         const std::string& feature_name);
    std::map<std::string, std::any> GetFeatures(const std::string& entity_id,
                                               const std::vector<std::string>& feature_names);
    std::map<std::string, std::any> GetFeatureVector(const std::string& entity_id);
    
    // Batch read
    std::vector<std::map<std::string, std::any>> GetFeatureVectors(
        const std::vector<std::string>& entity_ids,
        const std::vector<std::string>& feature_names);
    
    // Point-in-time lookup
    std::optional<std::any> GetFeatureAtTime(const std::string& entity_id,
                                              const std::string& feature_name,
                                              std::chrono::steady_clock::time_point timestamp);
    
    // Delete operations
    bool DeleteFeature(const std::string& entity_id, const std::string& feature_name);
    bool DeleteEntity(const std::string& entity_id);
    
    // Statistics
    struct StoreStats {
        size_t total_entities = 0;
        size_t total_features = 0;
        size_t cache_hits = 0;
        size_t cache_misses = 0;
        double cache_hit_rate = 0.0;
        double avg_read_latency_ms = 0.0;
        double avg_write_latency_ms = 0.0;
    };
    
    StoreStats GetStats() const;
    
private:
    Config config_;
    std::unique_ptr<void, std::function<void(void*)>> backend_;
    
    // Local cache
    struct CacheEntry {
        std::any value;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::map<std::pair<std::string, std::string>, CacheEntry> cache_;
    mutable std::mutex cache_mutex_;
    
    std::atomic<size_t> cache_hits_{0};
    std::atomic<size_t> cache_misses_{0};
};

// ============================================================================
// Offline Feature Store
// ============================================================================

class OfflineFeatureStore {
public:
    struct Config {
        std::string storage_type = "parquet";  // parquet, delta, iceberg
        std::string storage_path;
        std::string partition_column = "event_timestamp";
        std::string partition_format = "year=%Y/month=%m/day=%d";
    };
    
    explicit OfflineFeatureStore(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Write operations
    bool WriteFeatures(const std::string& feature_set_name,
                       const std::vector<std::map<std::string, std::any>>& data);
    bool AppendFeatures(const std::string& feature_set_name,
                        const std::vector<std::map<std::string, std::any>>& data);
    
    // Read operations
    std::vector<std::map<std::string, std::any>> GetFeatures(
        const std::string& feature_set_name,
        const std::vector<std::string>& feature_names,
        const std::string& filter = "");
    
    // Time-based queries
    std::vector<std::map<std::string, std::any>> GetFeaturesInTimeRange(
        const std::string& feature_set_name,
        std::chrono::steady_clock::time_point start,
        std::chrono::steady_clock::time_point end);
    
    // Point-in-time join
    std::vector<std::map<std::string, std::any>> PointInTimeJoin(
        const std::string& entity_table,
        const std::vector<std::string>& feature_sets,
        const std::string& timestamp_column);
    
    // Training data generation
    std::vector<std::map<std::string, std::any>> GetTrainingData(
        const std::string& entity_table,
        const std::vector<std::string>& feature_sets,
        const std::string& label_column,
        std::chrono::steady_clock::time_point start,
        std::chrono::steady_clock::time_point end);
    
    // Materialization
    bool MaterializeToOnline(const std::string& feature_set_name,
                             OnlineFeatureStore* online_store);
    
private:
    Config config_;
};

// ============================================================================
// Feature Computation
// ============================================================================

class FeatureComputation {
public:
    struct Config {
        int max_workers = 4;
        std::chrono::seconds computation_timeout{300};
        bool enable_caching = true;
    };
    
    struct Computation {
        std::string feature_name;
        std::string entity_id;
        std::function<std::any(const std::map<std::string, std::any>&)> compute_func;
        std::vector<std::string> dependencies;
        std::chrono::seconds ttl{3600};
    };
    
    explicit FeatureComputation(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Computation registration
    bool RegisterComputation(const Computation& computation);
    bool UnregisterComputation(const std::string& feature_name);
    
    // On-demand computation
    std::any ComputeFeature(const std::string& feature_name,
                            const std::string& entity_id,
                            const std::map<std::string, std::any>& context);
    
    // Batch computation
    std::vector<std::any> ComputeFeatures(
        const std::vector<std::string>& feature_names,
        const std::vector<std::string>& entity_ids,
        const std::map<std::string, std::any>& context);
    
    // Scheduled computation
    void ScheduleComputation(const std::string& feature_name,
                             std::chrono::seconds interval);
    void CancelScheduledComputation(const std::string& feature_name);
    
private:
    Config config_;
    std::map<std::string, Computation> computations_;
    mutable std::mutex computations_mutex_;
    
    std::thread scheduler_thread_;
    std::atomic<bool> running_{false};
    
    void SchedulerLoop();
};

// ============================================================================
// Feature Monitoring
// ============================================================================

class FeatureMonitoring {
public:
    struct Config {
        bool enable_drift_detection = true;
        bool enable_statistics = true;
        std::chrono::seconds monitoring_interval{300};
        float drift_threshold = 0.05f;
    };
    
    struct FeatureStatistics {
        std::string feature_name;
        std::chrono::steady_clock::time_point computed_at;
        int64_t count = 0;
        double mean = 0.0;
        double std_dev = 0.0;
        double min = 0.0;
        double max = 0.0;
        std::map<std::string, int64_t> categorical_counts;
        double null_percent = 0.0;
    };
    
    struct DriftReport {
        std::string feature_name;
        std::chrono::steady_clock::time_point detected_at;
        float drift_score = 0.0;
        std::string drift_type;
        std::map<std::string, std::any> details;
    };
    
    explicit FeatureMonitoring(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Statistics
    FeatureStatistics ComputeStatistics(const std::string& feature_name,
                                        const std::vector<std::any>& values);
    void UpdateStatistics(const std::string& feature_name);
    FeatureStatistics GetStatistics(const std::string& feature_name) const;
    
    // Drift detection
    bool DetectDrift(const std::string& feature_name);
    std::vector<DriftReport> GetDriftReports() const;
    void SetDriftBaseline(const std::string& feature_name, 
                          const FeatureStatistics& baseline);
    
    // Alerts
    using DriftAlertHandler = std::function<void(const DriftReport&)>;
    void OnDriftDetected(DriftAlertHandler handler);
    
private:
    Config config_;
    std::map<std::string, FeatureStatistics> statistics_;
    std::map<std::string, FeatureStatistics> baselines_;
    std::vector<DriftReport> drift_reports_;
    mutable std::mutex data_mutex_;
    
    std::thread monitoring_thread_;
    std::vector<DriftAlertHandler> drift_handlers_;
    
    void MonitoringLoop();
    float CalculateDriftScore(const FeatureStatistics& current,
                              const FeatureStatistics& baseline);
};

// ============================================================================
// Feature Store Runtime
// ============================================================================

class FeatureStoreRuntime {
public:
    struct Config {
        FeatureRegistry::Config registry;
        OnlineFeatureStore::Config online;
        OfflineFeatureStore::Config offline;
        FeatureComputation::Config computation;
        FeatureMonitoring::Config monitoring;
    };
    
    explicit FeatureStoreRuntime(const Config& config);
    ~FeatureStoreRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    FeatureRegistry* GetRegistry();
    OnlineFeatureStore* GetOnlineStore();
    OfflineFeatureStore* GetOfflineStore();
    FeatureComputation* GetComputation();
    FeatureMonitoring* GetMonitoring();
    
    // High-level operations
    bool IngestFeatures(const std::string& feature_set_name,
                        const std::vector<std::map<std::string, std::any>>& data);
    
    std::vector<std::map<std::string, std::any>> GetFeatureVectors(
        const std::vector<std::string>& entity_ids,
        const std::vector<std::string>& feature_names);
    
    bool MaterializeFeatures(const std::vector<std::string>& feature_names);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<FeatureRegistry> registry_;
    std::unique_ptr<OnlineFeatureStore> online_store_;
    std::unique_ptr<OfflineFeatureStore> offline_store_;
    std::unique_ptr<FeatureComputation> computation_;
    std::unique_ptr<FeatureMonitoring> monitoring_;
};

} // namespace AIML
} // namespace Sovereign
