// Phase O.4/5: Feature Store
// RawrXD Feature Store - ML feature management and serving

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <variant>
#include <optional>

namespace RawrXD {
namespace ML {

// Feature value types
using FeatureValue = std::variant<
    int64_t,
    double,
    bool,
    std::string,
    std::vector<int64_t>,
    std::vector<double>,
    std::vector<std::string>
>;

// Feature types
enum class FeatureType {
    NUMERIC,        // Scalar numeric
    CATEGORICAL,    // Discrete categories
    EMBEDDING,      // Dense vector
    BINARY,         // True/false
    TEXT,           // String/text data
    TIMESTAMP,      // Date/time
    ARRAY,          // List of values
    JSON            // Complex structured data
};

// Feature definition
struct Feature {
    std::string name;
    std::string description;
    FeatureType type;
    
    // Metadata
    std::string entity_type;    // e.g., "user", "item", "session"
    std::string owner;          // Team or individual
    std::vector<std::string> tags;
    
    // Schema
    struct Schema {
        bool nullable;
        FeatureValue default_value;
        std::optional<double> min_value;      // For numeric
        std::optional<double> max_value;      // For numeric
        std::optional<uint32_t> embedding_dim;  // For embeddings
        std::vector<std::string> allowed_values;  // For categorical
    } schema;
    
    // Statistics
    struct Statistics {
        uint64_t total_count;
        uint64_t null_count;
        double mean;
        double std_dev;
        double min;
        double max;
        std::chrono::system_clock::time_point last_updated;
    } statistics;
    
    // Lineage
    std::string source;         // Data source
    std::string transformation; // Transformation logic
    std::vector<std::string> dependencies;  // Other features this depends on
    
    // Serving
    bool online_serving;      // Available for real-time serving
    bool offline_serving;     // Available for batch/training
    uint32_t ttl_seconds;     // Time-to-live for cached values
};

// Feature vector for an entity
struct FeatureVector {
    std::string entity_id;
    std::string entity_type;
    std::chrono::system_clock::time_point timestamp;
    std::unordered_map<std::string, FeatureValue> features;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> feature_timestamps;
};

// Feature set (collection of features)
struct FeatureSet {
    std::string id;
    std::string name;
    std::string description;
    std::string entity_type;
    std::vector<std::string> feature_names;
    std::vector<std::string> tags;
    std::string owner;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
    uint32_t version;
};

// Feature value with metadata
struct FeatureRecord {
    std::string entity_id;
    std::string feature_name;
    FeatureValue value;
    std::chrono::system_clock::time_point event_timestamp;
    std::chrono::system_clock::time_point ingestion_timestamp;
    std::unordered_map<std::string, std::string> metadata;
};

// Feature store interface
class IFeatureStore {
public:
    virtual ~IFeatureStore() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config) = 0;
    virtual void Shutdown() = 0;
    
    // Feature definition management
    virtual bool RegisterFeature(const Feature& feature) = 0;
    virtual bool UpdateFeature(const Feature& feature) = 0;
    virtual bool DeleteFeature(const std::string& feature_name) = 0;
    virtual std::optional<Feature> GetFeature(const std::string& feature_name) = 0;
    virtual std::vector<Feature> ListFeatures(const std::string& entity_type = "") = 0;
    virtual std::vector<Feature> SearchFeatures(const std::string& query) = 0;
    
    // Feature set management
    virtual std::string CreateFeatureSet(const FeatureSet& feature_set) = 0;
    virtual bool UpdateFeatureSet(const std::string& feature_set_id, const FeatureSet& feature_set) = 0;
    virtual bool DeleteFeatureSet(const std::string& feature_set_id) = 0;
    virtual std::optional<FeatureSet> GetFeatureSet(const std::string& feature_set_id) = 0;
    virtual std::vector<FeatureSet> ListFeatureSets(const std::string& entity_type = "") = 0;
    
    // Online serving (low latency)
    virtual std::optional<FeatureValue> GetOnlineFeature(
        const std::string& entity_id,
        const std::string& feature_name) = 0;
    virtual FeatureVector GetOnlineFeatures(
        const std::string& entity_id,
        const std::vector<std::string>& feature_names) = 0;
    virtual std::vector<FeatureVector> GetOnlineFeaturesBatch(
        const std::vector<std::string>& entity_ids,
        const std::vector<std::string>& feature_names) = 0;
    
    // Offline serving (batch)
    virtual std::vector<FeatureRecord> GetOfflineFeatures(
        const std::string& entity_type,
        const std::vector<std::string>& feature_names,
        std::chrono::system_clock::time_point start_time,
        std::chrono::system_clock::time_point end_time) = 0;
    virtual bool ExportFeaturesToDataset(
        const std::string& feature_set_id,
        const std::string& output_path,
        const std::string& format = "parquet") = 0;
    
    // Ingestion
    virtual bool IngestFeature(const FeatureRecord& record) = 0;
    virtual bool IngestFeaturesBatch(const std::vector<FeatureRecord>& records) = 0;
    virtual bool IngestFromDataSource(
        const std::string& feature_name,
        const std::string& data_source_config) = 0;
    
    // Point-in-time correctness
    virtual FeatureVector GetFeaturesAtTime(
        const std::string& entity_id,
        const std::vector<std::string>& feature_names,
        std::chrono::system_clock::time_point timestamp) = 0;
    
    // Statistics and monitoring
    virtual Feature::Statistics GetFeatureStatistics(const std::string& feature_name) = 0;
    virtual bool ComputeFeatureStatistics(const std::string& feature_name) = 0;
    virtual bool DetectFeatureDrift(const std::string& feature_name,
                                     std::chrono::system_clock::time_point window_start,
                                     std::chrono::system_clock::time_point window_end) = 0;
    
    // Validation
    virtual bool ValidateFeatureValue(const std::string& feature_name,
                                       const FeatureValue& value) = 0;
    virtual std::vector<std::string> ValidateFeatureSet(const std::string& feature_set_id) = 0;
    
    // Materialization
    virtual bool MaterializeFeatureSet(const std::string& feature_set_id) = 0;
    virtual bool ScheduleMaterialization(const std::string& feature_set_id,
                                          const std::string& schedule) = 0;
};

// In-memory feature store (for development/testing)
class InMemoryFeatureStore : public IFeatureStore {
public:
    InMemoryFeatureStore();
    ~InMemoryFeatureStore() override;
    
    bool Initialize(const std::string& config) override;
    void Shutdown() override;
    
    bool RegisterFeature(const Feature& feature) override;
    bool UpdateFeature(const Feature& feature) override;
    bool DeleteFeature(const std::string& feature_name) override;
    std::optional<Feature> GetFeature(const std::string& feature_name) override;
    std::vector<Feature> ListFeatures(const std::string& entity_type = "") override;
    std::vector<Feature> SearchFeatures(const std::string& query) override;
    
    std::string CreateFeatureSet(const FeatureSet& feature_set) override;
    bool UpdateFeatureSet(const std::string& feature_set_id, const FeatureSet& feature_set) override;
    bool DeleteFeatureSet(const std::string& feature_set_id) override;
    std::optional<FeatureSet> GetFeatureSet(const std::string& feature_set_id) override;
    std::vector<FeatureSet> ListFeatureSets(const std::string& entity_type = "") override;
    
    std::optional<FeatureValue> GetOnlineFeature(
        const std::string& entity_id,
        const std::string& feature_name) override;
    FeatureVector GetOnlineFeatures(
        const std::string& entity_id,
        const std::vector<std::string>& feature_names) override;
    std::vector<FeatureVector> GetOnlineFeaturesBatch(
        const std::vector<std::string>& entity_ids,
        const std::vector<std::string>& feature_names) override;
    
    std::vector<FeatureRecord> GetOfflineFeatures(
        const std::string& entity_type,
        const std::vector<std::string>& feature_names,
        std::chrono::system_clock::time_point start_time,
        std::chrono::system_clock::time_point end_time) override;
    bool ExportFeaturesToDataset(
        const std::string& feature_set_id,
        const std::string& output_path,
        const std::string& format = "parquet") override;
    
    bool IngestFeature(const FeatureRecord& record) override;
    bool IngestFeaturesBatch(const std::vector<FeatureRecord>& records) override;
    bool IngestFromDataSource(
        const std::string& feature_name,
        const std::string& data_source_config) override;
    
    FeatureVector GetFeaturesAtTime(
        const std::string& entity_id,
        const std::vector<std::string>& feature_names,
        std::chrono::system_clock::time_point timestamp) override;
    
    Feature::Statistics GetFeatureStatistics(const std::string& feature_name) override;
    bool ComputeFeatureStatistics(const std::string& feature_name) override;
    bool DetectFeatureDrift(const std::string& feature_name,
                             std::chrono::system_clock::time_point window_start,
                             std::chrono::system_clock::time_point window_end) override;
    
    bool ValidateFeatureValue(const std::string& feature_name,
                               const FeatureValue& value) override;
    std::vector<std::string> ValidateFeatureSet(const std::string& feature_set_id) override;
    
    bool MaterializeFeatureSet(const std::string& feature_set_id) override;
    bool ScheduleMaterialization(const std::string& feature_set_id,
                                  const std::string& schedule) override;
    
private:
    std::unordered_map<std::string, Feature> features_;
    std::unordered_map<std::string, FeatureSet> feature_sets_;
    std::unordered_map<std::string, std::unordered_map<std::string, FeatureValue>> online_store_;  // entity -> features
    std::vector<FeatureRecord> offline_store_;
    bool initialized_ = false;
};

// Feature transformation
class FeatureTransformer {
public:
    // Common transformations
    static FeatureValue Normalize(const FeatureValue& value, double mean, double std_dev);
    static FeatureValue Standardize(const FeatureValue& value, double min, double max);
    static FeatureValue OneHotEncode(const std::string& value, const std::vector<std::string>& categories);
    static FeatureValue Bucketize(double value, const std::vector<double>& boundaries);
    static FeatureValue Tokenize(const std::string& text, uint32_t max_length = 512);
    static FeatureValue ExtractEmbedding(const std::string& text, const std::string& model_id);
    
    // Time-based features
    static FeatureValue ExtractHour(std::chrono::system_clock::time_point timestamp);
    static FeatureValue ExtractDayOfWeek(std::chrono::system_clock::time_point timestamp);
    static FeatureValue ExtractMonth(std::chrono::system_clock::time_point timestamp);
    static FeatureValue TimeSinceLastEvent(std::chrono::system_clock::time_point current,
                                            std::chrono::system_clock::time_point last);
};

// Feature monitoring
struct FeatureDrift {
    std::string feature_name;
    double drift_score;
    std::string drift_type;  // "statistical", "concept", "data_quality"
    std::chrono::system_clock::time_point detected_at;
    std::unordered_map<std::string, double> metrics;
};

class FeatureMonitor {
public:
    bool DetectDrift(const std::string& feature_name,
                     const std::vector<FeatureValue>& baseline,
                     const std::vector<FeatureValue>& current);
    
    bool DetectNullRatioChange(const std::string& feature_name,
                                double baseline_null_ratio,
                                double current_null_ratio);
    
    bool DetectRangeViolation(const std::string& feature_name,
                               const FeatureValue& value,
                               const Feature::Schema& schema);
    
    std::vector<FeatureDrift> GetActiveDrifts();
    void ClearDrift(const std::string& feature_name);
    
private:
    std::unordered_map<std::string, FeatureDrift> active_drifts_;
};

// Global feature store
extern std::unique_ptr<IFeatureStore> g_feature_store;

// Initialize feature store
bool InitializeFeatureStore(const std::string& config);
void ShutdownFeatureStore();
bool IsFeatureStoreEnabled();

} // namespace ML
} // namespace RawrXD
