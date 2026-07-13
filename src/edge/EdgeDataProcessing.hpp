/**
 * EdgeDataProcessing.hpp
 *
 * Phase R Batch 3/5: Edge Data Processing
 *
 * Stream processing, data aggregation, and local analytics
 * for edge computing with offline capabilities.
 */

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <queue>

namespace Edge {

// ============================================================================
// Forward Declarations
// ============================================================================

class StreamProcessor;
class DataAggregator;
class EdgeAnalytics;
class LocalInference;

// ============================================================================
// Data Types
// ============================================================================

enum class DataType {
    SENSOR,
    METRIC,
    LOG,
    EVENT,
    IMAGE,
    AUDIO,
    VIDEO,
    BINARY,
    JSON,
    CUSTOM
};

// ============================================================================
// Data Point
// ============================================================================

struct DataPoint {
    std::string id;
    std::string source;
    DataType type;
    std::vector<uint8_t> payload;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
    std::optional<std::string> tenantId;
    std::optional<std::string> deviceId;
    
    template<typename T>
    T GetPayloadAs() const;
    
    std::string GetPayloadAsString() const;
    std::string ToJson() const;
    static DataPoint FromJson(const std::string& json);
};

// ============================================================================
// Stream Processor
// ============================================================================

class StreamProcessor {
public:
    struct Config {
        uint32_t maxConcurrency = 4;
        uint32_t batchSize = 100;
        std::chrono::milliseconds batchTimeout{1000};
        bool enableBackpressure = true;
        uint32_t maxQueueSize = 10000;
        bool enableExactlyOnce = false;
    };
    
    struct ProcessingContext {
        std::string streamId;
        std::chrono::system_clock::time_point processingTime;
        std::map<std::string, std::any> state;
        uint64_t sequenceNumber;
    };
    
    using DataTransformer = std::function<std::vector<DataPoint>(
        const DataPoint&, ProcessingContext&)>;
    using DataFilter = std::function<bool(const DataPoint&, const ProcessingContext&)>;
    using DataSink = std::function<void(const std::vector<DataPoint>&)>;
    
    explicit StreamProcessor(const Config& config);
    ~StreamProcessor();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const;
    
    // Pipeline building
    void AddSource(const std::string& name, std::function<std::optional<DataPoint>()> source);
    void AddTransformer(DataTransformer transformer);
    void AddFilter(DataFilter filter);
    void AddSink(const std::string& name, DataSink sink);
    
    // Processing
    void Submit(const DataPoint& data);
    void SubmitBatch(const std::vector<DataPoint>& data);
    
    // Windowing
    enum class WindowType {
        TUMBLING,    // Fixed time windows
        SLIDING,     // Overlapping windows
        SESSION,     // Activity-based windows
        GLOBAL       // Single window for all data
    };
    
    void AddWindowedOperation(WindowType type,
                              std::chrono::milliseconds duration,
                              std::function<void(const std::vector<DataPoint>&)> processor,
                              std::optional<std::chrono::milliseconds> slide = std::nullopt);
    
    // State management
    void SetState(const std::string& key, const std::any& value);
    std::optional<std::any> GetState(const std::string& key) const;
    void ClearState();
    
    // Checkpointing
    void Checkpoint();
    void RestoreFromCheckpoint(const std::string& checkpointId);
    
    // Statistics
    struct ProcessorStats {
        uint64_t pointsProcessed;
        uint64_t pointsFiltered;
        uint64_t pointsTransformed;
        uint64_t batchesProcessed;
        double averageProcessingTimeMs;
        uint32_t currentQueueSize;
        uint64_t droppedPoints;
    };
    ProcessorStats GetStats() const;
    
private:
    Config config_;
    bool running_;
    
    std::queue<DataPoint> inputQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCv_;
    
    std::vector<std::function<std::optional<DataPoint>()>> sources_;
    std::vector<DataTransformer> transformers_;
    std::vector<DataFilter> filters_;
    std::vector<DataSink> sinks_;
    
    std::map<std::string, std::any> state_;
    mutable std::mutex stateMutex_;
    
    std::vector<std::thread> workerThreads_;
    std::thread sourceThread_;
    
    ProcessorStats stats_;
    mutable std::mutex statsMutex_;
    
    void ProcessingLoop();
    void SourceLoop();
    void ProcessBatch(const std::vector<DataPoint>& batch);
};

// ============================================================================
// Data Aggregator
// ============================================================================

class DataAggregator {
public:
    struct Config {
        std::chrono::seconds aggregationInterval{60};
        uint32_t maxBuckets = 1000;
        bool enableCompression = true;
        std::chrono::hours retentionPeriod{24};
    };
    
    enum class AggregationFunction {
        SUM,
        AVG,
        MIN,
        MAX,
        COUNT,
        FIRST,
        LAST,
        PERCENTILE_50,
        PERCENTILE_95,
        PERCENTILE_99,
        CUSTOM
    };
    
    struct AggregationRule {
        std::string name;
        std::string sourcePattern;
        AggregationFunction function;
        std::optional<std::chrono::seconds> window;
        std::vector<std::string> groupBy;
        std::optional<std::string> filter;
        bool emitOnChange;
    };
    
    struct AggregationResult {
        std::string ruleName;
        std::chrono::system_clock::time_point timestamp;
        std::map<std::string, std::string> dimensions;
        double value;
        uint64_t sampleCount;
        std::optional<double> min;
        std::optional<double> max;
        std::optional<double> stdDev;
    };
    
    explicit DataAggregator(const Config& config);
    ~DataAggregator();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const;
    
    // Rule management
    void AddRule(const AggregationRule& rule);
    void RemoveRule(const std::string& name);
    void UpdateRule(const std::string& name, const AggregationRule& rule);
    std::vector<AggregationRule> GetRules() const;
    
    // Data ingestion
    void Ingest(const DataPoint& point);
    void IngestBatch(const std::vector<DataPoint>& points);
    
    // Querying
    std::vector<AggregationResult> Query(const std::string& ruleName,
                                           std::chrono::system_clock::time_point from,
                                           std::chrono::system_clock::time_point to) const;
    std::vector<AggregationResult> QueryLatest(const std::string& ruleName,
                                                uint32_t count = 1) const;
    
    // Real-time aggregations
    std::optional<double> GetCurrentValue(const std::string& ruleName) const;
    std::map<std::string, double> GetCurrentValues() const;
    
    // Export
    std::string ExportToCsv(const std::string& ruleName,
                           std::chrono::system_clock::time_point from,
                           std::chrono::system_clock::time_point to) const;
    std::string ExportToJson(const std::string& ruleName,
                            std::chrono::system_clock::time_point from,
                            std::chrono::system_clock::time_point to) const;
    
    // Maintenance
    void Compact();
    void PurgeOldData();
    
    // Statistics
    struct AggregatorStats {
        uint64_t pointsIngested;
        uint64_t aggregationsComputed;
        uint64_t bytesStored;
        uint32_t activeRules;
        double averageAggregationTimeMs;
    };
    AggregatorStats GetStats() const;
    
private:
    Config config_;
    bool running_;
    
    std::map<std::string, AggregationRule> rules_;
    mutable std::mutex rulesMutex_;
    
    struct Bucket {
        std::chrono::system_clock::time_point timestamp;
        std::vector<double> values;
        double sum;
        double min;
        double max;
    };
    
    std::map<std::string, std::vector<Bucket>> buckets_;
    mutable std::mutex bucketsMutex_;
    
    std::thread aggregationThread_;
    std::atomic<bool> stopAggregation_;
    
    AggregatorStats stats_;
    mutable std::mutex statsMutex_;
    
    void AggregationLoop();
    void ProcessAggregation(const AggregationRule& rule);
    double ComputeAggregation(const std::vector<double>& values, 
                              AggregationFunction func) const;
    void PruneOldBuckets();
};

// ============================================================================
// Edge Analytics
// ============================================================================

class EdgeAnalytics {
public:
    struct Config {
        bool enableLocalML = true;
        uint32_t maxConcurrentQueries = 10;
        std::chrono::seconds queryTimeout{30};
        bool cacheResults = true;
        std::chrono::seconds cacheTtl{300};
    };
    
    struct Query {
        std::string queryId;
        std::string queryString;
        std::map<std::string, std::any> parameters;
        std::chrono::system_clock::time_point submittedAt;
        std::optional<std::chrono::seconds> timeout;
    };
    
    struct QueryResult {
        std::string queryId;
        bool success;
        std::vector<std::map<std::string, std::any>> rows;
        std::optional<std::string> error;
        std::chrono::milliseconds executionTime;
        std::chrono::system_clock::time_point completedAt;
    };
    
    explicit EdgeAnalytics(const Config& config);
    ~EdgeAnalytics();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Query execution
    QueryResult ExecuteQuery(const std::string& query);
    QueryResult ExecuteQuery(const std::string& query,
                             const std::map<std::string, std::any>& parameters);
    std::future<QueryResult> ExecuteQueryAsync(const std::string& query);
    
    // Predefined queries
    void RegisterQuery(const std::string& name, 
                       const std::string& queryTemplate,
                       const std::vector<std::string>& parameters);
    QueryResult ExecuteNamedQuery(const std::string& name,
                                   const std::map<std::string, std::any>& parameters);
    
    // Data sources
    void RegisterDataSource(const std::string& name,
                            std::function<std::vector<DataPoint>(const std::string&)> source);
    void UnregisterDataSource(const std::string& name);
    
    // Anomaly detection
    void EnableAnomalyDetection(const std::string& metricName,
                                 double threshold,
                                 std::function<void(const DataPoint&)> callback);
    void DisableAnomalyDetection(const std::string& metricName);
    
    // Trend analysis
    struct TrendResult {
        std::string metric;
        double slope;
        double intercept;
        double rSquared;
        std::chrono::system_clock::time_point from;
        std::chrono::system_clock::time_point to;
        std::string direction;  // "increasing", "decreasing", "stable"
    };
    
    TrendResult AnalyzeTrend(const std::string& metric,
                             std::chrono::system_clock::time_point from,
                             std::chrono::system_clock::time_point to);
    
    // Forecasting
    struct ForecastResult {
        std::string metric;
        std::vector<std::pair<std::chrono::system_clock::time_point, double>> predictions;
        double confidenceInterval;
        std::string modelUsed;
    };
    
    ForecastResult Forecast(const std::string& metric,
                           uint32_t periods,
                           std::chrono::seconds periodDuration);
    
    // Statistics
    struct AnalyticsStats {
        uint64_t queriesExecuted;
        uint64_t queriesCached;
        double averageQueryTimeMs;
        uint32_t activeQueries;
        uint64_t anomaliesDetected;
        uint64_t forecastsGenerated;
    };
    AnalyticsStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::string> queryTemplates_;
    std::map<std::string, std::function<std::vector<DataPoint>(const std::string&)>> dataSources_;
    mutable std::mutex dataMutex_;
    
    std::map<std::string, QueryResult> cache_;
    mutable std::mutex cacheMutex_;
    
    std::map<std::string, std::pair<double, std::function<void(const DataPoint&)>>> anomalyDetectors_;
    mutable std::mutex anomalyMutex_;
    
    AnalyticsStats stats_;
    mutable std::mutex statsMutex_;
    
    QueryResult ExecuteQueryInternal(const Query& query);
    std::string GenerateCacheKey(const std::string& query,
                                    const std::map<std::string, std::any>& params) const;
    void DetectAnomalies(const DataPoint& point);
};

// ============================================================================
// Local Inference
// ============================================================================

class LocalInference {
public:
    struct Config {
        uint32_t maxModelCacheSize = 5;  // Number of models
        bool enableGPU = false;
        uint32_t inferenceThreads = 2;
        std::chrono::seconds modelUnloadTimeout{300};
        bool enableBatching = true;
        uint32_t maxBatchSize = 32;
    };
    
    struct ModelInfo {
        std::string modelId;
        std::string name;
        std::string version;
        std::string format;  // ONNX, TensorRT, TFLite, etc.
        uint64_t modelSizeBytes;
        std::vector<std::string> inputs;
        std::vector<std::string> outputs;
        std::map<std::string, std::string> metadata;
    };
    
    struct InferenceRequest {
        std::string requestId;
        std::string modelId;
        std::map<std::string, std::vector<float>> inputs;
        std::optional<std::chrono::milliseconds> timeout;
        std::optional<std::string> tenantId;
        std::map<std::string, std::string> metadata;
    };
    
    struct InferenceResult {
        std::string requestId;
        bool success;
        std::map<std::string, std::vector<float>> outputs;
        std::chrono::milliseconds inferenceTime;
        std::optional<std::string> error;
        std::map<std::string, std::string> metadata;
    };
    
    explicit LocalInference(const Config& config);
    ~LocalInference();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Model management
    bool LoadModel(const std::string& modelPath, const ModelInfo& info);
    void UnloadModel(const std::string& modelId);
    bool IsModelLoaded(const std::string& modelId) const;
    std::vector<ModelInfo> GetLoadedModels() const;
    
    // Inference
    InferenceResult RunInference(const InferenceRequest& request);
    std::vector<InferenceResult> RunBatchInference(
        const std::vector<InferenceRequest>& requests);
    std::future<InferenceResult> RunInferenceAsync(const InferenceRequest& request);
    
    // Streaming inference
    using StreamCallback = std::function<void(const InferenceResult&)>;
    void RunStreamingInference(const InferenceRequest& request, StreamCallback callback);
    
    // Model warmup
    void WarmupModel(const std::string& modelId, uint32_t iterations = 10);
    
    // Statistics
    struct InferenceStats {
        uint64_t inferencesRun;
        uint64_t batchInferencesRun;
        double averageInferenceTimeMs;
        double averageBatchSize;
        uint64_t cacheHits;
        uint64_t cacheMisses;
        std::map<std::string, uint64_t> inferencesByModel;
    };
    InferenceStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    struct CachedModel {
        ModelInfo info;
        void* modelHandle;  // Platform-specific
        std::chrono::system_clock::time_point lastUsed;
        uint64_t inferenceCount;
    };
    
    std::map<std::string, CachedModel> modelCache_;
    mutable std::mutex cacheMutex_;
    
    std::queue<InferenceRequest> requestQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCv_;
    
    std::vector<std::thread> inferenceThreads_;
    std::atomic<bool> stopInference_;
    
    InferenceStats stats_;
    mutable std::mutex statsMutex_;
    
    void InferenceLoop();
    InferenceResult ExecuteInference(const InferenceRequest& request);
    void EvictLeastRecentlyUsedModel();
};

// ============================================================================
// Offline Buffer
// ============================================================================

class OfflineBuffer {
public:
    struct Config {
        size_t maxBufferSize = 100 * 1024 * 1024;  // 100MB
        uint32_t maxItems = 100000;
        std::chrono::seconds flushInterval{60};
        bool persistentStorage = true;
        std::string storagePath;
        bool compressionEnabled = true;
    };
    
    explicit OfflineBuffer(const Config& config);
    ~OfflineBuffer();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Buffering
    bool Buffer(const DataPoint& point);
    bool BufferBatch(const std::vector<DataPoint>& points);
    
    // Flushing
    std::vector<DataPoint> Flush();
    std::vector<DataPoint> Flush(uint32_t maxItems);
    void FlushToCallback(std::function<void(const std::vector<DataPoint>&)> callback);
    
    // Connectivity awareness
    void SetConnectivityState(bool connected);
    bool IsConnected() const;
    void OnConnectivityRestored(std::function<void()> callback);
    
    // Statistics
    struct BufferStats {
        uint64_t itemsBuffered;
        uint64_t itemsFlushed;
        uint64_t itemsDropped;
        size_t currentBufferSize;
        uint32_t currentItemCount;
        std::chrono::system_clock::time_point oldestItem;
        std::chrono::system_clock::time_point newestItem;
    };
    BufferStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    bool connected_;
    
    std::deque<DataPoint> buffer_;
    mutable std::mutex bufferMutex_;
    
    std::function<void()> onConnectivityRestored_;
    mutable std::mutex callbackMutex_;
    
    BufferStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread flushThread_;
    std::atomic<bool> stopFlush_;
    
    void FlushLoop();
    void PersistBuffer();
    void RestoreBuffer();
    void DropOldestItems(uint32_t count);
};

} // namespace Edge
