/**
 * InferenceServer.hpp
 *
 * Phase L Batch 2/5: Model Serving & Inference Server
 *
 * High-performance model serving infrastructure with support for
 * multiple frameworks, batching, and GPU acceleration.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <future>
#include <queue>
#include <chrono>

namespace AI_ML {

// ============================================================================
// Forward Declarations
// ============================================================================

class InferenceRequest;
class InferenceResponse;
class InferenceServer;
class ModelInstance;
class BatchingStrategy;
class ModelCache;

// ============================================================================
// Tensor
// ============================================================================

/**
 * Generic tensor for inference.
 */
class Tensor {
public:
    enum class DataType {
        FLOAT32,
        FLOAT16,
        INT32,
        INT64,
        UINT8,
        INT8,
        BOOL,
        STRING
    };
    
    struct Config {
        std::vector<int64_t> shape;
        DataType dtype;
        std::vector<uint8_t> data;
        std::string name;
    };
    
    explicit Tensor(const Config& config);
    
    // Data access
    template<typename T>
    T* Data();
    template<typename T>
    const T* Data() const;
    
    size_t Size() const;
    size_t ByteSize() const;
    
    // Shape operations
    const std::vector<int64_t>& Shape() const { return shape_; }
    int64_t NumElements() const;
    DataType GetDataType() const { return dtype_; }
    
    // Serialization
    std::vector<uint8_t> Serialize() const;
    static Tensor Deserialize(const std::vector<uint8_t>& data);
    
    // Utilities
    static Tensor FromVector(const std::vector<float>& data,
                              const std::vector<int64_t>& shape);
    static Tensor Zeros(const std::vector<int64_t>& shape, DataType dtype);
    static Tensor Ones(const std::vector<int64_t>& shape, DataType dtype);
    
private:
    std::vector<int64_t> shape_;
    DataType dtype_;
    std::vector<uint8_t> data_;
    std::string name_;
};

// ============================================================================
// Inference Request
// ============================================================================

/**
 * Inference request with input tensors and metadata.
 */
class InferenceRequest {
public:
    struct Config {
        std::string requestId;
        std::string modelName;
        std::string modelVersion;
        std::map<std::string, Tensor> inputs;
        std::map<std::string, std::string> metadata;
        std::chrono::milliseconds timeout;
        std::optional<std::string> correlationId;
        std::optional<std::string> sessionId;
        bool returnRawOutputs;
    };
    
    explicit InferenceRequest(const Config& config);
    
    // Input management
    void AddInput(const std::string& name, const Tensor& tensor);
    void RemoveInput(const std::string& name);
    std::optional<Tensor> GetInput(const std::string& name) const;
    std::map<std::string, Tensor> GetInputs() const;
    
    // Metadata
    void SetMetadata(const std::string& key, const std::string& value);
    std::optional<std::string> GetMetadata(const std::string& key) const;
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetRequestId() const { return config_.requestId; }
    
    // Serialization
    std::string ToJson() const;
    std::vector<uint8_t> Serialize() const;
    
private:
    Config config_;
};

// ============================================================================
// Inference Response
// ============================================================================

/**
 * Inference response with output tensors and metadata.
 */
class InferenceResponse {
public:
    struct Config {
        std::string requestId;
        std::map<std::string, Tensor> outputs;
        std::map<std::string, std::string> metadata;
        std::chrono::microseconds inferenceTime;
        std::chrono::microseconds queueTime;
        std::chrono::microseconds totalTime;
        bool success;
        std::optional<std::string> errorMessage;
        std::optional<std::string> correlationId;
    };
    
    explicit InferenceResponse(const Config& config);
    
    // Output management
    void AddOutput(const std::string& name, const Tensor& tensor);
    std::optional<Tensor> GetOutput(const std::string& name) const;
    std::map<std::string, Tensor> GetOutputs() const;
    
    // Timing
    std::chrono::microseconds GetInferenceTime() const { return config_.inferenceTime; }
    std::chrono::microseconds GetQueueTime() const { return config_.queueTime; }
    std::chrono::microseconds GetTotalTime() const { return config_.totalTime; }
    
    // Status
    bool IsSuccess() const { return config_.success; }
    std::optional<std::string> GetError() const { return config_.errorMessage; }
    
    // Serialization
    std::string ToJson() const;
    std::vector<uint8_t> Serialize() const;
    
private:
    Config config_;
};

// ============================================================================
// Model Instance
// ============================================================================

/**
 * Loaded model instance for inference.
 */
class ModelInstance {
public:
    struct Config {
        std::string modelName;
        std::string modelVersion;
        std::string modelPath;
        ModelFramework framework;
        int32_t gpuDeviceId;
        size_t maxBatchSize;
        std::chrono::milliseconds maxLatencyMs;
        std::map<std::string, std::string> runtimeConfig;
    };
    
    explicit ModelInstance(const Config& config);
    ~ModelInstance();
    
    // Lifecycle
    bool Load();
    bool Unload();
    bool IsLoaded() const;
    
    // Inference
    std::shared_ptr<InferenceResponse> Predict(
        const InferenceRequest& request);
    std::future<std::shared_ptr<InferenceResponse>> PredictAsync(
        const InferenceRequest& request);
    
    // Batch inference
    std::vector<std::shared_ptr<InferenceResponse>> PredictBatch(
        const std::vector<InferenceRequest>& requests);
    
    // Warmup
    bool Warmup(uint32_t numIterations = 10);
    
    // Statistics
    struct Stats {
        uint64_t totalRequests;
        uint64_t totalBatches;
        double averageLatencyMs;
        double p50LatencyMs;
        double p95LatencyMs;
        double p99LatencyMs;
        double throughputQps;
        size_t memoryUsageBytes;
        double gpuUtilization;
    };
    Stats GetStats() const;
    void ResetStats();
    
    // Health
    bool HealthCheck();
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetInstanceId() const { return instanceId_; }
    
private:
    Config config_;
    std::string instanceId_;
    bool loaded_;
    mutable std::mutex mutex_;
    
    // Framework-specific backends
    void* backendHandle_;
    
    bool LoadPyTorchModel();
    bool LoadTensorFlowModel();
    bool LoadOnnxModel();
    bool LoadTensorRTModel();
    bool LoadGGMLModel();
    bool LoadGGUFModel();
    bool LoadSafeTensorsModel();
};

// ============================================================================
// Batching Strategy
// ============================================================================

/**
 * Dynamic batching strategy for inference requests.
 */
class BatchingStrategy {
public:
    struct Config {
        size_t maxBatchSize;
        std::chrono::milliseconds maxWaitTime;
        bool preferLatencyOverThroughput;
        std::optional<size_t> preferredBatchSize;
        bool enablePadding;
        std::string paddingToken;
    };
    
    explicit BatchingStrategy(const Config& config);
    
    // Batching
    struct Batch {
        std::vector<InferenceRequest> requests;
        std::chrono::system_clock::time_point createdAt;
        size_t batchSize;
    };
    
    void AddRequest(const InferenceRequest& request);
    std::optional<Batch> TryFormBatch();
    bool ShouldFlush() const;
    void Flush();
    
    // Statistics
    struct BatchingStats {
        uint64_t totalBatches;
        uint64_t totalRequests;
        double averageBatchSize;
        double averageWaitTimeMs;
        uint64_t timeouts;
    };
    BatchingStats GetStats() const;
    
private:
    Config config_;
    std::queue<InferenceRequest> requestQueue_;
    std::chrono::system_clock::time_point firstRequestTime_;
    mutable std::mutex mutex_;
    BatchingStats stats_;
};

// ============================================================================
// Model Cache
// ============================================================================

/**
 * LRU cache for model instances.
 */
class ModelCache {
public:
    struct Config {
        size_t maxModels;
        size_t maxMemoryBytes;
        std::chrono::seconds ttl;
        bool enablePrefetching;
    };
    
    struct CacheEntry {
        std::shared_ptr<ModelInstance> instance;
        std::chrono::system_clock::time_point lastAccess;
        uint64_t accessCount;
    };
    
    explicit ModelCache(const Config& config);
    
    // Cache operations
    std::optional<std::shared_ptr<ModelInstance>> Get(
        const std::string& modelName, const std::string& version);
    void Put(const std::string& modelName, const std::string& version,
             std::shared_ptr<ModelInstance> instance);
    void Invalidate(const std::string& modelName, const std::string& version);
    void InvalidateAll();
    
    // Prefetching
    void Prefetch(const std::string& modelName, const std::string& version);
    void SetPrefetchQueue(const std::vector<std::pair<std::string, std::string>>& models);
    
    // Statistics
    struct CacheStats {
        size_t currentSize;
        size_t currentMemoryBytes;
        uint64_t hits;
        uint64_t misses;
        double hitRate;
        uint64_t evictions;
    };
    CacheStats GetStats() const;
    
private:
    Config config_;
    std::map<std::string, CacheEntry> cache_;
    mutable std::mutex mutex_;
    CacheStats stats_;
    
    std::string MakeKey(const std::string& modelName, const std::string& version);
    void EvictIfNeeded();
};

// ============================================================================
// Inference Server
// ============================================================================

/**
 * High-performance inference server.
 */
class InferenceServer {
public:
    struct Config {
        // Server settings
        std::string host;
        uint16_t port;
        uint32_t numWorkers;
        
        // Model settings
        std::string modelRegistryUrl;
        size_t maxConcurrentModels;
        size_t maxBatchSize;
        
        // Performance settings
        std::chrono::milliseconds requestTimeout;
        std::chrono::milliseconds queueTimeout;
        bool enableDynamicBatching;
        bool enableModelCaching;
        
        // GPU settings
        std::vector<int32_t> gpuDevices;
        size_t gpuMemoryFraction;
        bool allowGpuGrowth;
        
        // Protocol settings
        bool enableGrpc;
        bool enableRest;
        bool enableWebsocket;
        
        // Monitoring
        bool enableMetrics;
        std::string metricsEndpoint;
        bool enableTracing;
    };
    
    explicit InferenceServer(const Config& config);
    ~InferenceServer();
    
    // Lifecycle
    bool Initialize();
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Model management
    bool LoadModel(const std::string& modelName, const std::string& version);
    bool UnloadModel(const std::string& modelName, const std::string& version);
    std::vector<std::string> ListLoadedModels() const;
    
    // Inference
    std::shared_ptr<InferenceResponse> Predict(const InferenceRequest& request);
    std::future<std::shared_ptr<InferenceResponse>> PredictAsync(
        const InferenceRequest& request);
    
    // Streaming inference
    using StreamCallback = std::function<void(const InferenceResponse&)>;
    void PredictStream(const InferenceRequest& request, StreamCallback callback);
    
    // Server-sent events for streaming
    void EnableSSE(bool enable);
    
    // Model warmup
    bool WarmupModel(const std::string& modelName, const std::string& version,
                     uint32_t numIterations = 10);
    
    // Server statistics
    struct ServerStats {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        uint64_t timedOutRequests;
        double averageLatencyMs;
        double p50LatencyMs;
        double p95LatencyMs;
        double p99LatencyMs;
        double throughputQps;
        size_t activeConnections;
        size_t queueDepth;
        size_t memoryUsageBytes;
        double gpuUtilization;
    };
    ServerStats GetStats() const;
    void ResetStats();
    
    // Health
    bool HealthCheck();
    std::map<std::string, bool> GetModelHealth() const;
    
    // Configuration
    void UpdateConfig(const Config& config);
    Config GetConfig() const;
    
    // Graceful shutdown
    void PrepareForShutdown();
    bool IsReadyForShutdown() const;
    
private:
    Config config_;
    bool running_;
    mutable std::mutex mutex_;
    
    // Components
    std::unique_ptr<ModelCache> modelCache_;
    std::unique_ptr<BatchingStrategy> batchingStrategy_;
    std::map<std::string, std::shared_ptr<ModelInstance>> loadedModels_;
    
    // Thread pool
    std::vector<std::thread> workerThreads_;
    std::queue<std::function<void()>> taskQueue_;
    std::condition_variable taskCondition_;
    std::atomic<bool> shutdown_;
    
    // Statistics
    ServerStats stats_;
    mutable std::mutex statsMutex_;
    
    // Protocol handlers
    void StartGrpcServer();
    void StartRestServer();
    void StartWebsocketServer();
    void StopGrpcServer();
    void StopRestServer();
    void StopWebsocketServer();
    
    // Request handling
    void ProcessRequest(const InferenceRequest& request);
    void ProcessBatch(const std::vector<InferenceRequest>& requests);
    
    // Model loading
    std::shared_ptr<ModelInstance> GetOrLoadModel(
        const std::string& modelName, const std::string& version);
};

// ============================================================================
// Model Ensemble
// ============================================================================

/**
 * Ensemble of models for advanced inference patterns.
 */
class ModelEnsemble {
public:
    enum class EnsembleType {
        PIPELINE,      // Sequential processing
        PARALLEL,      // Parallel processing with aggregation
        VOTING,        // Multiple models vote
        CASCADE,       // Cascade with early exit
        CONDITIONAL    // Conditional routing
    };
    
    struct EnsembleConfig {
        std::string name;
        EnsembleType type;
        std::vector<std::pair<std::string, std::string>> models;  // name, version
        std::map<std::string, std::string> routingRules;
        std::optional<std::string> aggregationFunction;
    };
    
    explicit ModelEnsemble(const EnsembleConfig& config,
                           std::shared_ptr<InferenceServer> server);
    
    // Inference
    std::shared_ptr<InferenceResponse> Predict(const InferenceRequest& request);
    
    // Ensemble-specific methods
    std::shared_ptr<InferenceResponse> PipelinePredict(
        const InferenceRequest& request);
    std::shared_ptr<InferenceResponse> ParallelPredict(
        const InferenceRequest& request);
    std::shared_ptr<InferenceResponse> VotingPredict(
        const InferenceRequest& request);
    std::shared_ptr<InferenceResponse> CascadePredict(
        const InferenceRequest& request);
    std::shared_ptr<InferenceResponse> ConditionalPredict(
        const InferenceRequest& request);
    
private:
    EnsembleConfig config_;
    std::shared_ptr<InferenceServer> server_;
};

// ============================================================================
// A/B Testing
// ============================================================================

/**
 * A/B testing for model variants.
 */
class ModelABTesting {
public:
    struct Variant {
        std::string modelName;
        std::string modelVersion;
        double trafficPercentage;
        std::map<std::string, std::string> metadata;
    };
    
    struct Experiment {
        std::string experimentId;
        std::string name;
        std::vector<Variant> variants;
        std::chrono::system_clock::time_point startTime;
        std::optional<std::chrono::system_clock::time_point> endTime;
        bool active;
    };
    
    explicit ModelABTesting(std::shared_ptr<InferenceServer> server);
    
    // Experiment management
    std::string CreateExperiment(const std::string& name,
                                  const std::vector<Variant>& variants);
    bool StartExperiment(const std::string& experimentId);
    bool StopExperiment(const std::string& experimentId);
    bool DeleteExperiment(const std::string& experimentId);
    
    // Routing
    std::pair<std::string, std::string> RouteRequest(
        const std::string& experimentId,
        const std::optional<std::string>& userId = std::nullopt);
    
    // Analysis
    struct ExperimentResults {
        std::string experimentId;
        std::map<std::string, ModelMetrics> variantMetrics;
        std::map<std::string, double> conversionRates;
        std::string winningVariant;
        double confidenceLevel;
    };
    ExperimentResults AnalyzeExperiment(const std::string& experimentId);
    
private:
    std::shared_ptr<InferenceServer> server_;
    std::map<std::string, Experiment> experiments_;
    mutable std::mutex mutex_;
};

} // namespace AI_ML
