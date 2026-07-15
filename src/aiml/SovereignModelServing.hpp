// Phase D.13 Batch 1/5: Model Serving Infrastructure
// Deploy and serve ML models at scale
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
// Model Types
// ============================================================================

enum class ModelFramework {
    TENSORFLOW = 0,
    PYTORCH = 1,
    ONNX = 2,
    SKLEARN = 3,
    XGBOOST = 4,
    TENSORRT = 5,
    OPENVINO = 6,
    CUSTOM = 7
};

enum class ModelStatus {
    PENDING = 0,
    LOADING = 1,
    READY = 2,
    SERVING = 3,
    ERROR = 4,
    UNLOADING = 5
};

struct ModelMetadata {
    std::string id;
    std::string name;
    std::string version;
    ModelFramework framework;
    std::string description;
    std::vector<std::string> tags;
    std::map<std::string, std::string> labels;
    size_t model_size_bytes = 0;
    std::string checksum;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::string author;
    std::map<std::string, std::any> signature;
    std::vector<std::string> input_names;
    std::vector<std::string> output_names;
    std::map<std::string, std::vector<int64_t>> input_shapes;
    std::map<std::string, std::vector<int64_t>> output_shapes;
    std::string runtime_requirements;
};

// ============================================================================
// Model Loader
// ============================================================================

class ModelLoader {
public:
    struct Config {
        std::string model_cache_path;
        size_t max_cache_size_gb = 10;
        bool enable_gpu = true;
        int gpu_device_id = 0;
        std::string runtime_backend = "auto";
    };
    
    explicit ModelLoader(const Config& config);
    ~ModelLoader();
    
    bool Initialize();
    void Shutdown();
    
    // Loading
    bool LoadModel(const ModelMetadata& metadata, const std::string& model_path);
    bool UnloadModel(const std::string& model_id);
    bool ReloadModel(const std::string& model_id);
    
    // Status
    ModelStatus GetModelStatus(const std::string& model_id) const;
    bool IsModelLoaded(const std::string& model_id) const;
    std::vector<std::string> GetLoadedModels() const;
    
    // Cache management
    bool WarmupModel(const std::string& model_id);
    bool PreloadModel(const std::string& model_id);
    void ClearCache();
    
private:
    Config config_;
    std::map<std::string, ModelStatus> model_status_;
    std::map<std::string, void*> model_handles_;
    mutable std::mutex models_mutex_;
    
    bool LoadTensorFlowModel(const std::string& model_id, const std::string& path);
    bool LoadPyTorchModel(const std::string& model_id, const std::string& path);
    bool LoadONNXModel(const std::string& model_id, const std::string& path);
};

// ============================================================================
// Inference Engine
// ============================================================================

class InferenceEngine {
public:
    struct Config {
        int max_batch_size = 32;
        std::chrono::milliseconds max_latency_ms{100};
        bool dynamic_batching = true;
        int num_threads = 4;
        bool enable_gpu = true;
    };
    
    struct InferenceRequest {
        std::string request_id;
        std::string model_id;
        std::map<std::string, std::any> inputs;
        std::map<std::string, std::string> metadata;
        std::chrono::steady_clock::time_point received_at;
        std::chrono::milliseconds timeout{5000};
    };
    
    struct InferenceResponse {
        std::string request_id;
        bool success;
        std::map<std::string, std::any> outputs;
        std::chrono::milliseconds latency{0};
        std::string error_message;
        std::map<std::string, std::string> metadata;
    };
    
    explicit InferenceEngine(const Config& config);
    ~InferenceEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Inference
    InferenceResponse Predict(const InferenceRequest& request);
    std::vector<InferenceResponse> PredictBatch(const std::vector<InferenceRequest>& requests);
    
    // Async inference
    using InferenceCallback = std::function<void(const InferenceResponse&)>;
    void PredictAsync(const InferenceRequest& request, InferenceCallback callback);
    
    // Streaming
    using StreamCallback = std::function<void(const std::map<std::string, std::any>& partial_output)>;
    void PredictStream(const InferenceRequest& request, StreamCallback callback);
    
    // Metrics
    struct InferenceMetrics {
        uint64_t total_requests = 0;
        uint64_t successful_requests = 0;
        uint64_t failed_requests = 0;
        double avg_latency_ms = 0.0;
        double p50_latency_ms = 0.0;
        double p95_latency_ms = 0.0;
        double p99_latency_ms = 0.0;
        double throughput_qps = 0.0;
        int active_requests = 0;
        int queue_depth = 0;
    };
    
    InferenceMetrics GetMetrics() const;
    InferenceMetrics GetMetricsForModel(const std::string& model_id) const;
    
private:
    Config config_;
    std::unique_ptr<ModelLoader> model_loader_;
    
    struct RequestQueue {
        std::queue<InferenceRequest> requests;
        std::mutex mutex;
        std::condition_variable cv;
    };
    
    RequestQueue request_queue_;
    std::vector<std::thread> worker_threads_;
    std::atomic<bool> running_{false};
    
    void WorkerLoop();
    InferenceResponse ExecuteInference(const InferenceRequest& request);
};

// ============================================================================
// Model Server
// ============================================================================

class ModelServer {
public:
    struct Config {
        std::string bind_address = "0.0.0.0";
        int port = 8080;
        int grpc_port = 9090;
        bool enable_rest = true;
        bool enable_grpc = true;
        int max_concurrent_requests = 1000;
        std::chrono::seconds request_timeout{30};
    };
    
    explicit ModelServer(const Config& config);
    ~ModelServer();
    
    bool Initialize();
    void Shutdown();
    
    // Server lifecycle
    bool Start();
    void Stop();
    bool IsRunning() const;
    
    // Model management
    bool RegisterModel(const ModelMetadata& metadata);
    bool UnregisterModel(const std::string& model_id);
    bool UpdateModel(const std::string& model_id, const ModelMetadata& metadata);
    
    // Endpoints
    void SetupRESTEndpoints();
    void SetupGRPCService();
    
    // Health
    bool IsHealthy() const;
    std::map<std::string, std::string> GetHealthStatus() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::unique_ptr<InferenceEngine> inference_engine_;
    
    std::thread rest_server_thread_;
    std::thread grpc_server_thread_;
    
    void RESTServerLoop();
    void GRPCServerLoop();
};

// ============================================================================
// Model Runtime
// ============================================================================

class ModelServingRuntime {
public:
    struct Config {
        ModelLoader::Config loader;
        InferenceEngine::Config engine;
        ModelServer::Config server;
    };
    
    explicit ModelServingRuntime(const Config& config);
    ~ModelServingRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    ModelLoader* GetLoader();
    InferenceEngine* GetEngine();
    ModelServer* GetServer();
    
    // Convenience
    bool LoadAndServe(const ModelMetadata& metadata, const std::string& model_path);
    InferenceEngine::InferenceResponse Predict(const InferenceEngine::InferenceRequest& request);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ModelLoader> loader_;
    std::unique_ptr<InferenceEngine> engine_;
    std::unique_ptr<ModelServer> server_;
};

} // namespace AIML
} // namespace Sovereign
