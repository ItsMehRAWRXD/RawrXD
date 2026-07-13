#pragma once

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <map>
#include <chrono>

namespace rawrxd {
namespace deployment {

// Server configuration
struct ModelServerConfig {
    std::string host = "0.0.0.0";
    int port = 8080;
    int numWorkers = 4;
    int maxConcurrentRequests = 100;
    int requestTimeoutMs = 30000;
    int maxQueueSize = 1000;
    
    // Model configuration
    std::string modelPath;
    std::string tokenizerPath;
    int maxBatchSize = 8;
    int maxSequenceLength = 4096;
    
    // Optimization settings
    bool enableFlashAttention = true;
    bool enableSpeculativeDecoding = false;
    bool enableQuantization = false;
    std::string quantizationType = "Q4_K";
    
    // Distributed settings
    bool enableDistributed = false;
    std::vector<int> deviceIds;
    int tensorParallelSize = 1;
    int pipelineParallelSize = 1;
    
    // Security
    bool enableAuth = false;
    std::string apiKey;
    bool enableRateLimiting = false;
    int rateLimitRequestsPerMinute = 60;
    
    // Logging
    std::string logLevel = "INFO";
    std::string logPath = "logs/server.log";
    bool enableAccessLog = true;
};

// Request types
enum class RequestType {
    COMPLETION,
    CHAT,
    EMBEDDING,
    TOKENIZE,
    DETOKENIZE,
    HEALTH
};

// Request structure
struct InferenceRequest {
    std::string requestId;
    RequestType type = RequestType::COMPLETION;
    std::string prompt;
    std::vector<std::map<std::string, std::string>> messages; // For chat
    int maxTokens = 128;
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
    float repetitionPenalty = 1.0f;
    std::vector<std::string> stopSequences;
    bool stream = false;
    std::string user;
    std::chrono::system_clock::time_point receivedTime;
    std::chrono::system_clock::time_point deadline;
};

// Response structure
struct InferenceResponse {
    std::string requestId;
    std::string generatedText;
    std::vector<float> embedding;
    std::vector<int> tokens;
    int tokensGenerated = 0;
    int promptTokens = 0;
    float timeToFirstTokenMs = 0.0f;
    float totalTimeMs = 0.0f;
    bool success = false;
    std::string errorMessage;
    std::string finishReason = "stop";
    std::vector<float> tokenLogprobs;
    std::map<std::string, std::string> usage;
};

// Request priority
enum class RequestPriority {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

// Queued request
struct QueuedRequest {
    InferenceRequest request;
    RequestPriority priority = RequestPriority::NORMAL;
    std::promise<InferenceResponse> promise;
    std::chrono::system_clock::time_point enqueueTime;
    
    bool operator<(const QueuedRequest& other) const {
        return priority < other.priority;
    }
};

// Model server
class ModelServer {
public:
    ModelServer();
    ~ModelServer();

    // Initialize server
    bool Initialize(const ModelServerConfig& config);
    
    // Start server
    bool Start();
    
    // Stop server
    void Stop();
    
    // Check if running
    bool IsRunning() const { return running_; }
    
    // Submit request
    std::future<InferenceResponse> SubmitRequest(const InferenceRequest& request,
                                                RequestPriority priority = RequestPriority::NORMAL);
    
    // Get server stats
    struct ServerStats {
        int totalRequests = 0;
        int successfulRequests = 0;
        int failedRequests = 0;
        int queuedRequests = 0;
        int activeRequests = 0;
        double avgLatencyMs = 0.0;
        double p50LatencyMs = 0.0;
        double p95LatencyMs = 0.0;
        double p99LatencyMs = 0.0;
        double throughputRequestsPerSec = 0.0;
        double throughputTokensPerSec = 0.0;
        size_t memoryUsageBytes = 0;
        float gpuUtilization = 0.0f;
    };
    ServerStats GetStats() const;
    
    // Health check
    bool HealthCheck() const;
    
    // Get model info
    struct ModelInfo {
        std::string modelId;
        std::string modelVersion;
        size_t modelSizeBytes = 0;
        int vocabSize = 0;
        int numLayers = 0;
        int numHeads = 0;
        int hiddenSize = 0;
        int maxContextLength = 0;
        std::vector<std::string> capabilities;
    };
    ModelInfo GetModelInfo() const;
    
    // Graceful shutdown
    void GracefulShutdown(std::chrono::seconds timeout);
    
    // Reload model
    bool ReloadModel(const std::string& modelPath);

private:
    ModelServerConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdownRequested_{false};
    
    // Model
    // std::unique_ptr<Model> model_;
    // std::unique_ptr<Tokenizer> tokenizer_;
    
    // Request queue
    std::priority_queue<QueuedRequest> requestQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCV_;
    
    // Worker threads
    std::vector<std::thread> workerThreads_;
    std::thread acceptThread_;
    std::thread monitorThread_;
    std::thread metricsThread_;
    
    // Statistics
    mutable std::mutex statsMutex_;
    ServerStats stats_;
    std::vector<double> latencies_;
    
    // Rate limiting
    std::map<std::string, std::vector<std::chrono::system_clock::time_point>> rateLimitMap_;
    mutable std::mutex rateLimitMutex_;
    
    // Methods
    void AcceptLoop();
    void WorkerLoop(int workerId);
    void MonitorLoop();
    void MetricsLoop();
    InferenceResponse ProcessRequest(const InferenceRequest& request);
    void UpdateStats(const InferenceRequest& request, const InferenceResponse& response);
    bool IsRequestValid(const InferenceRequest& request) const;
    bool CheckRateLimit(const std::string& user);
    std::string GenerateRequestId();
};

// REST API handler
class RESTAPIHandler {
public:
    RESTAPIHandler(ModelServer* server);
    ~RESTAPIHandler();
    
    // Handle request
    std::string HandleRequest(const std::string& method, const std::string& path,
                              const std::string& body,
                              const std::map<std::string, std::string>& headers);
    
    // Streaming response
    void HandleStreamingRequest(const std::string& method, const std::string& path,
                                const std::string& body,
                                const std::map<std::string, std::string>& headers,
                                std::function<void(const std::string&)> callback);

private:
    ModelServer* server_;
    
    std::string HandleCompletions(const std::string& body);
    std::string HandleChatCompletions(const std::string& body);
    std::string HandleEmbeddings(const std::string& body);
    std::string HandleTokenize(const std::string& body);
    std::string HandleHealth();
    std::string HandleModels();
    
    InferenceRequest ParseCompletionRequest(const std::string& body);
    InferenceRequest ParseChatRequest(const std::string& body);
    std::string SerializeResponse(const InferenceResponse& response);
    std::string SerializeStreamingChunk(const InferenceResponse& response, bool isLast);
};

// gRPC service (placeholder for future implementation)
class GRPCService {
public:
    GRPCService(ModelServer* server);
    ~GRPCService();
    
    bool Start(int port);
    void Stop();

private:
    ModelServer* server_;
    // std::unique_ptr<grpc::Server> grpcServer_;
};

// WebSocket handler for streaming
class WebSocketHandler {
public:
    WebSocketHandler(ModelServer* server);
    ~WebSocketHandler();
    
    void HandleConnection(int connectionId);
    void HandleMessage(int connectionId, const std::string& message);
    void HandleDisconnect(int connectionId);

private:
    ModelServer* server_;
    std::map<int, std::thread> streamingThreads_;
    std::mutex mutex_;
};

} // namespace deployment
} // namespace rawrxd
