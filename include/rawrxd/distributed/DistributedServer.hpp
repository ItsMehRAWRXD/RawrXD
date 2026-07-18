#pragma once

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <map>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>

namespace rawrxd {
namespace distributed {

// Server configuration
struct DistributedServerConfig {
    std::string host = "0.0.0.0";
    int port = 8080;
    int numWorkers = 4;
    int maxConcurrentRequests = 100;
    int requestTimeoutMs = 30000;
    bool enableSSL = false;
    std::string sslCertPath;
    std::string sslKeyPath;
    std::string modelPath;
    std::vector<int> deviceIds;
    ParallelStrategyConfig parallelConfig;
    PipelineBatchConfig pipelineConfig;
};

// Request structure
struct InferenceRequest {
    std::string requestId;
    std::string prompt;
    int maxTokens = 128;
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
    float repetitionPenalty = 1.0f;
    std::vector<std::string> stopSequences;
    bool stream = false;
    std::chrono::system_clock::time_point receivedTime;
    std::chrono::system_clock::time_point deadline;
};

// Response structure
struct InferenceResponse {
    std::string requestId;
    std::string generatedText;
    int tokensGenerated = 0;
    float timeToFirstTokenMs = 0.0f;
    float totalTimeMs = 0.0f;
    bool success = false;
    std::string errorMessage;
    std::vector<float> tokenLogprobs;
};

// Request priority
enum class RequestPriority {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

// Request queue entry
struct QueuedRequest {
    InferenceRequest request;
    RequestPriority priority = RequestPriority::NORMAL;
    std::promise<InferenceResponse> promise;
    std::chrono::system_clock::time_point enqueueTime;
    
    bool operator<(const QueuedRequest& other) const {
        return priority < other.priority;
    }
};

// Distributed inference server
class DistributedServer {
public:
    DistributedServer();
    ~DistributedServer();

    // Initialize server
    bool Initialize(const DistributedServerConfig& config);
    
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
        double throughputRequestsPerSec = 0.0;
        double throughputTokensPerSec = 0.0;
        std::map<int, DeviceInfo> deviceStats;
    };
    ServerStats GetStats() const;
    
    // Health check
    bool HealthCheck() const;
    
    // Graceful shutdown with timeout
    void GracefulShutdown(std::chrono::seconds timeout);

private:
    DistributedServerConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdownRequested_{false};
    
    // Inference engine
    std::unique_ptr<PipelineInferenceEngine> inferenceEngine_;
    
    // Request queue
    std::priority_queue<QueuedRequest> requestQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCV_;
    
    // Worker threads
    std::vector<std::thread> workerThreads_;
    std::thread acceptThread_;
    std::thread monitorThread_;
    
    // Statistics
    mutable std::mutex statsMutex_;
    ServerStats stats_;
    std::vector<double> latencies_;
    
    // Connection handling (placeholder for HTTP/WebSocket)
    // std::unique_ptr<HttpServer> httpServer_;
    
    // Methods
    void AcceptLoop();
    void WorkerLoop(int workerId);
    void MonitorLoop();
    InferenceResponse ProcessRequest(const InferenceRequest& request);
    void UpdateStats(const InferenceRequest& request, const InferenceResponse& response);
    bool IsRequestValid(const InferenceRequest& request) const;
};

// Cluster configuration for multi-node
struct ClusterConfig {
    std::string nodeId;
    std::string coordinatorAddress;
    int coordinatorPort = 9090;
    std::vector<std::string> peerNodes;
    int rank = 0;
    int worldSize = 1;
};

// Multi-node distributed coordinator
class ClusterCoordinator {
public:
    ClusterCoordinator();
    ~ClusterCoordinator();

    // Initialize as coordinator or worker
    bool Initialize(const ClusterConfig& config, bool isCoordinator);
    
    // Register node
    bool RegisterNode(const std::string& nodeId, const std::string& address, int port);
    
    // Discover nodes
    std::vector<std::string> DiscoverNodes();
    
    // Get node info
    struct NodeInfo {
        std::string nodeId;
        std::string address;
        int port = 0;
        bool isHealthy = false;
        int numDevices = 0;
        size_t availableMemory = 0;
        std::chrono::system_clock::time_point lastHeartbeat;
    };
    NodeInfo GetNodeInfo(const std::string& nodeId) const;
    std::vector<NodeInfo> GetAllNodes() const;
    
    // Heartbeat
    void SendHeartbeat();
    
    // Distributed request routing
    std::string RouteRequest(const InferenceRequest& request);
    
    // Shutdown
    void Shutdown();

private:
    ClusterConfig config_;
    bool isCoordinator_ = false;
    bool initialized_ = false;
    
    std::map<std::string, NodeInfo> nodes_;
    mutable std::mutex nodesMutex_;
    
    std::thread heartbeatThread_;
    std::atomic<bool> running_{false};
    
    void HeartbeatLoop();
    void MonitorNodes();
};

// Load balancer for distributed serving
class LoadBalancer {
public:
    enum class Strategy {
        ROUND_ROBIN,
        LEAST_CONNECTIONS,
        WEIGHTED_RESPONSE_TIME,
        CONSISTENT_HASHING
    };

    LoadBalancer(Strategy strategy = Strategy::LEAST_CONNECTIONS);
    ~LoadBalancer();

    // Add/remove backend
    void AddBackend(const std::string& backendId, const std::string& address,
                    int weight = 1);
    void RemoveBackend(const std::string& backendId);
    void UpdateBackendHealth(const std::string& backendId, bool isHealthy);
    
    // Select backend
    std::string SelectBackend(const InferenceRequest& request);
    
    // Report result
    void ReportResult(const std::string& backendId, bool success, double latencyMs);

private:
    Strategy strategy_;
    
    struct Backend {
        std::string id;
        std::string address;
        int weight = 1;
        bool isHealthy = true;
        int activeConnections = 0;
        double avgLatencyMs = 0.0;
        int totalRequests = 0;
        int successfulRequests = 0;
    };
    
    std::map<std::string, Backend> backends_;
    mutable std::mutex mutex_;
    std::atomic<int> roundRobinIndex_{0};
    
    std::string SelectRoundRobin();
    std::string SelectLeastConnections();
    std::string SelectWeightedResponseTime();
    std::string SelectConsistentHashing(const std::string& key);
};

} // namespace distributed
} // namespace rawrxd
