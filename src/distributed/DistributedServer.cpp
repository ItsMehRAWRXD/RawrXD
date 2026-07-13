#include "rawrxd/distributed/DistributedServer.hpp"
#include <algorithm>
#include <math>

namespace rawrxd {
namespace distributed {

// DistributedServer implementation
DistributedServer::DistributedServer() = default;

DistributedServer::~DistributedServer() {
    Stop();
}

bool DistributedServer::Initialize(const DistributedServerConfig& config) {
    config_ = config;
    
    // Initialize inference engine
    inferenceEngine_ = std::make_unique<PipelineInferenceEngine>();
    if (!inferenceEngine_->Initialize(config_.modelPath, config_.deviceIds, config_.pipelineConfig)) {
        return false;
    }
    
    // Initialize HTTP server (placeholder)
    // httpServer_ = std::make_unique<HttpServer>();
    // if (!httpServer_->Initialize(config_.host, config_.port)) {
    //     return false;
    // }
    
    return true;
}

bool DistributedServer::Start() {
    if (running_) {
        return false;
    }
    
    running_ = true;
    shutdownRequested_ = false;
    
    // Start worker threads
    for (int i = 0; i < config_.numWorkers; ++i) {
        workerThreads_.emplace_back(&DistributedServer::WorkerLoop, this, i);
    }
    
    // Start accept thread
    acceptThread_ = std::thread(&DistributedServer::AcceptLoop, this);
    
    // Start monitor thread
    monitorThread_ = std::thread(&DistributedServer::MonitorLoop, this);
    
    return true;
}

void DistributedServer::Stop() {
    if (!running_) {
        return;
    }
    
    shutdownRequested_ = true;
    running_ = false;
    
    // Notify all waiting threads
    queueCV_.notify_all();
    
    // Join threads
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }
    
    for (auto& thread : workerThreads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
    
    // Shutdown inference engine
    if (inferenceEngine_) {
        inferenceEngine_->Shutdown();
    }
}

std::future<InferenceResponse> DistributedServer::SubmitRequest(const InferenceRequest& request,
                                                                     RequestPriority priority) {
    std::promise<InferenceResponse> promise;
    std::future<InferenceResponse> future = promise.get_future();
    
    if (!running_ || shutdownRequested_) {
        InferenceResponse response;
        response.requestId = request.requestId;
        response.success = false;
        response.errorMessage = "Server not running";
        promise.set_value(response);
        return future;
    }
    
    // Check if request is valid
    if (!IsRequestValid(request)) {
        InferenceResponse response;
        response.requestId = request.requestId;
        response.success = false;
        response.errorMessage = "Invalid request";
        promise.set_value(response);
        return future;
    }
    
    // Queue request
    QueuedRequest queuedRequest;
    queuedRequest.request = request;
    queuedRequest.priority = priority;
    queuedRequest.promise = std::move(promise);
    queuedRequest.enqueueTime = std::chrono::system_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (static_cast<int>(requestQueue_.size()) >= config_.maxConcurrentRequests) {
            InferenceResponse response;
            response.requestId = request.requestId;
            response.success = false;
            response.errorMessage = "Server overloaded";
            queuedRequest.promise.set_value(response);
            return future;
        }
        requestQueue_.push(std::move(queuedRequest));
    }
    
    queueCV_.notify_one();
    
    return future;
}

DistributedServer::ServerStats DistributedServer::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

bool DistributedServer::HealthCheck() const {
    if (!running_) return false;
    if (!inferenceEngine_) return false;
    
    // Check if devices are available
    auto devices = DeviceManager::GetInstance().GetAvailableDevices();
    return !devices.empty();
}

void DistributedServer::GracefulShutdown(std::chrono::seconds timeout) {
    shutdownRequested_ = true;
    
    // Wait for queue to drain or timeout
    auto startTime = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::steady_clock::now() - startTime) < timeout) {
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (requestQueue_.empty()) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    Stop();
}

void DistributedServer::AcceptLoop() {
    // In real implementation, accept HTTP/WebSocket connections
    // For now, this is a placeholder
    
    while (running_ && !shutdownRequested_) {
        // Accept new connection
        // auto connection = httpServer_->Accept();
        // Handle connection...
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void DistributedServer::WorkerLoop(int workerId) {
    while (running_) {
        QueuedRequest request;
        
        // Wait for request
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCV_.wait(lock, [this] {
                return !requestQueue_.empty() || !running_;
            });
            
            if (!running_) break;
            
            if (requestQueue_.empty()) continue;
            
            request = std::move(const_cast<QueuedRequest>&(requestQueue_.top()));
            requestQueue_.pop();
        }
        
        // Check deadline
        if (std::chrono::system_clock::now() > request.request.deadline) {
            InferenceResponse response;
            response.requestId = request.request.requestId;
            response.success = false;
            response.errorMessage = "Request timeout";
            request.promise.set_value(response);
            continue;
        }
        
        // Process request
        auto response = ProcessRequest(request.request);
        
        // Update stats
        UpdateStats(request.request, response);
        
        // Set promise value
        request.promise.set_value(response);
    }
}

void DistributedServer::MonitorLoop() {
    while (running_) {
        // Update device stats
        auto devices = DeviceManager::GetInstance().GetAllDevices();
        
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.deviceStats.clear();
        for (const auto& device : devices) {
            stats_.deviceStats[device.deviceId] = device;
        }
        
        // Calculate throughput
        if (!latencies_.empty()) {
            double avgLatency = std::accumulate(latencies_.begin(), latencies_.end(), 0.0) 
                              / latencies_.size();
            stats_.avgLatencyMs = avgLatency;
            
            if (avgLatency > 0) {
                stats_.throughputRequestsPerSec = 1000.0 / avgLatency;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

InferenceResponse DistributedServer::ProcessRequest(const InferenceRequest& request) {
    InferenceResponse response;
    response.requestId = request.requestId;
    auto startTime = std::chrono::high_resolution_clock::now();
    
    try {
        // Generate text
        auto result = inferenceEngine_->Generate(request.prompt, request.maxTokens);
        
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);
        
        response.generatedText = result;
        response.tokensGenerated = request.maxTokens; // Actual count would be tracked
        response.totalTimeMs = duration.count();
        response.timeToFirstTokenMs = duration.count() * 0.1f; // Approximate
        response.success = true;
        
    } catch (const std::exception& e) {
        response.success = false;
        response.errorMessage = e.what();
    }
    
    return response;
}

void DistributedServer::UpdateStats(const InferenceRequest& request, 
                                     const InferenceResponse& response) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    stats_.totalRequests++;
    if (response.success) {
        stats_.successfulRequests++;
    } else {
        stats_.failedRequests++;
    }
    
    latencies_.push_back(response.totalTimeMs);
    if (latencies_.size() > 1000) {
        latencies_.erase(latencies_.begin());
    }
    
    stats_.throughputTokensPerSec += response.tokensGenerated;
}

bool DistributedServer::IsRequestValid(const InferenceRequest& request) const {
    if (request.requestId.empty()) return false;
    if (request.prompt.empty()) return false;
    if (request.maxTokens <= 0 || request.maxTokens > 8192) return false;
    if (request.temperature < 0.0f || request.temperature > 2.0f) return false;
    if (request.topP < 0.0f || request.topP > 1.0f) return false;
    return true;
}

// ClusterCoordinator implementation
ClusterCoordinator::ClusterCoordinator() = default;

ClusterCoordinator::~ClusterCoordinator() {
    Shutdown();
}

bool ClusterCoordinator::Initialize(const ClusterConfig& config, bool isCoordinator) {
    config_ = config;
    isCoordinator_ = isCoordinator;
    
    // Register self
    NodeInfo selfInfo;
    selfInfo.nodeId = config_.nodeId;
    selfInfo.isHealthy = true;
    selfInfo.numDevices = static_cast<int>(
        DeviceManager::GetInstance().GetGPUDevices().size());
    selfInfo.availableMemory = DeviceManager::GetInstance().GetFreeMemory(0);
    selfInfo.lastHeartbeat = std::chrono::system_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(nodesMutex_);
        nodes_[config_.nodeId] = selfInfo;
    }
    
    // Start heartbeat thread
    running_ = true;
    heartbeatThread_ = std::thread(&ClusterCoordinator::HeartbeatLoop, this);
    
    initialized_ = true;
    return true;
}

bool ClusterCoordinator::RegisterNode(const std::string& nodeId, 
                                       const std::string& address, int port) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    NodeInfo info;
    info.nodeId = nodeId;
    info.address = address;
    info.port = port;
    info.isHealthy = true;
    info.lastHeartbeat = std::chrono::system_clock::now();
    
    nodes_[nodeId] = info;
    return true;
}

std::vector<std::string> ClusterCoordinator::DiscoverNodes() {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    std::vector<std::string> nodeIds;
    for (const auto& pair : nodes_) {
        nodeIds.push_back(pair.first);
    }
    return nodeIds;
}

ClusterCoordinator::NodeInfo ClusterCoordinator::GetNodeInfo(const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        return it->second;
    }
    return NodeInfo();
}

std::vector<ClusterCoordinator::NodeInfo> ClusterCoordinator::GetAllNodes() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    std::vector<NodeInfo> result;
    for (const auto& pair : nodes_) {
        result.push_back(pair.second);
    }
    return result;
}

void ClusterCoordinator::SendHeartbeat() {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(config_.nodeId);
    if (it != nodes_.end()) {
        it->second.lastHeartbeat = std::chrono::system_clock::now();
        it->second.availableMemory = DeviceManager::GetInstance().GetFreeMemory(0);
    }
}

std::string ClusterCoordinator::RouteRequest(const InferenceRequest& request) {
    // Simple routing: select least loaded node
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    std::string bestNode;
    size_t maxMemory = 0;
    
    for (const auto& pair : nodes_) {
        if (pair.second.isHealthy && pair.second.availableMemory > maxMemory) {
            maxMemory = pair.second.availableMemory;
            bestNode = pair.first;
        }
    }
    
    return bestNode;
}

void ClusterCoordinator::Shutdown() {
    running_ = false;
    if (heartbeatThread_.joinable()) {
        heartbeatThread_.join();
    }
}

void ClusterCoordinator::HeartbeatLoop() {
    while (running_) {
        SendHeartbeat();
        MonitorNodes();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void ClusterCoordinator::MonitorNodes() {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto now = std::chrono::system_clock::now();
    auto timeout = std::chrono::seconds(30);
    
    for (auto& pair : nodes_) {
        if (now - pair.second.lastHeartbeat > timeout) {
            pair.second.isHealthy = false;
        }
    }
}

// LoadBalancer implementation
LoadBalancer::LoadBalancer(Strategy strategy) : strategy_(strategy) {}

LoadBalancer::~LoadBalancer() = default;

void LoadBalancer::AddBackend(const std::string& backendId, const std::string& address,
                               int weight) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Backend backend;
    backend.id = backendId;
    backend.address = address;
    backend.weight = weight;
    backend.isHealthy = true;
    
    backends_[backendId] = backend;
}

void LoadBalancer::RemoveBackend(const std::string& backendId) {
    std::lock_guard<std::mutex> lock(mutex_);
    backends_.erase(backendId);
}

void LoadBalancer::UpdateBackendHealth(const std::string& backendId, bool isHealthy) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = backends_.find(backendId);
    if (it != backends_.end()) {
        it->second.isHealthy = isHealthy;
    }
}

std::string LoadBalancer::SelectBackend(const InferenceRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    switch (strategy_) {
        case Strategy::ROUND_ROBIN:
            return SelectRoundRobin();
        case Strategy::LEAST_CONNECTIONS:
            return SelectLeastConnections();
        case Strategy::WEIGHTED_RESPONSE_TIME:
            return SelectWeightedResponseTime();
        case Strategy::CONSISTENT_HASHING:
            return SelectConsistentHashing(request.requestId);
        default:
            return SelectLeastConnections();
    }
}

void LoadBalancer::ReportResult(const std::string& backendId, bool success, double latencyMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = backends_.find(backendId);
    if (it != backends_.end()) {
        it->second.totalRequests++;
        if (success) {
            it->second.successfulRequests++;
        }
        
        // Update average latency with exponential moving average
        if (it->second.avgLatencyMs == 0) {
            it->second.avgLatencyMs = latencyMs;
        } else {
            it->second.avgLatencyMs = 0.7 * it->second.avgLatencyMs + 0.3 * latencyMs;
        }
        
        it->second.activeConnections--;
    }
}

std::string LoadBalancer::SelectRoundRobin() {
    std::vector<std::string> healthyBackends;
    for (const auto& pair : backends_) {
        if (pair.second.isHealthy) {
            healthyBackends.push_back(pair.first);
        }
    }
    
    if (healthyBackends.empty()) {
        return "";
    }
    
    int index = roundRobinIndex_.fetch_add(1) % healthyBackends.size();
    auto it = backends_.find(healthyBackends[index]);
    if (it != backends_.end()) {
        it->second.activeConnections++;
    }
    
    return healthyBackends[index];
}

std::string LoadBalancer::SelectLeastConnections() {
    std::string bestBackend;
    int minConnections = std::numeric_limits<int>::max();
    
    for (auto& pair : backends_) {
        if (pair.second.isHealthy && pair.second.activeConnections < minConnections) {
            minConnections = pair.second.activeConnections;
            bestBackend = pair.first;
        }
    }
    
    if (!bestBackend.empty()) {
        backends_[bestBackend].activeConnections++;
    }
    
    return bestBackend;
}

std::string LoadBalancer::SelectWeightedResponseTime() {
    std::string bestBackend;
    double bestScore = std::numeric_limits<double>::max();
    
    for (auto& pair : backends_) {
        if (!pair.second.isHealthy) continue;
        
        // Score = avgLatency / weight
        double score = pair.second.avgLatencyMs / pair.second.weight;
        if (score < bestScore) {
            bestScore = score;
            bestBackend = pair.first;
        }
    }
    
    if (!bestBackend.empty()) {
        backends_[bestBackend].activeConnections++;
    }
    
    return bestBackend;
}

std::string LoadBalancer::SelectConsistentHashing(const std::string& key) {
    // Simple hash-based selection
    if (backends_.empty()) {
        return "";
    }
    
    std::hash<std::string> hasher;
    size_t hash = hasher(key);
    
    std::vector<std::string> healthyBackends;
    for (const auto& pair : backends_) {
        if (pair.second.isHealthy) {
            healthyBackends.push_back(pair.first);
        }
    }
    
    if (healthyBackends.empty()) {
        return "";
    }
    
    size_t index = hash % healthyBackends.size();
    auto it = backends_.find(healthyBackends[index]);
    if (it != backends_.end()) {
        it->second.activeConnections++;
    }
    
    return healthyBackends[index];
}

} // namespace distributed
} // namespace rawrxd
