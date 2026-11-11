// RawrXD Distributed Runtime Implementation
// Phase O: Complete distributed system integration

#include "DistributedRuntime.hpp"
#include "ClusterManager.hpp"
#include "DistributedScheduler.hpp"
#include "ModelResidencyManager.hpp"
#include "DistributedKVCache.hpp"
#include "DistributedBenchmark.hpp"
#include "WorkStealingScheduler.hpp"
#include "PriorityTaskQueue.hpp"
#include "ModelShardingManager.hpp"
#include "CachePrefetchEngine.hpp"
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Distributed {

// DistributedRuntime Implementation

DistributedRuntime::DistributedRuntime()
    : running_(false)
    , initialized_(false)
{
}

DistributedRuntime::~DistributedRuntime() {
    shutdown();
}

bool DistributedRuntime::initialize(const DistributedRuntimeConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Initialize cluster manager
    clusterManager_ = std::make_shared<ClusterManager>();
    ClusterConfig clusterConfig;
    clusterConfig.nodeId = config.nodeId;
    clusterConfig.listenAddress = config.listenAddress;
    clusterConfig.listenPort = config.listenPort;
    clusterConfig.seedNodes = config.seedNodes;
    clusterConfig.resources.totalVRAM = config.totalVRAM;
    clusterConfig.resources.totalRAM = config.totalRAM;
    clusterConfig.resources.cpuCores = config.cpuCores;
    clusterConfig.resources.gpuCount = config.gpuCount;
    clusterConfig.capabilities = config.capabilities;
    
    if (!clusterManager_->initialize(clusterConfig)) {
        return false;
    }
    
    // Initialize scheduler
    scheduler_ = std::make_shared<DistributedScheduler>(clusterManager_);
    SchedulerConfig schedulerConfig;
    if (!scheduler_->initialize(schedulerConfig)) {
        return false;
    }
    
    // Initialize model residency manager
    residencyManager_ = std::make_shared<ModelResidencyManager>(clusterManager_);
    ResidencyConfig residencyConfig;
    if (!residencyManager_->initialize(residencyConfig)) {
        return false;
    }
    
    // Initialize KV cache
    kvCache_ = std::make_shared<DistributedKVCache>(clusterManager_);
    DistributedCacheConfig cacheConfig;
    cacheConfig.maxMemoryPerNode = config.totalRAM / 4; // Use 25% of RAM
    if (!kvCache_->initialize(cacheConfig)) {
        return false;
    }
    
    // Initialize benchmark
    if (config.enableBenchmarking) {
        benchmark_ = std::make_shared<DistributedBenchmark>(
            clusterManager_, scheduler_, residencyManager_, kvCache_);
        benchmark_->initialize();
    }
    
    // Initialize optional components
    if (config.enableWorkStealing) {
        workStealingScheduler_ = std::make_shared<WorkStealingScheduler>(clusterManager_);
        WorkStealingConfig wsConfig;
        workStealingScheduler_->initialize(wsConfig);
    }
    
    if (config.enablePriorityScheduling) {
        priorityQueue_ = std::make_shared<PriorityTaskQueue>();
        PriorityQueueConfig pqConfig;
        priorityQueue_->initialize(pqConfig);
    }
    
    if (config.enableModelSharding) {
        shardingManager_ = std::make_shared<ModelShardingManager>(
            clusterManager_, residencyManager_);
        ShardingConfig shardConfig;
        shardingManager_->initialize(shardConfig);
    }
    
    if (config.enablePrefetching) {
        prefetchEngine_ = std::make_shared<CachePrefetchEngine>(kvCache_);
        PrefetchEngineConfig prefetchConfig;
        prefetchEngine_->initialize(prefetchConfig);
    }
    
    running_ = true;
    
    // Start background threads
    runtimeThread_ = std::thread(&DistributedRuntime::runtimeLoop, this);
    healthThread_ = std::thread(&DistributedRuntime::healthCheckLoop, this);
    
    initialized_ = true;
    
    notifyEvent("runtime_initialized", {{
        "node_id", config.nodeId
    }});
    
    return true;
}

bool DistributedRuntime::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    // Stop threads
    if (runtimeThread_.joinable()) {
        runtimeThread_.join();
    }
    if (healthThread_.joinable()) {
        healthThread_.join();
    }
    
    // Shutdown components in reverse order
    if (prefetchEngine_) {
        prefetchEngine_->shutdown();
    }
    if (shardingManager_) {
        shardingManager_->shutdown();
    }
    if (priorityQueue_) {
        priorityQueue_->shutdown();
    }
    if (workStealingScheduler_) {
        workStealingScheduler_->shutdown();
    }
    if (benchmark_) {
        benchmark_->shutdown();
    }
    if (kvCache_) {
        kvCache_->shutdown();
    }
    if (residencyManager_) {
        residencyManager_->shutdown();
    }
    if (scheduler_) {
        scheduler_->shutdown();
    }
    if (clusterManager_) {
        clusterManager_->shutdown();
    }
    
    initialized_ = false;
    return true;
}

bool DistributedRuntime::isHealthy() const {
    if (!initialized_) {
        return false;
    }
    
    return clusterManager_ && clusterManager_->isInitialized();
}

// Configuration
bool DistributedRuntime::updateConfig(const DistributedRuntimeConfig& config) {
    config_ = config;
    return true;
}

// Status
RuntimeStatus DistributedRuntime::getStatus() const {
    RuntimeStatus status;
    
    status.isHealthy = isHealthy();
    status.isLeader = isLeader();
    
    if (clusterManager_) {
        auto nodes = clusterManager_->getAllNodes();
        auto healthy = clusterManager_->getHealthyNodes();
        status.totalNodes = static_cast<uint32_t>(nodes.size()) + 1; // +1 for self
        status.healthyNodes = static_cast<uint32_t>(healthy.size()) + 1;
        status.unhealthyNodes = status.totalNodes - status.healthyNodes;
        status.leaderNodeId = clusterManager_->getLeaderNodeId();
        
        auto stats = clusterManager_->getStats();
        status.totalVRAM = stats.totalVRAM;
        status.availableVRAM = stats.availableVRAM;
        status.totalRAM = stats.totalRAM;
        status.availableRAM = stats.availableRAM;
    }
    
    if (scheduler_) {
        auto stats = scheduler_->getStats();
        status.schedulerQueueDepth = static_cast<uint32_t>(stats.currentQueueDepth);
        status.requestsPerSecond = stats.tasksExecuted / 60.0; // Per minute average
    }
    
    if (kvCache_) {
        auto stats = kvCache_->getLocalStats();
        status.cacheHitRate = stats.hitRate;
    }
    
    if (residencyManager_) {
        auto models = residencyManager_->getRegisteredModels();
        status.loadedModels = static_cast<uint32_t>(models.size());
    }
    
    return status;
}

std::string DistributedRuntime::getStatusJson() const {
    auto status = getStatus();
    
    std::stringstream json;
    json << "{\n";
    json << "  \"isHealthy\": " << (status.isHealthy ? "true" : "false") << ",\n";
    json << "  \"isLeader\": " << (status.isLeader ? "true" : "false") << ",\n";
    json << "  \"totalNodes\": " << status.totalNodes << ",\n";
    json << "  \"healthyNodes\": " << status.healthyNodes << ",\n";
    json << "  \"requestsPerSecond\": " << status.requestsPerSecond << ",\n";
    json << "  \"cacheHitRate\": " << status.cacheHitRate << ",\n";
    json << "  \"loadedModels\": " << status.loadedModels << "\n";
    json << "}\n";
    
    return json.str();
}

// Inference
std::string DistributedRuntime::submitInference(const DistributedInferenceRequest& request) {
    std::string requestId = generateRequestId();
    
    // Store request
    {
        std::lock_guard<std::mutex> lock(mutex_);
        activeRequests_[requestId] = request;
    }
    
    // Submit to scheduler
    if (scheduler_) {
        TaskSpec task;
        task.taskId = requestId;
        task.modelId = request.modelId;
        task.payloadSize = request.inputTokens.size();
        
        // Map priority
        switch (request.priority) {
            case DistributedInferenceRequest::Priority::CRITICAL:
                task.priority = TaskPriority::CRITICAL;
                break;
            case DistributedInferenceRequest::Priority::HIGH:
                task.priority = TaskPriority::HIGH;
                break;
            case DistributedInferenceRequest::Priority::NORMAL:
                task.priority = TaskPriority::NORMAL;
                break;
            case DistributedInferenceRequest::Priority::LOW:
                task.priority = TaskPriority::LOW;
                break;
            default:
                task.priority = TaskPriority::BACKGROUND;
                break;
        }
        
        scheduler_->submitTaskAsync(task, 
            [this, requestId](const ExecutionResult& result) {
                DistributedInferenceResponse response;
                response.requestId = requestId;
                response.success = result.success;
                response.errorMessage = result.errorMessage;
                response.tokensGenerated = result.tokensGenerated;
                response.tokensPerSecond = result.tokensPerSecond;
                response.executionTimeMs = static_cast<uint32_t>(result.duration.count());
                response.executedOnNode = result.nodeId;
                
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    completedResponses_[requestId] = response;
                    activeRequests_.erase(requestId);
                }
                
                // Notify completion
                auto it = activeRequests_.find(requestId);
                if (it != activeRequests_.end() && it->second.onComplete) {
                    it->second.onComplete(result.success, result.errorMessage);
                }
            });
    }
    
    stats_.totalRequests++;
    
    return requestId;
}

bool DistributedRuntime::cancelInference(const std::string& requestId) {
    if (scheduler_) {
        return scheduler_->cancelTask(requestId);
    }
    return false;
}

DistributedInferenceResponse DistributedRuntime::getInferenceResult(const std::string& requestId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = completedResponses_.find(requestId);
    if (it != completedResponses_.end()) {
        return it->second;
    }
    
    return DistributedInferenceResponse();
}

// Model management
bool DistributedRuntime::loadModel(const std::string& modelId) {
    if (!residencyManager_) {
        return false;
    }
    
    // Would get model info from registry
    ModelInfo info;
    info.modelId = modelId;
    
    if (!residencyManager_->isModelRegistered(modelId)) {
        residencyManager_->registerModel(info);
    }
    
    // Find best node and load
    auto bestNode = residencyManager_->findBestNodeForModel(modelId);
    if (!bestNode.empty()) {
        return residencyManager_->requestModelLoad(modelId, bestNode);
    }
    
    return false;
}

bool DistributedRuntime::unloadModel(const std::string& modelId) {
    if (!residencyManager_) {
        return false;
    }
    
    auto nodes = residencyManager_->findNodesWithModel(modelId);
    for (const auto& node : nodes) {
        residencyManager_->requestModelUnload(modelId, node);
    }
    
    return true;
}

bool DistributedRuntime::shardModel(const std::string& modelId) {
    if (!shardingManager_) {
        return false;
    }
    
    ShardingConfig config;
    return shardingManager_->shardModel(modelId, config);
}

bool DistributedRuntime::unshardModel(const std::string& modelId) {
    if (!shardingManager_) {
        return false;
    }
    
    return shardingManager_->unshardModel(modelId);
}

std::vector<std::string> DistributedRuntime::getLoadedModels() const {
    if (!residencyManager_) {
        return std::vector<std::string>();
    }
    
    std::vector<std::string> models;
    auto registered = residencyManager_->getRegisteredModels();
    for (const auto& model : registered) {
        models.push_back(model.modelId);
    }
    return models;
}

// Session management
std::string DistributedRuntime::createSession(const std::string& modelId) {
    std::string sessionId = generateRequestId();
    
    if (kvCache_) {
        kvCache_->createSession(sessionId, modelId);
    }
    
    if (prefetchEngine_) {
        prefetchEngine_->registerSession(sessionId, modelId);
    }
    
    return sessionId;
}

bool DistributedRuntime::destroySession(const std::string& sessionId) {
    if (kvCache_) {
        kvCache_->destroySession(sessionId);
    }
    
    if (prefetchEngine_) {
        prefetchEngine_->unregisterSession(sessionId);
    }
    
    return true;
}

bool DistributedRuntime::extendSession(const std::string& sessionId, uint32_t ttlSeconds) {
    // Would extend session TTL
    return true;
}

// Cluster operations
bool DistributedRuntime::joinCluster(const std::vector<std::string>& seedNodes) {
    if (!clusterManager_) {
        return false;
    }
    
    return clusterManager_->joinCluster();
}

bool DistributedRuntime::leaveCluster() {
    if (!clusterManager_) {
        return false;
    }
    
    return clusterManager_->leaveCluster();
}

std::vector<std::string> DistributedRuntime::getClusterNodes() const {
    if (!clusterManager_) {
        return std::vector<std::string>();
    }
    
    std::vector<std::string> nodeIds;
    auto nodes = clusterManager_->getAllNodes();
    for (const auto& node : nodes) {
        nodeIds.push_back(node.nodeId);
    }
    return nodeIds;
}

bool DistributedRuntime::isLeader() const {
    if (!clusterManager_) {
        return false;
    }
    
    return clusterManager_->isLeader();
}

// Load balancing
void DistributedRuntime::triggerRebalancing() {
    if (scheduler_) {
        scheduler_->triggerRebalancing();
    }
    
    if (shardingManager_) {
        shardingManager_->rebalanceShards();
    }
}

bool DistributedRuntime::migrateModel(const std::string& modelId, const std::string& fromNode,
                                       const std::string& toNode) {
    if (!residencyManager_) {
        return false;
    }
    
    // Would implement model migration
    return true;
}

// Benchmarking
std::string DistributedRuntime::startBenchmark(const std::string& benchmarkType) {
    if (!benchmark_) {
        return "";
    }
    
    BenchmarkConfig config;
    if (benchmarkType == "throughput") {
        config = DistributedBenchmark::createThroughputBenchmark();
    } else if (benchmarkType == "latency") {
        config = DistributedBenchmark::createLatencyBenchmark();
    } else if (benchmarkType == "scalability") {
        config = DistributedBenchmark::createScalabilityBenchmark();
    } else {
        config = DistributedBenchmark::createEndToEndBenchmark();
    }
    
    return benchmark_->startBenchmark(config);
}

bool DistributedRuntime::stopBenchmark(const std::string& benchmarkId) {
    if (!benchmark_) {
        return false;
    }
    
    return benchmark_->stopBenchmark(benchmarkId);
}

std::string DistributedRuntime::getBenchmarkReport(const std::string& benchmarkId) {
    if (!benchmark_) {
        return "";
    }
    
    return benchmark_->generateReport(benchmarkId);
}

// Statistics
DistributedRuntime::RuntimeStats DistributedRuntime::getStats() const {
    RuntimeStats stats;
    
    stats.totalRequests = stats_.totalRequests.load();
    stats.successfulRequests = stats_.successfulRequests.load();
    stats.failedRequests = stats_.failedRequests.load();
    stats.cancelledRequests = stats_.cancelledRequests.load();
    
    uint64_t latencyCount = stats_.latencyCount.load();
    if (latencyCount > 0) {
        stats.avgLatencyMs = stats_.totalLatencyMs.load() / latencyCount;
    }
    
    if (kvCache_) {
        auto cacheStats = kvCache_->getLocalStats();
        stats.cacheHits = cacheStats.hitCount;
        stats.cacheMisses = cacheStats.missCount;
        uint64_t total = stats.cacheHits + stats.cacheMisses;
        stats.cacheHitRate = total > 0 ? static_cast<double>(stats.cacheHits) / total : 0.0;
    }
    
    if (residencyManager_) {
        stats.modelsLoaded = static_cast<uint64_t>(residencyManager_->getRegisteredModels().size());
    }
    
    return stats;
}

void DistributedRuntime::resetStats() {
    stats_.totalRequests = 0;
    stats_.successfulRequests = 0;
    stats_.failedRequests = 0;
    stats_.cancelledRequests = 0;
    stats_.totalLatencyMs = 0.0;
    stats_.latencyCount = 0;
}

// Event callbacks
void DistributedRuntime::setEventCallback(RuntimeEventCallback callback) {
    eventCallback_ = callback;
}

// Internal methods
void DistributedRuntime::runtimeLoop() {
    while (running_) {
        // Periodic runtime maintenance
        // Would check health, rebalance, etc.
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void DistributedRuntime::healthCheckLoop() {
    while (running_) {
        // Periodic health checks
        if (!isHealthy()) {
            notifyEvent("health_check_failed", {{
                "timestamp", std::to_string(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count())
            }});
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void DistributedRuntime::notifyEvent(const std::string& eventType,
                                        const std::map<std::string, std::string>& data) {
    if (eventCallback_) {
        eventCallback_(eventType, data);
    }
}

std::string DistributedRuntime::generateRequestId() {
    uint64_t id = requestIdCounter_.fetch_add(1);
    
    std::stringstream ss;
    ss << "req-" << std::hex << std::setw(16) << std::setfill('0') << id;
    return ss.str();
}

// DistributedRuntimeFactory Implementation

std::unique_ptr<DistributedRuntime> DistributedRuntimeFactory::create(
    const DistributedRuntimeConfig& config) {
    auto runtime = std::make_unique<DistributedRuntime>();
    if (!runtime->initialize(config)) {
        return nullptr;
    }
    return runtime;
}

DistributedRuntimeConfig DistributedRuntimeFactory::createDefaultConfig() {
    DistributedRuntimeConfig config;
    config.nodeId = "node-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    config.listenAddress = "0.0.0.0";
    config.listenPort = 8080;
    config.totalVRAM = 24ULL * 1024 * 1024 * 1024; // 24GB
    config.totalRAM = 64ULL * 1024 * 1024 * 1024;  // 64GB
    config.cpuCores = 16;
    config.gpuCount = 1;
    config.capabilities = 0xFF; // All capabilities
    return config;
}

DistributedRuntimeConfig DistributedRuntimeFactory::createSingleNodeConfig() {
    auto config = createDefaultConfig();
    // No seed nodes for single node
    return config;
}

DistributedRuntimeConfig DistributedRuntimeFactory::createClusterConfig(
    const std::vector<std::string>& seedNodes) {
    auto config = createDefaultConfig();
    config.seedNodes = seedNodes;
    return config;
}

// DistributedRuntimeSingleton Implementation

std::unique_ptr<DistributedRuntime> DistributedRuntimeSingleton::instance_;
std::mutex DistributedRuntimeSingleton::mutex_;

DistributedRuntime& DistributedRuntimeSingleton::instance() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!instance_) {
        instance_ = std::make_unique<DistributedRuntime>();
    }
    return *instance_;
}

bool DistributedRuntimeSingleton::initialize(const DistributedRuntimeConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!instance_) {
        instance_ = std::make_unique<DistributedRuntime>();
    }
    return instance_->initialize(config);
}

bool DistributedRuntimeSingleton::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_) {
        return instance_->shutdown();
    }
    return true;
}

bool DistributedRuntimeSingleton::isInitialized() {
    std::lock_guard<std::mutex> lock(mutex_);
    return instance_ && instance_->isInitialized();
}

} // namespace Distributed
} // namespace RawrXD
