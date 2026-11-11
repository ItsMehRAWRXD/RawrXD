// RawrXD Distributed Scheduler Implementation
// Phase O.2: Task Graph Scheduling with Resource Awareness

#include "DistributedScheduler.hpp"
#include "ClusterManager.hpp"
#include "ModelResidencyManager.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Distributed {

DistributedScheduler::DistributedScheduler(std::shared_ptr<ClusterManager> clusterManager)
    : running_(false)
    , initialized_(false)
    , isRebalancing_(false)
    , clusterManager_(clusterManager)
    , residencyManager_(nullptr)
{
}

DistributedScheduler::~DistributedScheduler() {
    shutdown();
}

bool DistributedScheduler::initialize(const SchedulerConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    running_ = true;
    
    // Start scheduler threads
    schedulerThread_ = std::thread(&DistributedScheduler::schedulerLoop, this);
    rebalancingThread_ = std::thread(&DistributedScheduler::rebalancingLoop, this);
    
    initialized_ = true;
    return true;
}

bool DistributedScheduler::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    // Cancel all pending tasks
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        while (!taskQueue_.empty()) {
            auto taskId = taskQueue_.front();
            taskQueue_.pop();
            failTask(taskId, "Scheduler shutting down");
        }
    }
    
    // Stop threads
    if (schedulerThread_.joinable()) {
        schedulerThread_.join();
    }
    if (rebalancingThread_.joinable()) {
        rebalancingThread_.join();
    }
    
    initialized_ = false;
    return true;
}

// Task submission
std::future<ExecutionResult> DistributedScheduler::submitTask(const TaskSpec& task) {
    auto promise = std::make_shared<std::promise<ExecutionResult>>();
    auto future = promise->get_future();
    
    std::string taskId = submitTaskAsync(task, nullptr);
    
    {
        std::lock_guard<std::mutex> lock(promisesMutex_);
        promises_[taskId] = promise;
    }
    
    return future;
}

std::string DistributedScheduler::submitTaskAsync(const TaskSpec& task, TaskCompletionCallback callback) {
    std::string taskId = generateTaskId();
    
    QueuedTask queuedTask;
    queuedTask.task = task;
    queuedTask.task.taskId = taskId;
    queuedTask.task.submittedAt = std::chrono::steady_clock::now();
    queuedTask.queuedAt = std::chrono::steady_clock::now();
    queuedTask.retryCount = 0;
    
    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        tasks_[taskId] = queuedTask;
    }
    
    if (callback) {
        std::lock_guard<std::mutex> lock(callbacksMutex_);
        callbacks_[taskId] = callback;
    }
    
    // Add to queue
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        taskQueue_.push(taskId);
    }
    
    // Update stats
    stats_.tasksSubmitted++;
    stats_.tasksQueued++;
    
    return taskId;
}

// Task management
bool DistributedScheduler::cancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) {
        return false;
    }
    
    // Check if already running
    if (runningTasks_.find(taskId) != runningTasks_.end()) {
        // Cannot cancel running task
        return false;
    }
    
    // Mark as cancelled
    ExecutionResult result;
    result.taskId = taskId;
    result.success = false;
    result.errorMessage = "Task cancelled by user";
    
    completeTask(taskId, result);
    stats_.tasksCancelled++;
    
    return true;
}

TaskSpec DistributedScheduler::getTaskStatus(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    
    auto it = tasks_.find(taskId);
    if (it != tasks_.end()) {
        return it->second.task;
    }
    
    return TaskSpec();
}

std::vector<TaskSpec> DistributedScheduler::getQueuedTasks() const {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    std::lock_guard<std::mutex> queueLock(queueMutex_);
    
    std::vector<TaskSpec> result;
    auto queueCopy = taskQueue_;
    
    while (!queueCopy.empty()) {
        auto taskId = queueCopy.front();
        queueCopy.pop();
        
        auto it = tasks_.find(taskId);
        if (it != tasks_.end()) {
            result.push_back(it->second.task);
        }
    }
    
    return result;
}

std::vector<TaskSpec> DistributedScheduler::getRunningTasks() const {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    
    std::vector<TaskSpec> result;
    for (const auto& taskId : runningTasks_) {
        auto it = tasks_.find(taskId);
        if (it != tasks_.end()) {
            result.push_back(it->second.task);
        }
    }
    
    return result;
}

// Scheduling
SchedulingDecision DistributedScheduler::scheduleTask(const TaskSpec& task) {
    SchedulingDecision decision;
    decision.taskId = task.taskId;
    decision.canExecute = false;
    
    // Get candidate nodes
    auto candidates = getCandidateNodes(task);
    if (candidates.empty()) {
        decision.reason = "No nodes available with required capabilities";
        return decision;
    }
    
    // Score nodes
    auto scores = scoreNodesForTask(task);
    if (scores.empty()) {
        decision.reason = "No nodes meet task requirements";
        return decision;
    }
    
    // Select best node
    auto& bestScore = scores[0];
    decision.nodeId = bestScore.nodeId;
    decision.canExecute = true;
    decision.reason = "Selected based on scheduling policy";
    decision.estimatedLatencyMs = static_cast<uint32_t>(bestScore.latencyScore * 1000);
    decision.queuePosition = bestScore.queueScore > 0 ? 
        static_cast<uint32_t>(1.0f / bestScore.queueScore) : 0;
    
    // Get fallback nodes
    for (size_t i = 1; i < scores.size() && i < 3; i++) {
        decision.fallbackNodes.push_back(scores[i].nodeId);
    }
    
    return decision;
}

std::vector<NodeScore> DistributedScheduler::scoreNodesForTask(const TaskSpec& task) {
    std::vector<NodeScore> scores;
    
    auto nodes = clusterManager_->getHealthyNodes();
    
    for (const auto& node : nodes) {
        if (!canNodeExecuteTask(node, task)) {
            continue;
        }
        
        NodeScore score;
        score.nodeId = node.nodeId;
        
        // Calculate component scores
        score.resourceScore = calculateResourceScore(node, task);
        score.latencyScore = calculateLatencyScore(node);
        score.queueScore = calculateQueueScore(node);
        score.affinityScore = calculateAffinityScore(node, task);
        score.capabilityScore = calculateCapabilityScore(node, task);
        score.healthScore = node.health.isHealthy ? 1.0f : 0.0f;
        
        // Calculate weighted total
        score.totalScore = 
            config_.resourceWeight * score.resourceScore +
            config_.latencyWeight * score.latencyScore +
            config_.queueWeight * score.queueScore +
            config_.affinityWeight * score.affinityScore +
            config_.capabilityWeight * score.capabilityScore;
        
        // Additional details
        score.availableVRAM = node.resources.availableVRAM;
        score.queueDepth = getQueueDepthForNode(node.nodeId);
        score.latencyMs = node.health.latencyMs;
        score.hasModelLoaded = false; // Would check residency manager
        
        scores.push_back(score);
    }
    
    // Sort by total score (descending)
    std::sort(scores.begin(), scores.end(), 
        [](const NodeScore& a, const NodeScore& b) {
            return a.totalScore > b.totalScore;
        });
    
    return scores;
}

std::vector<std::string> DistributedScheduler::getCandidateNodes(const TaskSpec& task) {
    std::vector<std::string> candidates;
    
    auto nodes = clusterManager_->getHealthyNodes();
    
    for (const auto& node : nodes) {
        if (canNodeExecuteTask(node, task)) {
            candidates.push_back(node.nodeId);
        }
    }
    
    return candidates;
}

// Queue management
size_t DistributedScheduler::getQueueDepth() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return taskQueue_.size();
}

size_t DistributedScheduler::getQueueDepthForNode(const std::string& nodeId) const {
    // This would track per-node queue depth
    // Current implementation returns estimated value
    return getQueueDepth() / std::max<size_t>(1, clusterManager_->getAllNodes().size());
}

void DistributedScheduler::clearQueue() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    while (!taskQueue_.empty()) {
        auto taskId = taskQueue_.front();
        taskQueue_.pop();
        
        ExecutionResult result;
        result.taskId = taskId;
        result.success = false;
        result.errorMessage = "Queue cleared";
        completeTask(taskId, result);
    }
}

// Statistics
DistributedScheduler::SchedulerStats DistributedScheduler::getStats() const {
    SchedulerStats stats;
    
    stats.tasksSubmitted = stats_.tasksSubmitted.load();
    stats.tasksExecuted = stats_.tasksExecuted.load();
    stats.tasksFailed = stats_.tasksFailed.load();
    stats.tasksCancelled = stats_.tasksCancelled.load();
    stats.tasksQueued = stats_.tasksQueued.load();
    
    uint64_t execCount = stats_.tasksExecuted.load();
    if (execCount > 0) {
        stats.avgLatencyMs = stats_.totalLatencyMs.load() / execCount;
        stats.avgQueueTimeMs = stats_.totalQueueTimeMs.load() / execCount;
        stats.avgExecutionTimeMs = stats_.totalExecutionTimeMs.load() / execCount;
    }
    
    stats.currentQueueDepth = static_cast<uint32_t>(getQueueDepth());
    
    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        stats.currentRunningTasks = static_cast<uint32_t>(runningTasks_.size());
    }
    
    return stats;
}

void DistributedScheduler::resetStats() {
    stats_.tasksSubmitted = 0;
    stats_.tasksExecuted = 0;
    stats_.tasksFailed = 0;
    stats_.tasksCancelled = 0;
    stats_.tasksQueued = 0;
    stats_.totalLatencyMs = 0.0;
    stats_.totalQueueTimeMs = 0.0;
    stats_.totalExecutionTimeMs = 0.0;
}

// Configuration
bool DistributedScheduler::updateConfig(const SchedulerConfig& config) {
    config_ = config;
    return true;
}

// Load balancing
void DistributedScheduler::triggerRebalancing() {
    isRebalancing_ = true;
}

// Internal methods
void DistributedScheduler::schedulerLoop() {
    while (running_) {
        // Process queued tasks
        std::string taskId;
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (!taskQueue_.empty()) {
                taskId = taskQueue_.front();
                taskQueue_.pop();
            }
        }
        
        if (!taskId.empty()) {
            QueuedTask queuedTask;
            {
                std::lock_guard<std::mutex> lock(tasksMutex_);
                auto it = tasks_.find(taskId);
                if (it != tasks_.end()) {
                    queuedTask = it->second;
                    runningTasks_.insert(taskId);
                }
            }
            
            if (!queuedTask.task.taskId.empty()) {
                executeTask(queuedTask);
            }
        }
        
        // Small sleep to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void DistributedScheduler::rebalancingLoop() {
    while (running_) {
        if (isRebalancing_) {
            // Perform rebalancing logic
            // Move tasks from overloaded nodes to underloaded nodes
            isRebalancing_ = false;
        }
        
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.rebalanceIntervalMs));
    }
}

void DistributedScheduler::executeTask(const QueuedTask& queuedTask) {
    // Schedule the task
    auto decision = scheduleTask(queuedTask.task);
    
    if (!decision.canExecute) {
        // Retry if possible
        if (queuedTask.retryCount < config_.maxRetries) {
            auto mutableTask = queuedTask;
            mutableTask.retryCount++;
            
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.retryDelayMs));
            
            {
                std::lock_guard<std::mutex> lock(queueMutex_);
                taskQueue_.push(queuedTask.task.taskId);
            }
        } else {
            failTask(queuedTask.task.taskId, "Max retries exceeded: " + decision.reason);
        }
        
        {
            std::lock_guard<std::mutex> lock(tasksMutex_);
            runningTasks_.erase(queuedTask.task.taskId);
        }
        return;
    }
    
    // Update task with scheduling info
    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        auto it = tasks_.find(queuedTask.task.taskId);
        if (it != tasks_.end()) {
            it->second.task.startedAt = std::chrono::steady_clock::now();
        }
    }
    
    // Execute task (would integrate with actual inference engine)
    ExecutionResult result;
    result.taskId = queuedTask.task.taskId;
    result.nodeId = decision.nodeId;
    result.success = true;
    result.duration = std::chrono::milliseconds(100); // Basic timing
    result.tokensGenerated = 100;
    result.tokensPerSecond = 1000;
    
    completeTask(queuedTask.task.taskId, result);
}

void DistributedScheduler::completeTask(const std::string& taskId, const ExecutionResult& result) {
    // Update stats
    stats_.tasksExecuted++;
    stats_.totalLatencyMs += result.duration.count();
    
    // Notify callback
    {
        std::lock_guard<std::mutex> lock(callbacksMutex_);
        auto it = callbacks_.find(taskId);
        if (it != callbacks_.end() && it->second) {
            it->second(result);
            callbacks_.erase(it);
        }
    }
    
    // Complete promise
    {
        std::lock_guard<std::mutex> lock(promisesMutex_);
        auto it = promises_.find(taskId);
        if (it != promises_.end()) {
            it->second->set_value(result);
            promises_.erase(it);
        }
    }
    
    // Remove from running tasks
    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        runningTasks_.erase(taskId);
    }
}

void DistributedScheduler::failTask(const std::string& taskId, const std::string& error) {
    stats_.tasksFailed++;
    
    ExecutionResult result;
    result.taskId = taskId;
    result.success = false;
    result.errorMessage = error;
    
    completeTask(taskId, result);
}

// Scoring methods
float DistributedScheduler::calculateNodeScore(const NodeInfo& node, const TaskSpec& task) {
    if (!canNodeExecuteTask(node, task)) {
        return 0.0f;
    }
    
    float score = 0.0f;
    score += config_.resourceWeight * calculateResourceScore(node, task);
    score += config_.latencyWeight * calculateLatencyScore(node);
    score += config_.queueWeight * calculateQueueScore(node);
    score += config_.affinityWeight * calculateAffinityScore(node, task);
    score += config_.capabilityWeight * calculateCapabilityScore(node, task);
    
    return score;
}

float DistributedScheduler::calculateResourceScore(const NodeInfo& node, const TaskSpec& task) {
    float score = 1.0f;
    
    // Check VRAM availability
    if (task.requirements.minVRAM > 0) {
        float vramRatio = static_cast<float>(node.resources.availableVRAM) / 
                         static_cast<float>(task.requirements.minVRAM);
        score *= std::min(vramRatio, 1.0f);
    }
    
    // Check RAM availability
    if (task.requirements.minRAM > 0) {
        float ramRatio = static_cast<float>(node.resources.availableRAM) / 
                        static_cast<float>(task.requirements.minRAM);
        score *= std::min(ramRatio, 1.0f);
    }
    
    // Check CPU cores
    if (task.requirements.minCpuCores > 0) {
        float cpuRatio = static_cast<float>(node.resources.cpuCores) / 
                        static_cast<float>(task.requirements.minCpuCores);
        score *= std::min(cpuRatio, 1.0f);
    }
    
    return score;
}

float DistributedScheduler::calculateLatencyScore(const NodeInfo& node) {
    // Lower latency = higher score
    if (node.health.latencyMs == 0) {
        return 1.0f;
    }
    
    float normalizedLatency = static_cast<float>(node.health.latencyMs) / 100.0f;
    return std::max(0.0f, 1.0f - normalizedLatency);
}

float DistributedScheduler::calculateQueueScore(const NodeInfo& node) {
    // Lower queue depth = higher score
    uint32_t queueDepth = getQueueDepthForNode(node.nodeId);
    if (queueDepth == 0) {
        return 1.0f;
    }
    
    float normalizedQueue = static_cast<float>(queueDepth) / 
                           static_cast<float>(config_.maxQueueDepthPerNode);
    return std::max(0.0f, 1.0f - normalizedQueue);
}

float DistributedScheduler::calculateAffinityScore(const NodeInfo& node, const TaskSpec& task) {
    // Check if model is already loaded on this node
    // Would integrate with residency manager
    return 0.5f; // Neutral score for now
}

float DistributedScheduler::calculateCapabilityScore(const NodeInfo& node, const TaskSpec& task) {
    float score = 1.0f;
    
    // Check GPU requirement
    if (task.requirements.requiresGPU && 
        (node.capabilities & static_cast<uint32_t>(NodeCapability::GPU)) == 0) {
        return 0.0f;
    }
    
    // Check quantized support
    if (task.requirements.supportsQuantized &&
        (node.capabilities & static_cast<uint32_t>(NodeCapability::QUANTIZED)) == 0) {
        score *= 0.5f;
    }
    
    // Check streaming support
    if (task.requirements.requiresStreaming &&
        (node.capabilities & static_cast<uint32_t>(NodeCapability::STREAMING)) == 0) {
        return 0.0f;
    }
    
    return score;
}

bool DistributedScheduler::canNodeExecuteTask(const NodeInfo& node, const TaskSpec& task) {
    if (!node.health.isHealthy) {
        return false;
    }
    
    return meetsRequirements(node, task.requirements);
}

bool DistributedScheduler::meetsRequirements(const NodeInfo& node, const TaskSpec::Requirements& req) {
    // Check GPU requirement
    if (req.requiresGPU && 
        (node.capabilities & static_cast<uint32_t>(NodeCapability::GPU)) == 0) {
        return false;
    }
    
    // Check VRAM
    if (req.minVRAM > 0 && node.resources.availableVRAM < req.minVRAM) {
        return false;
    }
    
    // Check RAM
    if (req.minRAM > 0 && node.resources.availableRAM < req.minRAM) {
        return false;
    }
    
    // Check CPU cores
    if (req.minCpuCores > 0 && node.resources.cpuCores < req.minCpuCores) {
        return false;
    }
    
    // Check streaming support
    if (req.requiresStreaming &&
        (node.capabilities & static_cast<uint32_t>(NodeCapability::STREAMING)) == 0) {
        return false;
    }
    
    return true;
}

std::string DistributedScheduler::generateTaskId() {
    uint64_t id = taskIdCounter_.fetch_add(1);
    
    std::stringstream ss;
    ss << "task-" << std::hex << std::setw(16) << std::setfill('0') << id;
    return ss.str();
}

void DistributedScheduler::cleanupCompletedTasks() {
    // Periodically clean up old completed tasks
    // Implementation would remove tasks older than retention period
}

} // namespace Distributed
} // namespace RawrXD
