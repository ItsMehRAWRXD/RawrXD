/**
 * WorkScheduler.cpp
 *
 * Phase D.3 Batch 4/5: Work Distribution & Load Balancing
 *
 * Implementation of distributed task scheduling and load balancing.
 */

#include "WorkScheduler.hpp"
#include "../core/Logger.hpp"
#include "../core/ErrorCodes.hpp"
#include <chrono>
#include <random>

namespace Distributed {

// ============================================================================
// String Helpers
// ============================================================================

std::string TaskPriorityToString(TaskPriority priority) {
    switch (priority) {
        case TaskPriority::CRITICAL: return "critical";
        case TaskPriority::HIGH:     return "high";
        case TaskPriority::NORMAL:   return "normal";
        case TaskPriority::LOW:      return "low";
        case TaskPriority::BATCH:    return "batch";
        default: return "unknown";
    }
}

std::string TaskStateToString(TaskState state) {
    switch (state) {
        case TaskState::PENDING:    return "pending";
        case TaskState::SCHEDULED:  return "scheduled";
        case TaskState::RUNNING:    return "running";
        case TaskState::COMPLETED:  return "completed";
        case TaskState::FAILED:     return "failed";
        case TaskState::CANCELLED:  return "cancelled";
        default: return "unknown";
    }
}

std::string TaskTypeToString(TaskType type) {
    switch (type) {
        case TaskType::INFERENCE:        return "inference";
        case TaskType::TRAINING:         return "training";
        case TaskType::EVALUATION:       return "evaluation";
        case TaskType::DATA_PROCESSING:  return "data_processing";
        case TaskType::AGENT_TASK:       return "agent_task";
        case TaskType::SYSTEM_TASK:      return "system_task";
        case TaskType::CUSTOM:           return "custom";
        default: return "unknown";
    }
}

// ============================================================================
// ResourceRequirements Implementation
// ============================================================================

bool ResourceRequirements::CanBeSatisfiedBy(const ResourceRequirements& available) const {
    return cpuCores <= available.cpuCores &&
           memoryBytes <= available.memoryBytes &&
           gpuMemoryBytes <= available.gpuMemoryBytes &&
           gpuCount <= available.gpuCount &&
           diskBytes <= available.diskBytes;
}

std::string ResourceRequirements::ToJson() const {
    std::string json = "{";
    json += "\"cpuCores\":" + std::to_string(cpuCores) + ",";
    json += "\"memoryBytes\":" + std::to_string(memoryBytes) + ",";
    json += "\"gpuMemoryBytes\":" + std::to_string(gpuMemoryBytes) + ",";
    json += "\"gpuCount\":" + std::to_string(gpuCount) + ",";
    json += "\"diskBytes\":" + std::to_string(diskBytes) + ",";
    json += "\"networkBandwidth\":" + std::to_string(networkBandwidth);
    json += "}";
    return json;
}

// ============================================================================
// TaskSpec Implementation
// ============================================================================

std::string TaskSpec::ToJson() const {
    std::string json = "{";
    json += "\"taskId\":\"" + taskId + "\",";
    json += "\"type\":\"" + TaskTypeToString(type) + "\",";
    json += "\"priority\":\"" + TaskPriorityToString(priority) + "\",";
    json += "\"resources\":" + resources.ToJson() + ",";
    json += "\"payload\":\"" + payload + "\",";
    json += "\"nodeAffinity\":\"" + nodeAffinity + "\",";
    json += "\"maxRuntimeMs\":" + std::to_string(maxRuntimeMs) + ",";
    json += "\"maxRetries\":" + std::to_string(maxRetries);
    json += "}";
    return json;
}

TaskSpec TaskSpec::FromJson(const std::string& json) {
    TaskSpec spec;
    // Simplified parsing
    return spec;
}

// ============================================================================
// TaskStatus Implementation
// ============================================================================

std::string TaskStatus::ToJson() const {
    std::string json = "{";
    json += "\"taskId\":\"" + taskId + "\",";
    json += "\"state\":\"" + TaskStateToString(state) + "\",";
    json += "\"assignedNode\":\"" + assignedNode + "\",";
    json += "\"progress\":" + std::to_string(progress) + ",";
    json += "\"retryCount\":" + std::to_string(retryCount);
    if (!errorMessage.empty()) {
        json += ",\"error\":\"" + errorMessage + "\"";
    }
    json += "}";
    return json;
}

// ============================================================================
// NodeCapacity Implementation
// ============================================================================

ResourceRequirements NodeCapacity::GetAvailable() const {
    ResourceRequirements avail;
    avail.cpuCores = total.cpuCores - used.cpuCores;
    avail.memoryBytes = total.memoryBytes - used.memoryBytes;
    avail.gpuMemoryBytes = total.gpuMemoryBytes - used.gpuMemoryBytes;
    avail.gpuCount = total.gpuCount - used.gpuCount;
    avail.diskBytes = total.diskBytes - used.diskBytes;
    return avail;
}

bool NodeCapacity::CanAccept(const ResourceRequirements& requirements) const {
    return GetAvailable().CanBeSatisfiedBy(requirements);
}

float NodeCapacity::GetUtilizationScore() const {
    float cpuUtil = total.cpuCores > 0 ? 
        static_cast<float>(used.cpuCores) / total.cpuCores : 0.0f;
    float memUtil = total.memoryBytes > 0 ?
        static_cast<float>(used.memoryBytes) / total.memoryBytes : 0.0f;
    float gpuUtil = total.gpuCount > 0 ?
        static_cast<float>(used.gpuCount) / total.gpuCount : 0.0f;
    
    return (cpuUtil + memUtil + gpuUtil) / 3.0f;
}

std::string NodeCapacity::ToJson() const {
    std::string json = "{";
    json += "\"nodeId\":\"" + nodeId + "\",";
    json += "\"available\":" + GetAvailable().ToJson() + ",";
    json += "\"utilization\":" + std::to_string(GetUtilizationScore()) + ",";
    json += "\"activeTasks\":" + std::to_string(activeTasks) + ",";
    json += "\"isHealthy\":" + std::string(isHealthy ? "true" : "false");
    json += "}";
    return json;
}

// ============================================================================
// TaskQueue Implementation
// ============================================================================

TaskQueue::TaskQueue() = default;
TaskQueue::~TaskQueue() = default;

bool TaskQueue::QueuedTask::operator<(const QueuedTask& other) const {
    // Higher priority comes first
    if (spec.priority != other.spec.priority) {
        return spec.priority > other.spec.priority;
    }
    // Earlier enqueue time comes first
    return enqueueTime > other.enqueueTime;
}

void TaskQueue::Enqueue(const TaskSpec& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    QueuedTask qt;
    qt.spec = task;
    qt.enqueueTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    queue_.push(qt);
    taskMap_[task.taskId] = task;
}

std::optional<TaskSpec> TaskQueue::Dequeue() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.empty()) {
        return std::nullopt;
    }
    
    TaskSpec task = queue_.top().spec;
    queue_.pop();
    taskMap_.erase(task.taskId);
    
    return task;
}

std::optional<TaskSpec> TaskQueue::Dequeue(const NodeCapacity& nodeCapacity) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find first task that fits
    std::priority_queue<QueuedTask> tempQueue;
    std::optional<TaskSpec> result;
    
    while (!queue_.empty()) {
        QueuedTask qt = queue_.top();
        queue_.pop();
        
        if (!result && nodeCapacity.CanAccept(qt.spec.resources)) {
            result = qt.spec;
            taskMap_.erase(qt.spec.taskId);
        } else {
            tempQueue.push(qt);
        }
    }
    
    queue_ = std::move(tempQueue);
    return result;
}

std::optional<TaskSpec> TaskQueue::Peek() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.empty()) {
        return std::nullopt;
    }
    
    return queue_.top().spec;
}

bool TaskQueue::Remove(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = taskMap_.find(taskId);
    if (it == taskMap_.end()) {
        return false;
    }
    
    // Rebuild queue without this task
    std::priority_queue<QueuedTask> newQueue;
    while (!queue_.empty()) {
        QueuedTask qt = queue_.top();
        queue_.pop();
        if (qt.spec.taskId != taskId) {
            newQueue.push(qt);
        }
    }
    
    queue_ = std::move(newQueue);
    taskMap_.erase(it);
    
    return true;
}

bool TaskQueue::Contains(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return taskMap_.find(taskId) != taskMap_.end();
}

size_t TaskQueue::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

bool TaskQueue::IsEmpty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

size_t TaskQueue::CountByPriority(TaskPriority priority) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = 0;
    auto tempQueue = queue_;
    while (!tempQueue.empty()) {
        if (tempQueue.top().spec.priority == priority) {
            count++;
        }
        tempQueue.pop();
    }
    return count;
}

std::vector<TaskSpec> TaskQueue::GetAll() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<TaskSpec> result;
    for (const auto& [id, spec] : taskMap_) {
        result.push_back(spec);
    }
    return result;
}

std::vector<TaskSpec> TaskQueue::GetByType(TaskType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<TaskSpec> result;
    for (const auto& [id, spec] : taskMap_) {
        if (spec.type == type) {
            result.push_back(spec);
        }
    }
    return result;
}

void TaskQueue::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    while (!queue_.empty()) {
        queue_.pop();
    }
    taskMap_.clear();
}

// ============================================================================
// LoadBalancer Implementation
// ============================================================================

LoadBalancer::LoadBalancer(const SchedulingPolicy& policy) : policy_(policy) {}

LoadBalancer::~LoadBalancer() {
    Shutdown();
}

bool LoadBalancer::Initialize() {
    running_ = true;
    return true;
}

void LoadBalancer::Shutdown() {
    running_ = false;
}

void LoadBalancer::UpdateNodeCapacity(const NodeCapacity& capacity) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_[capacity.nodeId] = capacity;
}

void LoadBalancer::RemoveNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_.erase(nodeId);
}

std::optional<NodeCapacity> LoadBalancer::GetNodeCapacity(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<NodeCapacity> LoadBalancer::GetAllNodeCapacities() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<NodeCapacity> result;
    for (const auto& [id, capacity] : nodes_) {
        result.push_back(capacity);
    }
    return result;
}

std::optional<std::string> LoadBalancer::SelectNode(const TaskSpec& task) {
    switch (policy_.strategy) {
        case SchedulingPolicy::Strategy::ROUND_ROBIN:
            return SelectRoundRobin(task);
        case SchedulingPolicy::Strategy::LEAST_LOADED:
            return SelectLeastLoaded(task);
        case SchedulingPolicy::Strategy::MOST_LOCALITY:
            return SelectByLocality(task);
        case SchedulingPolicy::Strategy::FAIR_SHARE:
            return SelectByFairShare(task);
        case SchedulingPolicy::Strategy::BIN_PACKING:
            return SelectByBinPacking(task);
        default:
            return SelectLeastLoaded(task);
    }
}

std::vector<std::string> LoadBalancer::SelectNodes(const TaskSpec& task, size_t count) {
    std::vector<std::string> result;
    
    for (size_t i = 0; i < count; i++) {
        auto node = SelectNode(task);
        if (node) {
            result.push_back(*node);
        } else {
            break;
        }
    }
    
    return result;
}

bool LoadBalancer::NeedsRebalancing() {
    return !IsBalanced();
}

std::vector<std::pair<std::string, std::string>> LoadBalancer::GetRebalanceRecommendations() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::pair<std::string, std::string>> recommendations;
    
    // Find overloaded and underloaded nodes
    std::vector<std::string> overloaded;
    std::vector<std::string> underloaded;
    
    float avgUtil = GetAverageUtilization();
    for (const auto& [id, capacity] : nodes_) {
        float util = capacity.GetUtilizationScore();
        if (util > avgUtil + policy_.loadBalanceThreshold) {
            overloaded.push_back(id);
        } else if (util < avgUtil - policy_.loadBalanceThreshold) {
            underloaded.push_back(id);
        }
    }
    
    // Generate recommendations
    for (const auto& over : overloaded) {
        for (const auto& under : underloaded) {
            recommendations.emplace_back(over, under);
        }
    }
    
    return recommendations;
}

float LoadBalancer::GetAverageUtilization() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (nodes_.empty()) {
        return 0.0f;
    }
    
    float total = 0.0f;
    for (const auto& [id, capacity] : nodes_) {
        total += capacity.GetUtilizationScore();
    }
    
    return total / nodes_.size();
}

float LoadBalancer::GetUtilizationVariance() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (nodes_.size() < 2) {
        return 0.0f;
    }
    
    float avg = GetAverageUtilization();
    float variance = 0.0f;
    
    for (const auto& [id, capacity] : nodes_) {
        float diff = capacity.GetUtilizationScore() - avg;
        variance += diff * diff;
    }
    
    return variance / nodes_.size();
}

bool LoadBalancer::IsBalanced() const {
    return GetUtilizationVariance() < (policy_.loadBalanceThreshold * policy_.loadBalanceThreshold);
}

std::string LoadBalancer::GetStatusJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string json = "{";
    json += "\"strategy\":\"" + std::to_string(static_cast<int>(policy_.strategy)) + "\",";
    json += "\"nodes\":" + std::to_string(nodes_.size()) + ",";
    json += "\"averageUtilization\":" + std::to_string(GetAverageUtilization()) + ",";
    json += "\"variance\":" + std::to_string(GetUtilizationVariance()) + ",";
    json += "\"balanced\":" + std::string(IsBalanced() ? "true" : "false");
    json += "}";
    return json;
}

std::optional<std::string> LoadBalancer::SelectRoundRobin(const TaskSpec& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    static size_t lastIndex = 0;
    std::vector<std::string> eligible = GetEligibleNodes(task);
    
    if (eligible.empty()) {
        return std::nullopt;
    }
    
    lastIndex = (lastIndex + 1) % eligible.size();
    return eligible[lastIndex];
}

std::optional<std::string> LoadBalancer::SelectLeastLoaded(const TaskSpec& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> eligible = GetEligibleNodes(task);
    if (eligible.empty()) {
        return std::nullopt;
    }
    
    // Find least loaded
    std::string bestNode;
    float bestScore = std::numeric_limits<float>::max();
    
    for (const auto& nodeId : eligible) {
        auto it = nodes_.find(nodeId);
        if (it != nodes_.end()) {
            float score = CalculateNodeScore(it->second, task);
            if (score < bestScore) {
                bestScore = score;
                bestNode = nodeId;
            }
        }
    }
    
    return bestNode.empty() ? std::nullopt : std::optional<std::string>(bestNode);
}

std::optional<std::string> LoadBalancer::SelectByLocality(const TaskSpec& task) {
    // Prefer node affinity if specified
    if (!task.nodeAffinity.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = nodes_.find(task.nodeAffinity);
        if (it != nodes_.end() && it->second.CanAccept(task.resources)) {
            return task.nodeAffinity;
        }
    }
    
    // Fall back to least loaded
    return SelectLeastLoaded(task);
}

std::optional<std::string> LoadBalancer::SelectByFairShare(const TaskSpec& task) {
    // TODO: Implement fair share scheduling
    return SelectLeastLoaded(task);
}

std::optional<std::string> LoadBalancer::SelectByBinPacking(const TaskSpec& task) {
    // TODO: Implement bin packing
    return SelectLeastLoaded(task);
}

float LoadBalancer::CalculateNodeScore(const NodeCapacity& node, const TaskSpec& task) {
    // Lower score is better
    float utilization = node.GetUtilizationScore();
    float resourceFit = 0.0f;
    
    // Calculate how well task fits
    auto available = node.GetAvailable();
    if (task.resources.cpuCores > 0) {
        resourceFit += static_cast<float>(task.resources.cpuCores) / available.cpuCores;
    }
    if (task.resources.memoryBytes > 0) {
        resourceFit += static_cast<float>(task.resources.memoryBytes) / available.memoryBytes;
    }
    
    return utilization + resourceFit * 0.5f;
}

std::vector<std::string> LoadBalancer::GetEligibleNodes(const TaskSpec& task) {
    std::vector<std::string> eligible;
    
    for (const auto& [id, capacity] : nodes_) {
        // Skip unhealthy nodes
        if (!capacity.isHealthy) continue;
        
        // Skip anti-affinity nodes
        if (std::find(task.nodeAntiAffinity.begin(), task.nodeAntiAffinity.end(), id) 
            != task.nodeAntiAffinity.end()) {
            continue;
        }
        
        // Check resource requirements
        if (capacity.CanAccept(task.resources)) {
            eligible.push_back(id);
        }
    }
    
    return eligible;
}

// ============================================================================
// TaskDistributor Implementation
// ============================================================================

TaskDistributor::TaskDistributor(
    std::shared_ptr<CommunicationManager> commManager,
    std::shared_ptr<LoadBalancer> loadBalancer
) : commManager_(commManager), loadBalancer_(loadBalancer) {}

TaskDistributor::~TaskDistributor() {
    Shutdown();
}

bool TaskDistributor::Initialize() {
    running_ = true;
    monitorThread_ = std::thread(&TaskDistributor::MonitorLoop, this);
    return true;
}

void TaskDistributor::Shutdown() {
    running_ = false;
    
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
}

bool TaskDistributor::SubmitTask(const TaskSpec& task) {
    // Select node
    auto nodeId = loadBalancer_->SelectNode(task);
    if (!nodeId) {
        return false;
    }
    
    // Send task to node
    return SendTaskToNode(task, *nodeId);
}

bool TaskDistributor::SubmitTasks(const std::vector<TaskSpec>& tasks) {
    bool success = true;
    for (const auto& task : tasks) {
        if (!SubmitTask(task)) {
            success = false;
        }
    }
    return success;
}

bool TaskDistributor::CancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = taskStatus_.find(taskId);
    if (it == taskStatus_.end()) {
        return false;
    }
    
    if (it->second.state == TaskState::COMPLETED ||
        it->second.state == TaskState::FAILED ||
        it->second.state == TaskState::CANCELLED) {
        return false;
    }
    
    // Send cancel message
    Message msg;
    msg.header.type = MessageType::RPC_REQUEST;
    msg.header.destinationNode = it->second.assignedNode;
    msg.payload = "{\"action\":\"cancel\",\"taskId\":\"" + taskId + "\"}";
    
    commManager_->SendMessage(it->second.assignedNode, msg);
    
    it->second.state = TaskState::CANCELLED;
    return true;
}

std::optional<TaskStatus> TaskDistributor::GetTaskStatus(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = taskStatus_.find(taskId);
    if (it != taskStatus_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<TaskStatus> TaskDistributor::GetAllTaskStatus() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<TaskStatus> result;
    for (const auto& [id, status] : taskStatus_) {
        result.push_back(status);
    }
    return result;
}

std::vector<TaskStatus> TaskDistributor::GetTasksByState(TaskState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<TaskStatus> result;
    for (const auto& [id, status] : taskStatus_) {
        if (status.state == state) {
            result.push_back(status);
        }
    }
    return result;
}

bool TaskDistributor::WaitForTask(const std::string& taskId, uint64_t timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    while (true) {
        auto status = GetTaskStatus(taskId);
        if (status) {
            if (status->state == TaskState::COMPLETED ||
                status->state == TaskState::FAILED ||
                status->state == TaskState::CANCELLED) {
                return true;
            }
        }
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        
        if (elapsed >= timeoutMs) {
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool TaskDistributor::WaitForAllTasks(uint64_t timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    while (true) {
        bool allComplete = true;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& [id, status] : taskStatus_) {
                if (status.state == TaskState::PENDING ||
                    status.state == TaskState::SCHEDULED ||
                    status.state == TaskState::RUNNING) {
                    allComplete = false;
                    break;
                }
            }
        }
        
        if (allComplete) {
            return true;
        }
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        
        if (elapsed >= timeoutMs) {
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void TaskDistributor::OnTaskComplete(TaskCompleteCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    completeCallback_ = callback;
}

void TaskDistributor::MonitorLoop() {
    while (running_) {
        // Check for timed out tasks
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            
            for (auto& [id, status] : taskStatus_) {
                if (status.state == TaskState::RUNNING) {
                    auto it = taskSpecs_.find(id);
                    if (it != taskSpecs_.end()) {
                        if (now - status.startedTime > it->second.maxRuntimeMs) {
                            status.state = TaskState::FAILED;
                            status.errorMessage = "Timeout";
                            NotifyTaskComplete(status);
                        }
                    }
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void TaskDistributor::NotifyTaskComplete(const TaskStatus& status) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (completeCallback_) {
        completeCallback_(status);
    }
}

bool TaskDistributor::SendTaskToNode(const TaskSpec& task, const std::string& nodeId) {
    Message msg;
    msg.header.type = MessageType::RPC_REQUEST;
    msg.header.destinationNode = nodeId;
    msg.payload = task.ToJson();
    
    // Update status
    {
        std::lock_guard<std::mutex> lock(mutex_);
        TaskStatus status;
        status.taskId = task.taskId;
        status.state = TaskState::SCHEDULED;
        status.assignedNode = nodeId;
        status.scheduledTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        taskStatus_[task.taskId] = status;
        taskSpecs_[task.taskId] = task;
    }
    
    return commManager_->SendMessage(nodeId, msg);
}

// ============================================================================
// WorkScheduler Implementation
// ============================================================================

WorkScheduler::WorkScheduler(
    std::shared_ptr<CommunicationManager> commManager,
    const SchedulingPolicy& policy
) : commManager_(commManager), policy_(policy) {}

WorkScheduler::~WorkScheduler() {
    Shutdown();
}

bool WorkScheduler::Initialize() {
    running_ = true;
    
    taskQueue_ = std::make_unique<TaskQueue>();
    loadBalancer_ = std::make_unique<LoadBalancer>(policy_);
    distributor_ = std::make_unique<TaskDistributor>(commManager_, loadBalancer_);
    
    loadBalancer_->Initialize();
    distributor_->Initialize();
    
    schedulerThread_ = std::thread(&WorkScheduler::SchedulerLoop, this);
    rebalanceThread_ = std::thread(&WorkScheduler::RebalanceLoop, this);
    
    return true;
}

void WorkScheduler::Shutdown() {
    running_ = false;
    
    if (schedulerThread_.joinable()) {
        schedulerThread_.join();
    }
    if (rebalanceThread_.joinable()) {
        rebalanceThread_.join();
    }
    
    if (distributor_) {
        distributor_->Shutdown();
    }
    if (loadBalancer_) {
        loadBalancer_->Shutdown();
    }
}

std::string WorkScheduler::SubmitTask(const TaskSpec& task) {
    TaskSpec newTask = task;
    if (newTask.taskId.empty()) {
        newTask.taskId = GenerateTaskId();
    }
    
    // Add to queue
    taskQueue_->Enqueue(newTask);
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.totalTasksSubmitted++;
        stats_.pendingTasks++;
    }
    
    // Store spec
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        taskSpecs_[newTask.taskId] = newTask;
        
        TaskStatus status;
        status.taskId = newTask.taskId;
        status.state = TaskState::PENDING;
        status.createdTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        taskStatus_[newTask.taskId] = status;
    }
    
    return newTask.taskId;
}

std::vector<std::string> WorkScheduler::SubmitTasks(const std::vector<TaskSpec>& tasks) {
    std::vector<std::string> taskIds;
    for (const auto& task : tasks) {
        taskIds.push_back(SubmitTask(task));
    }
    return taskIds;
}

bool WorkScheduler::CancelTask(const std::string& taskId) {
    // Try to remove from queue first
    if (taskQueue_->Remove(taskId)) {
        std::lock_guard<std::mutex> lock(stateMutex_);
        auto it = taskStatus_.find(taskId);
        if (it != taskStatus_.end()) {
            it->second.state = TaskState::CANCELLED;
        }
        return true;
    }
    
    // Otherwise try to cancel via distributor
    return distributor_->CancelTask(taskId);
}

bool WorkScheduler::PauseTask(const std::string& taskId) {
    // TODO: Implement pause
    return false;
}

bool WorkScheduler::ResumeTask(const std::string& taskId) {
    // TODO: Implement resume
    return false;
}

std::optional<TaskStatus> WorkScheduler::GetTaskStatus(const std::string& taskId) {
    // Check local status first
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        auto it = taskStatus_.find(taskId);
        if (it != taskStatus_.end()) {
            return it->second;
        }
    }
    
    // Otherwise check distributor
    return distributor_->GetTaskStatus(taskId);
}

std::optional<TaskSpec> WorkScheduler::GetTaskSpec(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    auto it = taskSpecs_.find(taskId);
    if (it != taskSpecs_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<TaskStatus> WorkScheduler::GetTasksByState(TaskState state) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    std::vector<TaskStatus> result;
    for (const auto& [id, status] : taskStatus_) {
        if (status.state == state) {
            result.push_back(status);
        }
    }
    return result;
}

std::vector<TaskStatus> WorkScheduler::GetTasksByNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    std::vector<TaskStatus> result;
    for (const auto& [id, status] : taskStatus_) {
        if (status.assignedNode == nodeId) {
            result.push_back(status);
        }
    }
    return result;
}

bool WorkScheduler::WaitForTask(const std::string& taskId, uint64_t timeoutMs) {
    return distributor_->WaitForTask(taskId, timeoutMs);
}

bool WorkScheduler::WaitForTasks(const std::vector<std::string>& taskIds, uint64_t timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    for (const auto& taskId : taskIds) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        
        if (elapsed >= timeoutMs) {
            return false;
        }
        
        if (!WaitForTask(taskId, timeoutMs - elapsed)) {
            return false;
        }
    }
    
    return true;
}

std::optional<std::string> WorkScheduler::GetTaskResult(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    auto it = taskResults_.find(taskId);
    if (it != taskResults_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void WorkScheduler::OnTaskComplete(TaskResultCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    resultCallback_ = callback;
}

void WorkScheduler::RegisterNode(const std::string& nodeId, const NodeCapacity& capacity) {
    NodeCapacity cap = capacity;
    cap.nodeId = nodeId;
    loadBalancer_->UpdateNodeCapacity(cap);
}

void WorkScheduler::UnregisterNode(const std::string& nodeId) {
    loadBalancer_->RemoveNode(nodeId);
}

void WorkScheduler::UpdateNodeCapacity(const std::string& nodeId, const NodeCapacity& capacity) {
    NodeCapacity cap = capacity;
    cap.nodeId = nodeId;
    loadBalancer_->UpdateNodeCapacity(cap);
}

std::vector<std::string> WorkScheduler::GetActiveNodes() {
    auto capacities = loadBalancer_->GetAllNodeCapacities();
    std::vector<std::string> nodes;
    for (const auto& cap : capacities) {
        if (cap.isHealthy) {
            nodes.push_back(cap.nodeId);
        }
    }
    return nodes;
}

void WorkScheduler::PauseScheduling() {
    schedulingPaused_ = true;
}

void WorkScheduler::ResumeScheduling() {
    schedulingPaused_ = false;
}

bool WorkScheduler::IsSchedulingPaused() const {
    return schedulingPaused_.load();
}

WorkScheduler::Statistics WorkScheduler::GetStatistics() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

std::string WorkScheduler::GetStatisticsJson() const {
    auto stats = GetStatistics();
    
    std::string json = "{";
    json += "\"submitted\":" + std::to_string(stats.totalTasksSubmitted) + ",";
    json += "\"completed\":" + std::to_string(stats.totalTasksCompleted) + ",";
    json += "\"failed\":" + std::to_string(stats.totalTasksFailed) + ",";
    json += "\"cancelled\":" + std::to_string(stats.totalTasksCancelled) + ",";
    json += "\"pending\":" + std::to_string(stats.pendingTasks) + ",";
    json += "\"running\":" + std::to_string(stats.runningTasks) + ",";
    json += "\"utilization\":" + std::to_string(stats.clusterUtilization);
    json += "}";
    return json;
}

std::string WorkScheduler::GetStatusJson() const {
    std::string json = "{";
    json += "\"running\":" + std::string(running_ ? "true" : "false") + ",";
    json += "\"paused\":" + std::string(schedulingPaused_ ? "true" : "false") + ",";
    json += "\"statistics\":" + GetStatisticsJson() + ",";
    json += "\"loadBalancer\":" + loadBalancer_->GetStatusJson();
    json += "}";
    return json;
}

bool WorkScheduler::IsHealthy() const {
    return running_ && !schedulingPaused_;
}

void WorkScheduler::SchedulerLoop() {
    while (running_) {
        if (!schedulingPaused_) {
            ProcessQueue();
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void WorkScheduler::RebalanceLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        
        if (!running_) break;
        
        RebalanceIfNeeded();
    }
}

void WorkScheduler::ProcessQueue() {
    // Get node capacities
    auto nodes = loadBalancer_->GetAllNodeCapacities();
    
    for (const auto& node : nodes) {
        if (!node.isHealthy) continue;
        
        // Try to get a task that fits
        auto task = taskQueue_->Dequeue(node);
        if (!task) continue;
        
        // Schedule task
        if (ScheduleTask(*task)) {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.pendingTasks--;
            stats_.runningTasks++;
        } else {
            // Re-queue on failure
            taskQueue_->Enqueue(*task);
        }
    }
}

bool WorkScheduler::ScheduleTask(const TaskSpec& task) {
    // Select node
    auto nodeId = loadBalancer_->SelectNode(task);
    if (!nodeId) {
        return false;
    }
    
    // Send to distributor
    if (!distributor_->SubmitTask(task)) {
        return false;
    }
    
    // Update status
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        auto it = taskStatus_.find(task.taskId);
        if (it != taskStatus_.end()) {
            it->second.state = TaskState::SCHEDULED;
            it->second.assignedNode = *nodeId;
            it->second.scheduledTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        }
    }
    
    return true;
}

void WorkScheduler::UpdateTaskStatus(const TaskStatus& status) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    taskStatus_[status.taskId] = status;
}

void WorkScheduler::HandleTaskCompletion(const TaskStatus& status) {
    UpdateTaskStatus(status);
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.runningTasks--;
        
        switch (status.state) {
            case TaskState::COMPLETED:
                stats_.totalTasksCompleted++;
                break;
            case TaskState::FAILED:
                stats_.totalTasksFailed++;
                break;
            case TaskState::CANCELLED:
                stats_.totalTasksCancelled++;
                break;
            default:
                break;
        }
    }
    
    // Store result
    if (!status.result.empty()) {
        std::lock_guard<std::mutex> lock(stateMutex_);
        taskResults_[status.taskId] = status.result;
    }
    
    // Notify callback
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        if (resultCallback_) {
            resultCallback_(status.taskId, status.result);
        }
    }
}

void WorkScheduler::RebalanceIfNeeded() {
    if (!loadBalancer_->NeedsRebalancing()) {
        return;
    }
    
    auto recommendations = loadBalancer_->GetRebalanceRecommendations();
    // TODO: Implement task migration based on recommendations
}

std::string WorkScheduler::GenerateTaskId() {
    static std::atomic<uint64_t> counter{0};
    uint64_t id = counter.fetch_add(1);
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return "task-" + std::to_string(now) + "-" + std::to_string(id);
}

// ============================================================================
// DistributedExecutor Implementation
// ============================================================================

DistributedExecutor::DistributedExecutor(
    std::shared_ptr<CommunicationManager> commManager,
    const SchedulingPolicy& policy
) {
    scheduler_ = std::make_unique<WorkScheduler>(commManager, policy);
}

DistributedExecutor::~DistributedExecutor() {
    Shutdown();
}

bool DistributedExecutor::Initialize() {
    return scheduler_->Initialize();
}

void DistributedExecutor::Shutdown() {
    if (scheduler_) {
        scheduler_->Shutdown();
    }
}

std::future<std::string> DistributedExecutor::Execute(
    const std::string& command,
    const ResourceRequirements& resources
) {
    std::promise<std::string> promise;
    auto future = promise.get_future();
    
    TaskSpec task;
    task.type = TaskType::CUSTOM;
    task.priority = TaskPriority::NORMAL;
    task.resources = resources;
    task.payload = command;
    task.maxRetries = 3;
    
    std::string taskId = scheduler_->SubmitTask(task);
    
    // Set up callback
    scheduler_->OnTaskComplete(
        [promise = std::move(promise), taskId](const std::string& id, const std::string& result) mutable {
            if (id == taskId) {
                promise.set_value(result);
            }
        }
    );
    
    return future;
}

std::future<std::string> DistributedExecutor::ExecuteJson(
    const std::string& jsonCommand,
    const ResourceRequirements& resources
) {
    return Execute(jsonCommand, resources);
}

std::vector<std::future<std::string>> DistributedExecutor::ExecuteBatch(
    const std::vector<std::string>& commands,
    const ResourceRequirements& resources
) {
    std::vector<std::future<std::string>> futures;
    
    for (const auto& command : commands) {
        futures.push_back(Execute(command, resources));
    }
    
    return futures;
}

std::future<std::string> DistributedExecutor::MapReduce(
    const std::vector<std::string>& inputs,
    const std::string& mapFunction,
    const std::string& reduceFunction
) {
    // TODO: Implement map-reduce
    std::promise<std::string> promise;
    promise.set_value("");
    return promise.get_future();
}

std::string DistributedExecutor::GetStatusJson() const {
    return scheduler_->GetStatusJson();
}

} // namespace Distributed
