// RawrXD Work Stealing Scheduler Implementation
// Phase O.2: Advanced task scheduling with work stealing

#include "WorkStealingScheduler.hpp"
#include "ClusterManager.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Distributed {

// WorkStealingQueue Implementation

WorkStealingQueue::WorkStealingQueue(const std::string& nodeId)
    : nodeId_(nodeId)
{
}

WorkStealingQueue::~WorkStealingQueue() {
    clear();
}

void WorkStealingQueue::pushLocal(StealableTask&& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    tasks_.push_back(std::move(task));
    stats_.tasksPushed++;
}

bool WorkStealingQueue::popLocal(StealableTask& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (tasks_.empty()) {
        return false;
    }
    
    task = std::move(tasks_.front());
    tasks_.pop_front();
    stats_.tasksPopped++;
    return true;
}

bool WorkStealingQueue::peekLocal(StealableTask& task) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (tasks_.empty()) {
        return false;
    }
    
    task = tasks_.front();
    return true;
}

bool WorkStealingQueue::steal(StealableTask& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.stealAttempts++;
    
    if (tasks_.empty()) {
        stats_.failedSteals++;
        return false;
    }
    
    // Steal from the back (oldest tasks)
    task = std::move(tasks_.back());
    tasks_.pop_back();
    task.stealCount++;
    task.stealTime = std::chrono::steady_clock::now();
    
    stats_.tasksStolen++;
    return true;
}

size_t WorkStealingQueue::stealMultiple(std::vector<StealableTask>& tasks, size_t maxCount) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.stealAttempts++;
    
    size_t stolen = 0;
    while (!tasks_.empty() && stolen < maxCount) {
        StealableTask task;
        task = std::move(tasks_.back());
        tasks_.pop_back();
        task.stealCount++;
        task.stealTime = std::chrono::steady_clock::now();
        tasks.push_back(std::move(task));
        stolen++;
    }
    
    if (stolen == 0) {
        stats_.failedSteals++;
    } else {
        stats_.tasksStolen += stolen;
    }
    
    return stolen;
}

size_t WorkStealingQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tasks_.size();
}

bool WorkStealingQueue::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tasks_.empty();
}

void WorkStealingQueue::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    tasks_.clear();
}

WorkStealingQueue::QueueStats WorkStealingQueue::getStats() const {
    QueueStats stats;
    stats.tasksPushed = stats_.tasksPushed.load();
    stats.tasksPopped = stats_.tasksPopped.load();
    stats.tasksStolen = stats_.tasksStolen.load();
    stats.stealAttempts = stats_.stealAttempts.load();
    stats.failedSteals = stats_.failedSteals.load();
    stats.avgQueueDepth = static_cast<double>(tasks_.size());
    return stats;
}

void WorkStealingQueue::resetStats() {
    stats_.tasksPushed = 0;
    stats_.tasksPopped = 0;
    stats_.tasksStolen = 0;
    stats_.stealAttempts = 0;
    stats_.failedSteals = 0;
}

// VictimSelector Implementation

VictimSelector::VictimSelector(WorkStealingConfig::VictimSelection strategy)
    : strategy_(strategy)
    , rng_(std::random_device{}())
{
}

void VictimSelector::updateQueueSizes(const std::map<std::string, size_t>& sizes) {
    std::lock_guard<std::mutex> lock(mutex_);
    queueSizes_ = sizes;
}

std::string VictimSelector::selectVictim(const std::string& thiefId,
                                          const std::vector<std::string>& candidates) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (candidates.empty()) {
        return "";
    }
    
    // Filter out self
    std::vector<std::string> validCandidates;
    for (const auto& candidate : candidates) {
        if (candidate != thiefId) {
            validCandidates.push_back(candidate);
        }
    }
    
    if (validCandidates.empty()) {
        return "";
    }
    
    switch (strategy_) {
        case WorkStealingConfig::VictimSelection::RANDOM: {
            std::uniform_int_distribution<size_t> dist(0, validCandidates.size() - 1);
            return validCandidates[dist(rng_)];
        }
        
        case WorkStealingConfig::VictimSelection::LARGEST_QUEUE: {
            std::string bestVictim;
            size_t maxSize = 0;
            for (const auto& candidate : validCandidates) {
                auto it = queueSizes_.find(candidate);
                if (it != queueSizes_.end() && it->second > maxSize) {
                    maxSize = it->second;
                    bestVictim = candidate;
                }
            }
            return bestVictim.empty() ? validCandidates[0] : bestVictim;
        }
        
        case WorkStealingConfig::VictimSelection::NEIGHBOR: {
            // For now, just return first valid candidate
            // Would implement actual topology-aware selection
            return validCandidates[0];
        }
        
        case WorkStealingConfig::VictimSelection::LOAD_BASED: {
            // Select victim with highest load
            std::string bestVictim;
            size_t maxSize = 0;
            for (const auto& candidate : validCandidates) {
                auto it = queueSizes_.find(candidate);
                if (it != queueSizes_.end() && it->second > maxSize) {
                    maxSize = it->second;
                    bestVictim = candidate;
                }
            }
            return bestVictim.empty() ? validCandidates[0] : bestVictim;
        }
    }
    
    return "";
}

void VictimSelector::recordStealSuccess(const std::string& victimId) {
    std::lock_guard<std::mutex> lock(mutex_);
    successCount_[victimId]++;
}

void VictimSelector::recordStealFailure(const std::string& victimId) {
    std::lock_guard<std::mutex> lock(mutex_);
    failureCount_[victimId]++;
}

// WorkStealingScheduler Implementation

WorkStealingScheduler::WorkStealingScheduler(std::shared_ptr<ClusterManager> clusterManager)
    : running_(false)
    , initialized_(false)
    , clusterManager_(clusterManager)
    , currentBackoffMs_(0)
{
}

WorkStealingScheduler::~WorkStealingScheduler() {
    shutdown();
}

bool WorkStealingScheduler::initialize(const WorkStealingConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    localNodeId_ = clusterManager_->getLocalNodeId();
    
    // Create local queue
    localQueue_ = std::make_unique<WorkStealingQueue>(localNodeId_);
    
    // Create victim selector
    victimSelector_ = std::make_unique<VictimSelector>(config.victimSelection);
    
    running_ = true;
    
    // Start background threads
    if (config.enableWorkStealing) {
        stealingThread_ = std::thread(&WorkStealingScheduler::stealingLoop, this);
    }
    rebalancingThread_ = std::thread(&WorkStealingScheduler::rebalancingLoop, this);
    
    initialized_ = true;
    return true;
}

bool WorkStealingScheduler::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    // Stop threads
    if (stealingThread_.joinable()) {
        stealingThread_.join();
    }
    if (rebalancingThread_.joinable()) {
        rebalancingThread_.join();
    }
    
    initialized_ = false;
    return true;
}

// Task submission
std::string WorkStealingScheduler::submitTask(StealableTask&& task) {
    std::string taskId = generateTaskId();
    task.taskId = taskId;
    task.ownerNodeId = localNodeId_;
    task.submitTime = std::chrono::steady_clock::now();
    
    localQueue_->pushLocal(std::move(task));
    
    stats_.tasksSubmitted++;
    
    return taskId;
}

bool WorkStealingScheduler::cancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    
    auto it = activeTasks_.find(taskId);
    if (it != activeTasks_.end()) {
        activeTasks_.erase(it);
        return true;
    }
    
    return false;
}

// Local queue operations
bool WorkStealingScheduler::popTask(StealableTask& task) {
    // Try local queue first
    if (localQueue_->popLocal(task)) {
        stats_.tasksExecuted++;
        return true;
    }
    
    // Try stealing
    if (config_.enableWorkStealing && stealTask(task)) {
        stats_.tasksExecuted++;
        return true;
    }
    
    return false;
}

bool WorkStealingScheduler::tryPopTask(StealableTask& task, uint32_t timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    while (true) {
        if (popTask(task)) {
            return true;
        }
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        
        if (elapsed >= timeoutMs) {
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// Work stealing
bool WorkStealingScheduler::stealTask(StealableTask& task) {
    if (!config_.enableWorkStealing) {
        return false;
    }
    
    stats_.stealAttempts++;
    
    std::string victimId = selectVictim();
    if (victimId.empty()) {
        return false;
    }
    
    auto start = std::chrono::steady_clock::now();
    
    bool success = attemptSteal(victimId, task);
    
    auto end = std::chrono::steady_clock::now();
    auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    stats_.totalStealLatencyMs += latency;
    stats_.stealCount++;
    
    if (success) {
        stats_.successfulSteals++;
        stats_.tasksStolen++;
        stats_.stealsFromNode[victimId]++;
        victimSelector_->recordStealSuccess(victimId);
        currentBackoffMs_ = 0; // Reset backoff on success
    } else {
        stats_.failedSteals++;
        victimSelector_->recordStealFailure(victimId);
        backoff(currentBackoffMs_);
    }
    
    return success;
}

size_t WorkStealingScheduler::stealTasks(std::vector<StealableTask>& tasks, size_t maxCount) {
    if (!config_.enableWorkStealing) {
        return 0;
    }
    
    std::string victimId = selectVictim();
    if (victimId.empty()) {
        return 0;
    }
    
    return attemptStealMultiple(victimId, tasks, maxCount);
}

// Victim management
void WorkStealingScheduler::registerVictim(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(victimsMutex_);
    if (std::find(victims_.begin(), victims_.end(), nodeId) == victims_.end()) {
        victims_.push_back(nodeId);
    }
}

void WorkStealingScheduler::unregisterVictim(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(victimsMutex_);
    victims_.erase(std::remove(victims_.begin(), victims_.end(), nodeId), victims_.end());
}

std::vector<std::string> WorkStealingScheduler::getVictims() const {
    std::lock_guard<std::mutex> lock(victimsMutex_);
    return victims_;
}

// Load balancing
bool WorkStealingScheduler::isUnderloaded() const {
    return localQueue_->size() < config_.minQueueSizeToSteal;
}

bool WorkStealingScheduler::isOverloaded() const {
    // Consider overloaded if queue is significantly larger than average
    auto victims = getVictims();
    if (victims.empty()) {
        return false;
    }
    
    // Would calculate average queue size across cluster
    return localQueue_->size() > 10; // Simplified threshold
}

float WorkStealingScheduler::getLoadRatio() const {
    auto victims = getVictims();
    if (victims.empty()) {
        return 1.0f;
    }
    
    // Would calculate actual load ratio
    return 1.0f;
}

void WorkStealingScheduler::triggerRebalancing() {
    // Trigger immediate rebalancing
    // Would signal rebalancing thread
}

// Statistics
WorkStealingScheduler::StealingStats WorkStealingScheduler::getStats() const {
    StealingStats stats;
    
    stats.tasksSubmitted = stats_.tasksSubmitted.load();
    stats.tasksExecuted = stats_.tasksExecuted.load();
    stats.tasksStolen = stats_.tasksStolen.load();
    stats.stealAttempts = stats_.stealAttempts.load();
    stats.successfulSteals = stats_.successfulSteals.load();
    stats.failedSteals = stats_.failedSteals.load();
    
    uint64_t stealCount = stats_.stealCount.load();
    if (stealCount > 0) {
        stats.avgStealLatencyMs = stats_.totalStealLatencyMs.load() / stealCount;
    }
    
    // Copy per-node stats
    for (const auto& pair : stats_.stealsFromNode) {
        stats.stealsFromNode[pair.first] = pair.second.load();
    }
    for (const auto& pair : stats_.stealsToNode) {
        stats.stealsToNode[pair.first] = pair.second.load();
    }
    
    return stats;
}

void WorkStealingScheduler::resetStats() {
    stats_.tasksSubmitted = 0;
    stats_.tasksExecuted = 0;
    stats_.tasksStolen = 0;
    stats_.stealAttempts = 0;
    stats_.successfulSteals = 0;
    stats_.failedSteals = 0;
    stats_.totalStealLatencyMs = 0.0;
    stats_.stealCount = 0;
    
    for (auto& pair : stats_.stealsFromNode) {
        pair.second = 0;
    }
    for (auto& pair : stats_.stealsToNode) {
        pair.second = 0;
    }
}

// Configuration
bool WorkStealingScheduler::updateConfig(const WorkStealingConfig& config) {
    config_ = config;
    return true;
}

// Internal methods
void WorkStealingScheduler::stealingLoop() {
    while (running_) {
        if (!config_.enableWorkStealing) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        // Only steal if underloaded
        if (!isUnderloaded()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.stealIntervalMs));
            continue;
        }
        
        // Attempt to steal
        StealableTask task;
        if (stealTask(task)) {
            // Execute stolen task
            // Would integrate with actual execution
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.stealIntervalMs));
    }
}

void WorkStealingScheduler::rebalancingLoop() {
    while (running_) {
        // Update victim list
        updateVictimList();
        
        // Update victim selector with current queue sizes
        std::map<std::string, size_t> queueSizes;
        queueSizes[localNodeId_] = localQueue_->size();
        
        auto victims = getVictims();
        for (const auto& victim : victims) {
            // Would get actual queue sizes from remote nodes
            queueSizes[victim] = 0;
        }
        
        victimSelector_->updateQueueSizes(queueSizes);
        
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

std::string WorkStealingScheduler::selectVictim() {
    auto victims = getVictims();
    return victimSelector_->selectVictim(localNodeId_, victims);
}

bool WorkStealingScheduler::attemptSteal(const std::string& victimId, StealableTask& task) {
    // Would send RPC to victim node
    // For now, simulate failure
    return false;
}

size_t WorkStealingScheduler::attemptStealMultiple(const std::string& victimId,
                                                    std::vector<StealableTask>& tasks,
                                                    size_t maxCount) {
    // Would send RPC to victim node
    return 0;
}

void WorkStealingScheduler::updateVictimList() {
    auto nodes = clusterManager_->getAllNodes();
    
    std::lock_guard<std::mutex> lock(victimsMutex_);
    victims_.clear();
    
    for (const auto& node : nodes) {
        if (node.nodeId != localNodeId_) {
            victims_.push_back(node.nodeId);
        }
    }
}

void WorkStealingScheduler::backoff(uint32_t& currentBackoffMs) {
    if (currentBackoffMs == 0) {
        currentBackoffMs = config_.failedStealBackoffMs;
    } else {
        currentBackoffMs = std::min(currentBackoffMs * 2, config_.maxBackoffMs);
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(currentBackoffMs));
}

std::string WorkStealingScheduler::generateTaskId() {
    uint64_t id = taskIdCounter_.fetch_add(1);
    
    std::stringstream ss;
    ss << "ws-task-" << std::hex << std::setw(16) << std::setfill('0') << id;
    return ss.str();
}

} // namespace Distributed
} // namespace RawrXD
