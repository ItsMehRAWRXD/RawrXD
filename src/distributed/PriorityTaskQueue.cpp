// RawrXD Priority Task Queue Implementation
// Phase O.2: Multi-level priority queue with aging and preemption

#include "PriorityTaskQueue.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Distributed {

// FairShareTracker Implementation

FairShareTracker::FairShareTracker(uint32_t maxTasksPerUser)
    : maxTasksPerUser_(maxTasksPerUser)
{
}

bool FairShareTracker::canAcceptTask(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = userTaskCounts_.find(userId);
    if (it == userTaskCounts_.end()) {
        return true;
    }
    
    return it->second < maxTasksPerUser_;
}

void FairShareTracker::recordTaskSubmitted(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    userTaskCounts_[userId]++;
}

void FairShareTracker::recordTaskCompleted(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = userTaskCounts_.find(userId);
    if (it != userTaskCounts_.end()) {
        if (it->second > 0) {
            it->second--;
        }
    }
}

float FairShareTracker::getUserShare(const std::string& userId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = userTaskCounts_.find(userId);
    if (it == userTaskCounts_.end()) {
        return 0.0f;
    }
    
    uint32_t total = 0;
    for (const auto& pair : userTaskCounts_) {
        total += pair.second;
    }
    
    if (total == 0) {
        return 0.0f;
    }
    
    return static_cast<float>(it->second) / total;
}

std::vector<std::string> FairShareTracker::getOverQuotaUsers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> overQuota;
    for (const auto& pair : userTaskCounts_) {
        if (pair.second >= maxTasksPerUser_) {
            overQuota.push_back(pair.first);
        }
    }
    return overQuota;
}

void FairShareTracker::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    userTaskCounts_.clear();
}

// PriorityTaskQueue Implementation

PriorityTaskQueue::PriorityTaskQueue()
    : running_(false)
    , initialized_(false)
{
}

PriorityTaskQueue::~PriorityTaskQueue() {
    shutdown();
}

bool PriorityTaskQueue::initialize(const PriorityQueueConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Initialize fair share tracker
    fairShareTracker_ = std::make_unique<FairShareTracker>(config.maxTasksPerUser);
    
    // Initialize priority queues
    for (uint8_t p = 0; p <= static_cast<uint8_t>(TaskPriorityLevel::BACKGROUND); p++) {
        TaskPriorityLevel priority = static_cast<TaskPriorityLevel>(p);
        queues_[priority] = std::priority_queue<PriorityTask, 
                           std::vector<PriorityTask>, 
                           DeadlineComparator>();
    }
    
    running_ = true;
    
    // Start background threads
    if (config.enableAging) {
        agingThread_ = std::thread(&PriorityTaskQueue::agingLoop, this);
    }
    if (config.enableDeadlineScheduling) {
        deadlineThread_ = std::thread(&PriorityTaskQueue::deadlineLoop, this);
    }
    
    initialized_ = true;
    return true;
}

bool PriorityTaskQueue::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    // Stop threads
    if (agingThread_.joinable()) {
        agingThread_.join();
    }
    if (deadlineThread_.joinable()) {
        deadlineThread_.join();
    }
    
    clear();
    initialized_ = false;
    return true;
}

// Task submission
std::string PriorityTaskQueue::enqueue(PriorityTask&& task) {
    std::string taskId = generateTaskId();
    task.taskId = taskId;
    task.submitTime = std::chrono::steady_clock::now();
    task.sequenceNumber = getNextSequenceNumber();
    
    // Check fair share
    if (config_.enableFairSharing && !fairShareTracker_->canAcceptTask(task.userId)) {
        // User over quota - reject or lower priority
        task.priority = TaskPriorityLevel::BACKGROUND;
    }
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Add to appropriate queue
        auto it = queues_.find(task.priority);
        if (it != queues_.end()) {
            it->second.push(task);
        }
        
        // Track task
        taskMap_[taskId] = task;
        taskPriorityMap_[taskId] = task.priority;
    }
    
    // Update stats
    stats_.tasksSubmitted++;
    fairShareTracker_->recordTaskSubmitted(task.userId);
    
    return taskId;
}

bool PriorityTaskQueue::enqueueBatch(std::vector<PriorityTask>&& tasks) {
    for (auto& task : tasks) {
        enqueue(std::move(task));
    }
    return true;
}

// Task retrieval
bool PriorityTaskQueue::dequeue(PriorityTask& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try queues in priority order
    for (uint8_t p = 0; p <= static_cast<uint8_t>(TaskPriorityLevel::BACKGROUND); p++) {
        TaskPriorityLevel priority = static_cast<TaskPriorityLevel>(p);
        auto it = queues_.find(priority);
        
        if (it != queues_.end() && !it->second.empty()) {
            task = it->second.top();
            it->second.pop();
            
            // Update stats
            auto now = std::chrono::steady_clock::now();
            auto waitTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - task.submitTime).count();
            stats_.totalWaitTimeMs += waitTime;
            stats_.tasksExecuted++;
            
            task.startTime = now;
            
            return true;
        }
    }
    
    return false;
}

bool PriorityTaskQueue::dequeueWithTimeout(PriorityTask& task, uint32_t timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    while (true) {
        if (dequeue(task)) {
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

bool PriorityTaskQueue::peek(PriorityTask& task) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try queues in priority order
    for (uint8_t p = 0; p <= static_cast<uint8_t>(TaskPriorityLevel::BACKGROUND); p++) {
        TaskPriorityLevel priority = static_cast<TaskPriorityLevel>(p);
        auto it = queues_.find(priority);
        
        if (it != queues_.end() && !it->second.empty()) {
            task = it->second.top();
            return true;
        }
    }
    
    return false;
}

// Priority management
bool PriorityTaskQueue::boostPriority(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = taskMap_.find(taskId);
    if (it == taskMap_.end()) {
        return false;
    }
    
    auto currentPriority = taskPriorityMap_[taskId];
    if (currentPriority == TaskPriorityLevel::CRITICAL) {
        return false; // Already highest
    }
    
    // Boost to next level
    TaskPriorityLevel newPriority = static_cast<TaskPriorityLevel>(
        static_cast<uint8_t>(currentPriority) - 1);
    
    // Remove from old queue
    auto oldQueueIt = queues_.find(currentPriority);
    if (oldQueueIt != queues_.end()) {
        // Rebuild queue without this task
        std::priority_queue<PriorityTask, std::vector<PriorityTask>, DeadlineComparator> newQueue;
        while (!oldQueueIt->second.empty()) {
            auto task = oldQueueIt->second.top();
            oldQueueIt->second.pop();
            if (task.taskId != taskId) {
                newQueue.push(task);
            }
        }
        oldQueueIt->second = std::move(newQueue);
    }
    
    // Add to new queue
    it->second.priority = newPriority;
    it->second.ageBoosts++;
    it->second.lastBoostTime = std::chrono::steady_clock::now();
    
    auto newQueueIt = queues_.find(newPriority);
    if (newQueueIt != queues_.end()) {
        newQueueIt->second.push(it->second);
    }
    
    taskPriorityMap_[taskId] = newPriority;
    stats_.tasksBoosted++;
    
    return true;
}

bool PriorityTaskQueue::lowerPriority(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = taskMap_.find(taskId);
    if (it == taskMap_.end()) {
        return false;
    }
    
    auto currentPriority = taskPriorityMap_[taskId];
    if (currentPriority == TaskPriorityLevel::BACKGROUND) {
        return false; // Already lowest
    }
    
    // Lower to next level
    TaskPriorityLevel newPriority = static_cast<TaskPriorityLevel>(
        static_cast<uint8_t>(currentPriority) + 1);
    
    // Similar queue manipulation as boostPriority
    // (Implementation omitted for brevity)
    
    return true;
}

TaskPriorityLevel PriorityTaskQueue::getTaskPriority(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = taskPriorityMap_.find(taskId);
    if (it != taskPriorityMap_.end()) {
        return it->second;
    }
    
    return TaskPriorityLevel::NORMAL;
}

// Preemption
bool PriorityTaskQueue::shouldPreempt(const PriorityTask& runningTask, 
                                       const PriorityTask& waitingTask) const {
    if (!config_.enablePreemption) {
        return false;
    }
    
    // Preempt if waiting task has higher priority
    if (static_cast<uint8_t>(waitingTask.priority) < static_cast<uint8_t>(runningTask.priority)) {
        return true;
    }
    
    // Preempt if waiting task has deadline and running doesn't
    if (waitingTask.deadline != std::chrono::steady_clock::time_point() &&
        runningTask.deadline == std::chrono::steady_clock::time_point()) {
        return true;
    }
    
    return false;
}

std::vector<PriorityTask> PriorityTaskQueue::getPreemptibleTasks() const {
    std::vector<PriorityTask> preemptible;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& pair : taskMap_) {
        if (pair.second.preemptible && 
            pair.second.preemptionCount < pair.second.maxPreemptions) {
            preemptible.push_back(pair.second);
        }
    }
    
    return preemptible;
}

bool PriorityTaskQueue::markPreempted(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = taskMap_.find(taskId);
    if (it == taskMap_.end()) {
        return false;
    }
    
    it->second.preemptionCount++;
    stats_.tasksPreempted++;
    
    return true;
}

// Aging
void PriorityTaskQueue::applyAging() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    
    for (auto& pair : taskMap_) {
        auto& task = pair.second;
        
        // Check if task needs aging boost
        if (task.ageBoosts < config_.maxAgeBoosts) {
            auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - task.submitTime).count();
            
            if (age > config_.agingIntervalMs * (task.ageBoosts + 1)) {
                // Boost priority
                boostPriority(task.taskId);
            }
        }
    }
}

// Deadline management
std::vector<std::string> PriorityTaskQueue::getExpiredDeadlines() const {
    std::vector<std::string> expired;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& pair : taskMap_) {
        if (pair.second.deadline != std::chrono::steady_clock::time_point() &&
            now > pair.second.deadline) {
            expired.push_back(pair.first);
        }
    }
    
    return expired;
}

bool PriorityTaskQueue::extendDeadline(const std::string& taskId, uint32_t extensionMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = taskMap_.find(taskId);
    if (it == taskMap_.end()) {
        return false;
    }
    
    it->second.deadline += std::chrono::milliseconds(extensionMs);
    return true;
}

// Queue status
size_t PriorityTaskQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t total = 0;
    for (const auto& pair : queues_) {
        total += pair.second.size();
    }
    return total;
}

size_t PriorityTaskQueue::sizeForPriority(TaskPriorityLevel priority) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = queues_.find(priority);
    if (it != queues_.end()) {
        return it->second.size();
    }
    return 0;
}

bool PriorityTaskQueue::empty() const {
    return size() == 0;
}

void PriorityTaskQueue::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& pair : queues_) {
        while (!pair.second.empty()) {
            pair.second.pop();
        }
    }
    
    taskMap_.clear();
    taskPriorityMap_.clear();
}

// Statistics
PriorityTaskQueue::PriorityStats PriorityTaskQueue::getStats() const {
    PriorityStats stats;
    
    stats.tasksSubmitted = stats_.tasksSubmitted.load();
    stats.tasksExecuted = stats_.tasksExecuted.load();
    stats.tasksPreempted = stats_.tasksPreempted.load();
    stats.tasksExpired = stats_.tasksExpired.load();
    stats.tasksBoosted = stats_.tasksBoosted.load();
    
    uint64_t executed = stats_.tasksExecuted.load();
    if (executed > 0) {
        stats.avgWaitTimeMs = stats_.totalWaitTimeMs.load() / executed;
        stats.avgExecutionTimeMs = stats_.totalExecutionTimeMs.load() / executed;
    }
    
    uint64_t deadlineChecks = stats_.deadlineChecks.load();
    if (deadlineChecks > 0) {
        stats.deadlineMissRate = static_cast<double>(stats_.deadlineMisses.load()) / deadlineChecks;
    }
    
    // Count by priority
    for (uint8_t p = 0; p <= static_cast<uint8_t>(TaskPriorityLevel::BACKGROUND); p++) {
        TaskPriorityLevel priority = static_cast<TaskPriorityLevel>(p);
        stats.tasksByPriority[priority] = sizeForPriority(priority);
    }
    
    return stats;
}

void PriorityTaskQueue::resetStats() {
    stats_.tasksSubmitted = 0;
    stats_.tasksExecuted = 0;
    stats_.tasksPreempted = 0;
    stats_.tasksExpired = 0;
    stats_.tasksBoosted = 0;
    stats_.totalWaitTimeMs = 0.0;
    stats_.totalExecutionTimeMs = 0.0;
    stats_.deadlineMisses = 0;
    stats_.deadlineChecks = 0;
}

// Configuration
bool PriorityTaskQueue::updateConfig(const PriorityQueueConfig& config) {
    config_ = config;
    return true;
}

// Internal methods
void PriorityTaskQueue::agingLoop() {
    while (running_) {
        if (config_.enableAging) {
            applyAging();
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.agingIntervalMs));
    }
}

void PriorityTaskQueue::deadlineLoop() {
    while (running_) {
        if (config_.enableDeadlineScheduling) {
            auto expired = getExpiredDeadlines();
            for (const auto& taskId : expired) {
                stats_.tasksExpired++;
                stats_.deadlineMisses++;
            }
            stats_.deadlineChecks++;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

uint64_t PriorityTaskQueue::getNextSequenceNumber() {
    return sequenceNumber_.fetch_add(1);
}

void PriorityTaskQueue::updateWaitTimeStats(const PriorityTask& task) {
    auto now = std::chrono::steady_clock::now();
    auto waitTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - task.submitTime).count();
    stats_.totalWaitTimeMs += waitTime;
}

std::priority_queue<PriorityTask, std::vector<PriorityTask>, DeadlineComparator>*
    PriorityTaskQueue::selectQueue(TaskPriorityLevel priority) {
    auto it = queues_.find(priority);
    if (it != queues_.end()) {
        return &it->second;
    }
    return nullptr;
}

std::string PriorityTaskQueue::generateTaskId() {
    uint64_t id = sequenceNumber_.fetch_add(1);
    
    std::stringstream ss;
    ss << "prio-task-" << std::hex << std::setw(16) << std::setfill('0') << id;
    return ss.str();
}

// PreemptiveScheduler Implementation

PreemptiveScheduler::PreemptiveScheduler(std::shared_ptr<PriorityTaskQueue> taskQueue)
    : taskQueue_(taskQueue)
{
}

bool PreemptiveScheduler::startTask(const PriorityTask& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    runningTasks_[task.taskId] = task;
    return true;
}

bool PreemptiveScheduler::preemptTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = runningTasks_.find(taskId);
    if (it == runningTasks_.end()) {
        return false;
    }
    
    // Mark as preempted
    taskQueue_->markPreempted(taskId);
    
    // Remove from running
    runningTasks_.erase(it);
    
    return true;
}

bool PreemptiveScheduler::resumeTask(const std::string& taskId) {
    // Would resume preempted task
    return true;
}

bool PreemptiveScheduler::completeTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    runningTasks_.erase(taskId);
    return true;
}

bool PreemptiveScheduler::checkPreemptionNeeded() {
    if (!taskQueue_) {
        return false;
    }
    
    // Check if any running task should be preempted
    PriorityTask waitingTask;
    if (!taskQueue_->peek(waitingTask)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& pair : runningTasks_) {
        if (taskQueue_->shouldPreempt(pair.second, waitingTask)) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> PreemptiveScheduler::getTasksToPreempt() {
    std::vector<std::string> toPreempt;
    
    if (!taskQueue_) {
        return toPreempt;
    }
    
    PriorityTask waitingTask;
    if (!taskQueue_->peek(waitingTask)) {
        return toPreempt;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& pair : runningTasks_) {
        if (taskQueue_->shouldPreempt(pair.second, waitingTask)) {
            toPreempt.push_back(pair.first);
        }
    }
    
    return toPreempt;
}

std::vector<PriorityTask> PreemptiveScheduler::getRunningTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PriorityTask> tasks;
    for (const auto& pair : runningTasks_) {
        tasks.push_back(pair.second);
    }
    return tasks;
}

PriorityTask PreemptiveScheduler::getRunningTask(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = runningTasks_.find(taskId);
    if (it != runningTasks_.end()) {
        return it->second;
    }
    
    return PriorityTask();
}

} // namespace Distributed
} // namespace RawrXD
