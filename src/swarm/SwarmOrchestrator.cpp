#include "SwarmOrchestrator.hpp"
#include "CinematicVibeEngine.hpp"
#include "DeepContextManager.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace rawrxd {
namespace swarm {

// ============================================================================
// Task Implementation
// ============================================================================

Task::Task(const Task& other)
    : id(other.id),
      agentType(other.agentType),
      priority(other.priority),
      description(other.description),
      context(other.context),
      work(other.work),
      created(other.created),
      maxDuration(other.maxDuration),
      dependencies(other.dependencies),
      pendingDependencies(other.pendingDependencies.load()) {}

Task::Task(Task&& other) noexcept
    : id(other.id),
      agentType(other.agentType),
      priority(other.priority),
      description(std::move(other.description)),
      context(std::move(other.context)),
      work(std::move(other.work)),
      created(other.created),
      maxDuration(other.maxDuration),
      dependencies(std::move(other.dependencies)),
      pendingDependencies(other.pendingDependencies.load()) {}

Task& Task::operator=(const Task& other) {
    if (this != &other) {
        id = other.id;
        agentType = other.agentType;
        priority = other.priority;
        description = other.description;
        context = other.context;
        work = other.work;
        created = other.created;
        maxDuration = other.maxDuration;
        dependencies = other.dependencies;
        pendingDependencies.store(other.pendingDependencies.load());
    }
    return *this;
}

Task& Task::operator=(Task&& other) noexcept {
    if (this != &other) {
        id = other.id;
        agentType = other.agentType;
        priority = other.priority;
        description = std::move(other.description);
        context = std::move(other.context);
        work = std::move(other.work);
        created = other.created;
        maxDuration = other.maxDuration;
        dependencies = std::move(other.dependencies);
        pendingDependencies.store(other.pendingDependencies.load());
    }
    return *this;
}

Agent::Agent(const AgentConfig& config) : config_(config) {}

Agent::~Agent() {
    stop();
}

void Agent::start() {
    if (active_.exchange(true)) return;
    stopRequested_ = false;
    workerThread_ = std::thread(&Agent::workerLoop, this);
}

void Agent::stop() {
    if (!active_.exchange(false)) return;
    stopRequested_ = true;
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
}

void Agent::workerLoop() {
    // Agent worker loop - processes tasks from the orchestrator
    while (!stopRequested_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

TaskResult Agent::execute(const Task& task) {
    auto start = std::chrono::steady_clock::now();
    TaskResult result;
    result.taskId = task.id;
    result.completedBy = config_.type;
    result.agentId = config_.id;
    
    try {
        if (task.work) {
            result.output = task.work(task.context);
            result.success = true;
        } else {
            result.success = false;
            result.error = "No work function provided";
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.error = e.what();
    }
    
    auto end = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    result.completed = end;
    
    tasksCompleted_++;
    totalTaskTimeMs_ += result.duration.count();
    
    return result;
}

std::chrono::milliseconds Agent::getAverageTaskTime() const {
    size_t completed = tasksCompleted_.load();
    if (completed == 0) return std::chrono::milliseconds(0);
    return std::chrono::milliseconds(totalTaskTimeMs_.load() / completed);
}

// Forward declaration
std::string getAgentTypeName(AgentType type);

// ============================================================================
// AgentPool Implementation
// ============================================================================

AgentPool::AgentPool(AgentType type, size_t count) : type_(type) {
    for (size_t i = 0; i < count; ++i) {
        AgentConfig config;
        config.type = type;
        config.id = i;
        config.name = getAgentTypeName(type) + "_" + std::to_string(i);
        
        auto agent = std::make_shared<Agent>(config);
        agents_.push_back(agent);
        available_.push(agent);
    }
}

AgentPool::~AgentPool() {
    stop();
}

void AgentPool::start() {
    for (auto& agent : agents_) {
        agent->start();
    }
}

void AgentPool::stop() {
    for (auto& agent : agents_) {
        agent->stop();
    }
}

std::shared_ptr<Agent> AgentPool::acquireAgent() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return !available_.empty(); });
    
    auto agent = available_.front();
    available_.pop();
    return agent;
}

void AgentPool::releaseAgent(std::shared_ptr<Agent> agent) {
    std::lock_guard<std::mutex> lock(mutex_);
    available_.push(agent);
    cv_.notify_one();
}

size_t AgentPool::getActiveCount() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
    return agents_.size() - available_.size();
}

// ============================================================================
// SwarmOrchestrator Implementation
// ============================================================================

SwarmOrchestrator& SwarmOrchestrator::getInstance() {
    static SwarmOrchestrator instance;
    return instance;
}

void SwarmOrchestrator::initialize(
    size_t architects,
    size_t frontend,
    size_t backend,
    size_t qa,
    size_t reviewers
) {
    if (running_.exchange(true)) return;
    
    pools_[AgentType::ARCHITECT] = std::make_unique<AgentPool>(AgentType::ARCHITECT, architects);
    pools_[AgentType::FRONTEND] = std::make_unique<AgentPool>(AgentType::FRONTEND, frontend);
    pools_[AgentType::BACKEND] = std::make_unique<AgentPool>(AgentType::BACKEND, backend);
    pools_[AgentType::QA] = std::make_unique<AgentPool>(AgentType::QA, qa);
    pools_[AgentType::REVIEWER] = std::make_unique<AgentPool>(AgentType::REVIEWER, reviewers);
    
    for (auto& [type, pool] : pools_) {
        pool->start();
    }
    
    startTime_ = std::chrono::steady_clock::now();
    schedulerThread_ = std::thread(&SwarmOrchestrator::schedulerLoop, this);
    dependencyThread_ = std::thread(&SwarmOrchestrator::dependencyLoop, this);
}

void SwarmOrchestrator::initializeMicroSwarm() {
    // Micro-swarm for 8GB RAM: 50-70 agents
    // Distribution: 1 architect, 20 frontend, 20 backend, 15 QA, 10 reviewers = 66 agents
    initialize(1, 20, 20, 15, 10);
}

void SwarmOrchestrator::shutdown() {
    if (!running_.exchange(false)) return;
    
    taskCv_.notify_all();
    
    if (schedulerThread_.joinable()) schedulerThread_.join();
    if (dependencyThread_.joinable()) dependencyThread_.join();
    
    for (auto& [type, pool] : pools_) {
        if (pool) pool->stop();
    }
}

uint64_t SwarmOrchestrator::submitTask(const Task& task) {
    uint64_t id = nextTaskId_++;
    
    Task mutableTask = task;
    mutableTask.id = id;
    mutableTask.created = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(taskMutex_);
        taskQueue_.push(mutableTask);
    }
    
    taskCv_.notify_one();
    return id;
}

std::future<TaskResult> SwarmOrchestrator::submitTaskAsync(const Task& task) {
    auto promise = std::make_shared<std::promise<TaskResult>>();
    auto future = promise->get_future();
    
    uint64_t taskId = submitTask(task);
    
    // Launch watcher thread to fulfill promise when result is ready
    std::thread([this, taskId, promise]() {
        while (running_.load() && !hasResult(taskId)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (hasResult(taskId)) {
            promise->set_value(getResult(taskId));
        } else {
            TaskResult failed;
            failed.taskId = taskId;
            failed.success = false;
            failed.error = "Orchestrator shutdown before completion";
            promise->set_value(failed);
        }
    }).detach();
    
    return future;
}

std::vector<std::future<TaskResult>> SwarmOrchestrator::submitBatch(
    const std::vector<Task>& tasks
) {
    std::vector<std::future<TaskResult>> futures;
    futures.reserve(tasks.size());
    
    for (const auto& task : tasks) {
        futures.push_back(submitTaskAsync(task));
    }
    
    return futures;
}

void SwarmOrchestrator::waitForCompletion(uint64_t taskId) {
    while (running_.load() && !hasResult(taskId)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void SwarmOrchestrator::waitForAll() {
    while (running_.load()) {
        {
            std::lock_guard<std::mutex> lock(taskMutex_);
            if (taskQueue_.empty()) {
                std::lock_guard<std::mutex> depLock(dependencyMutex_);
                if (pendingTasks_.empty()) break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

TaskResult SwarmOrchestrator::getResult(uint64_t taskId) {
    std::lock_guard<std::mutex> lock(resultsMutex_);
    auto it = results_.find(taskId);
    if (it != results_.end()) {
        return it->second;
    }
    TaskResult empty;
    empty.taskId = taskId;
    empty.success = false;
    empty.error = "Result not found";
    return empty;
}

bool SwarmOrchestrator::hasResult(uint64_t taskId) const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(resultsMutex_));
    return results_.find(taskId) != results_.end();
}

void SwarmOrchestrator::addDependency(uint64_t taskId, uint64_t dependsOn) {
    std::lock_guard<std::mutex> lock(dependencyMutex_);
    dependents_[dependsOn].push_back(taskId);
    
    auto it = pendingTasks_.find(taskId);
    if (it != pendingTasks_.end()) {
        it->second.pendingDependencies++;
    }
}

SwarmOrchestrator::SwarmMetrics SwarmOrchestrator::getMetrics() const {
    SwarmMetrics metrics;
    
    for (const auto& [type, pool] : pools_) {
        if (pool) {
            metrics.totalAgents += pool->getTotalCount();
            metrics.activeAgents += pool->getActiveCount();
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(taskMutex_));
        metrics.pendingTasks = taskQueue_.size();
    }
    
    metrics.completedTasks = completedTasks_.load();
    metrics.failedTasks = failedTasks_.load();
    
    size_t totalCompleted = completedTasks_.load() + failedTasks_.load();
    if (totalCompleted > 0) {
        metrics.averageTaskTime = std::chrono::milliseconds(
            totalTaskTimeMs_.load() / totalCompleted
        );
    }
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime_).count();
    if (elapsed > 0) {
        metrics.tasksPerSecond = static_cast<double>(totalCompleted) / elapsed;
    }
    
    return metrics;
}

AgentPool* SwarmOrchestrator::getPool(AgentType type) {
    auto it = pools_.find(type);
    if (it != pools_.end()) {
        return it->second.get();
    }
    return nullptr;
}

void SwarmOrchestrator::schedulerLoop() {
    while (running_.load()) {
        Task task;
        
        {
            std::unique_lock<std::mutex> lock(taskMutex_);
            taskCv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
                return !taskQueue_.empty() || !running_.load();
            });
            
            if (!running_.load()) break;
            if (taskQueue_.empty()) continue;
            
            task = taskQueue_.top();
            taskQueue_.pop();
        }
        
        // Check dependencies
        if (task.pendingDependencies.load() > 0) {
            std::lock_guard<std::mutex> lock(dependencyMutex_);
            pendingTasks_[task.id] = task;
            continue;
        }
        
        // Execute task
        auto pool = getPool(task.agentType);
        if (pool) {
            auto agent = pool->acquireAgent();
            auto result = agent->execute(task);
            pool->releaseAgent(agent);
            
            {
                std::lock_guard<std::mutex> lock(resultsMutex_);
                results_[task.id] = result;
            }
            
            if (result.success) {
                completedTasks_++;
            } else {
                failedTasks_++;
            }
            totalTaskTimeMs_ += result.duration.count();
            
            // Notify dependents
            {
                std::lock_guard<std::mutex> lock(dependencyMutex_);
                auto it = dependents_.find(task.id);
                if (it != dependents_.end()) {
                    for (uint64_t depId : it->second) {
                        auto depIt = pendingTasks_.find(depId);
                        if (depIt != pendingTasks_.end()) {
                            if (--depIt->second.pendingDependencies == 0) {
                                Task readyTask = depIt->second;
                                pendingTasks_.erase(depIt);
                                {
                                    std::lock_guard<std::mutex> qLock(taskMutex_);
                                    taskQueue_.push(readyTask);
                                }
                                taskCv_.notify_one();
                            }
                        }
                    }
                    dependents_.erase(it);
                }
            }
        }
    }
}

void SwarmOrchestrator::dependencyLoop() {
    // Periodic cleanup and dependency timeout handling
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        auto now = std::chrono::steady_clock::now();
        std::vector<uint64_t> timedOut;
        
        {
            std::lock_guard<std::mutex> lock(dependencyMutex_);
            for (auto it = pendingTasks_.begin(); it != pendingTasks_.end();) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - it->second.created
                );
                if (elapsed > it->second.maxDuration) {
                    timedOut.push_back(it->first);
                    it = pendingTasks_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        
        // Mark timed out tasks as failed
        for (uint64_t taskId : timedOut) {
            TaskResult failed;
            failed.taskId = taskId;
            failed.success = false;
            failed.error = "Task timed out waiting for dependencies";
            
            std::lock_guard<std::mutex> lock(resultsMutex_);
            results_[taskId] = failed;
            failedTasks_++;
        }
    }
}

// Helper function
std::string getAgentTypeName(AgentType type) {
    switch (type) {
        case AgentType::ARCHITECT: return "Architect";
        case AgentType::FRONTEND: return "Frontend";
        case AgentType::BACKEND: return "Backend";
        case AgentType::QA: return "QA";
        case AgentType::REVIEWER: return "Reviewer";
        default: return "Unknown";
    }
}

} // namespace swarm
} // namespace rawrxd
