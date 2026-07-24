#pragma once

#include "CinematicVibeEngine.hpp"
#include "DeepContextManager.hpp"
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>
#include <string>
#include <map>
#include <set>
#include <chrono>

namespace rawrxd {
namespace swarm {

// Forward declarations
class Agent;
class AgentPool;
class Task;
class TaskResult;

// Agent types matching Kimi K2.6 architecture
enum class AgentType {
    ARCHITECT = 0,      // 1 agent - designs schema, stack, project tree
    FRONTEND = 1,       // 120 agents - UI/UX components, forms, styles, animations
    BACKEND = 2,        // 100 agents - server logic, APIs, payments, auth
    QA = 3,             // 50 agents - unit tests, load testing
    REVIEWER = 4,       // 29 agents - security, clean code, dependencies
    COUNT = 5
};

// Agent configuration
struct AgentConfig {
    AgentType type;
    std::string name;
    std::string specialization;
    size_t id;
    bool active{true};
    std::chrono::milliseconds timeout{std::chrono::seconds(30)};
};

// Task priority for swarm scheduling
enum class TaskPriority {
    CRITICAL = 0,       // Architect tasks
    HIGH = 1,           // Backend API dependencies
    NORMAL = 2,         // Frontend components
    LOW = 3,            // QA tests (can run in parallel)
    BACKGROUND = 4      // Review tasks
};

// Task definition for swarm execution
struct Task {
    uint64_t id;
    AgentType agentType;
    TaskPriority priority;
    std::string description;
    std::string context;           // 256K context window reference
    std::function<std::string(const std::string&)> work;
    std::chrono::steady_clock::time_point created;
    std::chrono::milliseconds maxDuration{std::chrono::minutes(5)};
    
    // For dependency graph
    std::vector<uint64_t> dependencies;
    std::atomic<size_t> pendingDependencies{0};
    
    bool operator<(const Task& other) const {
        return static_cast<int>(priority) > static_cast<int>(other.priority);
    }
    
    // Copy/move constructors (required due to atomic member)
    Task() = default;
    Task(const Task& other);
    Task(Task&& other) noexcept;
    Task& operator=(const Task& other);
    Task& operator=(Task&& other) noexcept;
};

// Task result with metadata
struct TaskResult {
    uint64_t taskId;
    bool success;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    AgentType completedBy;
    size_t agentId;
    std::chrono::steady_clock::time_point completed;
};

// Individual agent in the swarm
class Agent {
public:
    Agent(const AgentConfig& config);
    ~Agent();
    
    void start();
    void stop();
    bool isActive() const { return active_.load(); }
    
    TaskResult execute(const Task& task);
    const AgentConfig& getConfig() const { return config_; }
    
    // Metrics
    size_t getTasksCompleted() const { return tasksCompleted_.load(); }
    std::chrono::milliseconds getAverageTaskTime() const;
    
private:
    void workerLoop();
    
    AgentConfig config_;
    std::atomic<bool> active_{false};
    std::atomic<bool> stopRequested_{false};
    std::thread workerThread_;
    
    // Metrics
    std::atomic<size_t> tasksCompleted_{0};
    std::atomic<uint64_t> totalTaskTimeMs_{0};
};

// Pool of agents for a specific type
class AgentPool {
public:
    AgentPool(AgentType type, size_t count);
    ~AgentPool();
    
    void start();
    void stop();
    
    std::shared_ptr<Agent> acquireAgent();
    void releaseAgent(std::shared_ptr<Agent> agent);
    
    size_t getActiveCount() const;
    size_t getTotalCount() const { return agents_.size(); }
    
private:
    AgentType type_;
    std::vector<std::shared_ptr<Agent>> agents_;
    std::queue<std::shared_ptr<Agent>> available_;
    std::mutex mutex_;
    std::condition_variable cv_;
};

// The Hive - Main orchestrator managing 300 agents
class SwarmOrchestrator {
public:
    static SwarmOrchestrator& getInstance();
    
    // Initialize with Kimi K2.6 defaults: 1+120+100+50+29 = 300 agents
    void initialize(
        size_t architects = 1,
        size_t frontend = 120,
        size_t backend = 100,
        size_t qa = 50,
        size_t reviewers = 29
    );
    
    // Micro-swarm mode for 8GB RAM (50-70 agents)
    void initializeMicroSwarm();
    
    void shutdown();
    bool isRunning() const { return running_.load(); }
    
    // Task submission
    uint64_t submitTask(const Task& task);
    std::future<TaskResult> submitTaskAsync(const Task& task);
    
    // Batch submission for parallel execution
    std::vector<std::future<TaskResult>> submitBatch(
        const std::vector<Task>& tasks
    );
    
    // Wait for completion
    void waitForCompletion(uint64_t taskId);
    void waitForAll();
    
    // Results
    TaskResult getResult(uint64_t taskId);
    bool hasResult(uint64_t taskId) const;
    
    // Dependency graph
    void addDependency(uint64_t taskId, uint64_t dependsOn);
    
    // Metrics
    struct SwarmMetrics {
        size_t totalAgents;
        size_t activeAgents;
        size_t pendingTasks;
        size_t completedTasks;
        size_t failedTasks;
        std::chrono::milliseconds averageTaskTime;
        double tasksPerSecond;
    };
    SwarmMetrics getMetrics() const;
    
    // Agent pool access
    AgentPool* getPool(AgentType type);
    
private:
    SwarmOrchestrator() = default;
    ~SwarmOrchestrator() = default;
    SwarmOrchestrator(const SwarmOrchestrator&) = delete;
    SwarmOrchestrator& operator=(const SwarmOrchestrator&) = delete;
    
    void schedulerLoop();
    void dependencyLoop();
    
    std::map<AgentType, std::unique_ptr<AgentPool>> pools_;
    
    // Task queues per priority
    std::priority_queue<Task> taskQueue_;
    std::mutex taskMutex_;
    std::condition_variable taskCv_;
    
    // Dependency tracking
    std::map<uint64_t, Task> pendingTasks_;
    std::map<uint64_t, std::vector<uint64_t>> dependents_;
    std::mutex dependencyMutex_;
    
    // Results
    std::map<uint64_t, TaskResult> results_;
    mutable std::mutex resultsMutex_;
    
    // Control
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> nextTaskId_{1};
    std::thread schedulerThread_;
    std::thread dependencyThread_;
    
    // Metrics
    std::atomic<size_t> completedTasks_{0};
    std::atomic<size_t> failedTasks_{0};
    std::atomic<uint64_t> totalTaskTimeMs_{0};
    std::chrono::steady_clock::time_point startTime_;
};

// Safe Execution Sandbox
class SafeExecutionSandbox {
public:
    struct ExecutionConfig {
        bool allowNetwork{false};
        bool allowFileSystem{false};
        size_t maxMemoryMB{512};
        std::chrono::seconds timeout{30};
        std::vector<std::string> allowedSyscalls;
    };
    
    bool validateCode(const std::string& code);
    std::pair<bool, std::string> execute(const std::string& code, const ExecutionConfig& config);
    
private:
    std::vector<std::string> dangerousPatterns_ = {
        "system(", "exec(", "eval(", "__import__('os').system",
        "subprocess.call", "os.popen", "ctypes.CDLL",
        "Runtime.getRuntime().exec", "ProcessBuilder"
    };
};

} // namespace swarm
} // namespace rawrxd
