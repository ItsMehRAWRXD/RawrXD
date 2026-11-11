// AgentGraphRuntime.hpp
// DAG-based Task Scheduler for Multi-Agent Orchestration
// Feature #1: AgentGraphRuntime - The "Brain" Orchestrator

#ifndef AGENTGRAPHRUNTIME_HPP
#define AGENTGRAPHRUNTIME_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <future>
#include <condition_variable>

namespace Sovereign {

// Forward declarations
class AgentNode;
class AgentGraphRuntime;

/**
 * @enum AgentState
 * @brief Execution states for agent nodes
 */
enum class AgentState {
    IDLE,           // Waiting for activation
    RUNNING,        // Currently executing
    COMPLETED,      // Finished successfully
    FAILED,         // Execution failed
    BLOCKED         // Waiting for dependencies
};

/**
 * @enum AgentMode
 * @brief Different reasoning policies for agents
 */
enum class AgentMode {
    ASK,            // Read-only query
    PLAN,           // Generate structured plans
    EDIT,           // Apply bounded diffs
    AGENT           // Full autonomous execution
};

/**
 * @struct AgentCapability
 * @brief Describes what an agent can do
 */
struct AgentCapability {
    std::string name;
    std::string description;
    std::vector<std::string> tools;
    AgentMode mode;
    size_t maxCycles = 10;
    bool requireHumanApproval = false;
};

/**
 * @struct AgentTask
 * @brief Unit of work in the agent graph
 */
struct AgentTask {
    std::string id;
    std::string agentName;
    std::string objective;
    std::vector<std::string> dependencies;
    std::unordered_map<std::string, std::string> context;
    uint64_t sessionId = 0;
    uint64_t timestamp = 0;
};

/**
 * @struct AgentResult
 * @brief Output from agent execution
 */
struct AgentResult {
    bool success;
    std::string output;
    std::string error;
    uint64_t executionTimeMs = 0;
    std::vector<std::string> artifacts;
};

/**
 * @class AgentNode
 * @brief Individual agent in the orchestration graph
 */
class AgentNode {
    friend class AgentGraphRuntime;
    
    std::string name;
    AgentCapability capability;
    std::vector<std::string> inputs;   // Incoming edges
    std::vector<std::string> outputs;  // Outgoing edges
    std::atomic<AgentState> state{AgentState::IDLE};
    std::function<AgentResult(const AgentTask&)> executor;
    
public:
    AgentNode(const std::string& nodeName, const AgentCapability& cap)
        : name(nodeName), capability(cap) {}
    
    const std::string& GetName() const { return name; }
    AgentState GetState() const { return state.load(); }
    const AgentCapability& GetCapability() const { return capability; }
    
    void SetExecutor(std::function<AgentResult(const AgentTask&)> exec) {
        executor = exec;
    }
    
    AgentResult Execute(const AgentTask& task) {
        if (executor) {
            return executor(task);
        }
        return {false, "", "NO_EXECUTOR", 0, {}};
    }
};

/**
 * @class AgentGraphRuntime
 * @brief DAG-based task scheduler for multi-agent orchestration
 * 
 * Usage:
 *   AgentGraphRuntime runtime;
 *   
 *   // Create agents
 *   runtime.AddAgent({"Planner", "Generates execution plans", {}, AgentMode::PLAN});
 *   runtime.AddAgent({"Coder", "Writes code", {"read_file", "write_file"}, AgentMode::AGENT});
 *   runtime.AddAgent({"Reviewer", "Reviews code", {"read_file", "static_analysis"}, AgentMode::ASK});
 *   
 *   // Connect them
 *   runtime.Connect("Planner", "Coder");
 *   runtime.Connect("Coder", "Reviewer");
 *   
 *   // Execute
 *   runtime.Execute(sessionId);
 */
class AgentGraphRuntime {
    mutable std::mutex graphLock;
    std::unordered_map<std::string, std::shared_ptr<AgentNode>> agents;
    std::unordered_map<std::string, std::vector<std::string>> adjacencyList;
    std::unordered_map<std::string, std::vector<std::string>> reverseAdjacency;
    
    // Thread pool for execution
    std::vector<std::thread> workerPool;
    std::queue<AgentTask> taskQueue;
    std::mutex queueLock;
    std::condition_variable queueCV;
    std::atomic<bool> running{false};
    size_t threadCount = 4;
    
    // Execution tracking
    std::unordered_map<std::string, AgentResult> results;
    std::mutex resultsLock;
    
public:
    AgentGraphRuntime(size_t threads = 4) : threadCount(threads) {}
    ~AgentGraphRuntime() { Shutdown(); }
    
    /**
     * @brief Add an agent to the graph
     * @param node Agent node to add
     * @return true if added successfully
     */
    bool AddAgent(std::shared_ptr<AgentNode> node);
    
    /**
     * @brief Connect two agents (directed edge: from -> to)
     * @param from Source agent name
     * @param to Target agent name
     * @return true if connection established
     */
    bool Connect(const std::string& from, const std::string& to);
    
    /**
     * @brief Remove a connection between agents
     * @param from Source agent name
     * @param to Target agent name
     * @return true if connection removed
     */
    bool Disconnect(const std::string& from, const std::string& to);
    
    /**
     * @brief Execute the agent graph for a session
     * @param sessionId Session identifier
     * @param initialTask Starting task
     * @return Final execution result
     */
    AgentResult Execute(uint64_t sessionId, const AgentTask& initialTask);
    
    /**
     * @brief Start the runtime worker threads
     */
    void Start();
    
    /**
     * @brief Shutdown the runtime
     */
    void Shutdown();
    
    /**
     * @brief Get agent by name
     * @param name Agent name
     * @return Shared pointer to agent, or nullptr
     */
    std::shared_ptr<AgentNode> GetAgent(const std::string& name) const;
    
    /**
     * @brief Get execution order (topological sort)
     * @return Vector of agent names in execution order
     */
    std::vector<std::string> GetExecutionOrder() const;
    
    /**
     * @brief Check if graph has cycles
     * @return true if cycle detected
     */
    bool HasCycle() const;
    
    /**
     * @brief Get all registered agent names
     * @return Vector of agent names
     */
    std::vector<std::string> GetAgentNames() const;
    
    /**
     * @brief Spawn a sub-agent at runtime
     * @param parentAgent Name of parent agent
     * @param subAgent Sub-agent to spawn
     * @return true if spawned successfully
     */
    bool SpawnSubAgent(const std::string& parentAgent, std::shared_ptr<AgentNode> subAgent);
    
private:
    void WorkerLoop();
    bool AreDependenciesMet(const std::string& agentName, uint64_t sessionId);
    void ProcessTask(const AgentTask& task);
    std::vector<std::string> TopologicalSort() const;
};

} // namespace Sovereign

#endif // AGENTGRAPHRUNTIME_HPP
