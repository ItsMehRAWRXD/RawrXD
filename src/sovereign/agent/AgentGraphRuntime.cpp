// AgentGraphRuntime.cpp
// DAG-based Task Scheduler for Multi-Agent Orchestration

#include "AgentGraphRuntime.hpp"
#include <algorithm>
#include <queue>

namespace Sovereign {

bool AgentGraphRuntime::AddAgent(std::shared_ptr<AgentNode> node) {
    if (!node) return false;
    
    std::lock_guard<std::mutex> lock(graphLock);
    
    const std::string& name = node->GetName();
    if (agents.find(name) != agents.end()) {
        return false; // Already exists
    }
    
    agents[name] = node;
    adjacencyList[name] = {};
    reverseAdjacency[name] = {};
    
    return true;
}

bool AgentGraphRuntime::Connect(const std::string& from, const std::string& to) {
    std::lock_guard<std::mutex> lock(graphLock);
    
    // Check both agents exist
    if (agents.find(from) == agents.end() || agents.find(to) == agents.end()) {
        return false;
    }
    
    // Check for self-loop
    if (from == to) {
        return false;
    }
    
    // Add edge
    adjacencyList[from].push_back(to);
    reverseAdjacency[to].push_back(from);
    
    // Check for cycles
    if (HasCycle()) {
        // Remove edge if it creates a cycle
        auto& edges = adjacencyList[from];
        edges.erase(std::remove(edges.begin(), edges.end(), to), edges.end());
        
        auto& revEdges = reverseAdjacency[to];
        revEdges.erase(std::remove(revEdges.begin(), revEdges.end(), from), revEdges.end());
        
        return false;
    }
    
    return true;
}

bool AgentGraphRuntime::Disconnect(const std::string& from, const std::string& to) {
    std::lock_guard<std::mutex> lock(graphLock);
    
    auto& edges = adjacencyList[from];
    auto it = std::find(edges.begin(), edges.end(), to);
    if (it == edges.end()) {
        return false;
    }
    edges.erase(it);
    
    auto& revEdges = reverseAdjacency[to];
    revEdges.erase(std::remove(revEdges.begin(), revEdges.end(), from), revEdges.end());
    
    return true;
}

std::vector<std::string> AgentGraphRuntime::TopologicalSort() const {
    std::lock_guard<std::mutex> lock(graphLock);
    
    // Kahn's algorithm
    std::unordered_map<std::string, int> inDegree;
    for (const auto& [name, node] : agents) {
        inDegree[name] = 0;
    }
    
    for (const auto& [from, toList] : adjacencyList) {
        for (const auto& to : toList) {
            inDegree[to]++;
        }
    }
    
    std::queue<std::string> q;
    for (const auto& [name, degree] : inDegree) {
        if (degree == 0) {
            q.push(name);
        }
    }
    
    std::vector<std::string> result;
    while (!q.empty()) {
        std::string current = q.front();
        q.pop();
        result.push_back(current);
        
        for (const auto& neighbor : adjacencyList.at(current)) {
            inDegree[neighbor]--;
            if (inDegree[neighbor] == 0) {
                q.push(neighbor);
            }
        }
    }
    
    return result;
}

bool AgentGraphRuntime::HasCycle() const {
    // DFS-based cycle detection
    std::unordered_map<std::string, int> state; // 0 = unvisited, 1 = visiting, 2 = visited
    for (const auto& [name, node] : agents) {
        state[name] = 0;
    }
    
    std::function<bool(const std::string&)> dfs = [&](const std::string& node) -> bool {
        state[node] = 1; // visiting
        
        for (const auto& neighbor : adjacencyList.at(node)) {
            if (state[neighbor] == 1) {
                return true; // cycle found
            }
            if (state[neighbor] == 0 && dfs(neighbor)) {
                return true;
            }
        }
        
        state[node] = 2; // visited
        return false;
    };
    
    for (const auto& [name, node] : agents) {
        if (state[name] == 0 && dfs(name)) {
            return true;
        }
    }
    
    return false;
}

void AgentGraphRuntime::Start() {
    if (running.exchange(true)) {
        return; // Already running
    }
    
    // Start worker threads
    for (size_t i = 0; i < threadCount; ++i) {
        workerPool.emplace_back(&AgentGraphRuntime::WorkerLoop, this);
    }
}

void AgentGraphRuntime::Shutdown() {
    if (!running.exchange(false)) {
        return; // Not running
    }
    
    // Wake up all workers
    queueCV.notify_all();
    
    // Join all threads
    for (auto& thread : workerPool) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    workerPool.clear();
}

void AgentGraphRuntime::WorkerLoop() {
    while (running.load()) {
        AgentTask task;
        
        {
            std::unique_lock<std::mutex> lock(queueLock);
            queueCV.wait(lock, [this] { return !taskQueue.empty() || !running.load(); });
            
            if (!running.load() && taskQueue.empty()) {
                return;
            }
            
            if (taskQueue.empty()) {
                continue;
            }
            
            task = taskQueue.front();
            taskQueue.pop();
        }
        
        ProcessTask(task);
    }
}

void AgentGraphRuntime::ProcessTask(const AgentTask& task) {
    auto agent = GetAgent(task.agentName);
    if (!agent) {
        AgentResult result;
        result.success = false;
        result.error = "Agent not found: " + task.agentName;
        
        std::lock_guard<std::mutex> lock(resultsLock);
        results[task.id] = result;
        return;
    }
    
    // Set agent state
    agent->state.store(AgentState::RUNNING);
    
    // Execute
    auto startTime = std::chrono::steady_clock::now();
    AgentResult result = agent->Execute(task);
    auto endTime = std::chrono::steady_clock::now();
    
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    // Update state
    agent->state.store(result.success ? AgentState::COMPLETED : AgentState::FAILED);
    
    // Store result
    {
        std::lock_guard<std::mutex> lock(resultsLock);
        results[task.id] = result;
    }
}

AgentResult AgentGraphRuntime::Execute(uint64_t sessionId, const AgentTask& initialTask) {
    if (!running.load()) {
        Start();
    }
    
    // Get execution order
    auto executionOrder = GetExecutionOrder();
    
    if (executionOrder.empty()) {
        AgentResult result;
        result.success = false;
        result.error = "No agents in graph";
        return result;
    }
    
    // Queue tasks in dependency order
    for (const auto& agentName : executionOrder) {
        AgentTask task = initialTask;
        task.agentName = agentName;
        task.id = sessionId; // Use session ID as task ID for simplicity
        
        {
            std::lock_guard<std::mutex> lock(queueLock);
            taskQueue.push(task);
        }
        queueCV.notify_one();
    }
    
    // Wait for all tasks to complete (simplified - in production use futures)
    // For now, return the result of the last agent
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    std::lock_guard<std::mutex> lock(resultsLock);
    auto it = results.find(std::to_string(sessionId));
    if (it != results.end()) {
        return it->second;
    }
    
    AgentResult result;
    result.success = true;
    result.output = "Execution queued";
    return result;
}

std::shared_ptr<AgentNode> AgentGraphRuntime::GetAgent(const std::string& name) const {
    std::lock_guard<std::mutex> lock(graphLock);
    auto it = agents.find(name);
    if (it != agents.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> AgentGraphRuntime::GetExecutionOrder() const {
    return TopologicalSort();
}

std::vector<std::string> AgentGraphRuntime::GetAgentNames() const {
    std::lock_guard<std::mutex> lock(graphLock);
    std::vector<std::string> names;
    names.reserve(agents.size());
    for (const auto& [name, agent] : agents) {
        names.push_back(name);
    }
    return names;
}

bool AgentGraphRuntime::SpawnSubAgent(const std::string& parentAgent, 
                                       std::shared_ptr<AgentNode> subAgent) {
    if (!subAgent) return false;
    
    // Add the sub-agent
    if (!AddAgent(subAgent)) {
        return false;
    }
    
    // Connect parent to sub-agent
    return Connect(parentAgent, subAgent->GetName());
}

bool AgentGraphRuntime::AreDependenciesMet(const std::string& agentName, uint64_t sessionId) {
    std::lock_guard<std::mutex> lock(graphLock);
    
    auto it = reverseAdjacency.find(agentName);
    if (it == reverseAdjacency.end() || it->second.empty()) {
        return true; // No dependencies
    }
    
    // Check if all parent agents completed successfully
    for (const auto& parent : it->second) {
        auto parentAgent = agents.find(parent);
        if (parentAgent == agents.end()) {
            return false;
        }
        
        AgentState state = parentAgent->second->GetState();
        if (state != AgentState::COMPLETED) {
            return false;
        }
    }
    
    return true;
}

} // namespace Sovereign
