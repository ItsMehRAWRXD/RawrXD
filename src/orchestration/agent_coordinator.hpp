#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <functional>

class AgentCoordinator {

public:
    explicit AgentCoordinator(void* parent = nullptr);
    ~AgentCoordinator();

    struct AgentTask {
        std::string id;
        std::string name;
        std::string agentId;
        std::vector<std::string> dependencies;
        void* payload;
        int priority = 0;
        int maxRetries = 0;
    };

    enum class AgentTaskState {
        Pending,
        Ready,
        Running,
        Completed,
        Failed,
        Skipped,
        Cancelled
    };

    struct AgentMetadata {
        std::string agentId;
        std::vector<std::string> capabilities;
        int maxConcurrency = 1;
        int activeAssignments = 0;
        bool available = true;
        std::chrono::system_clock::time_point registeredAt;
    };

    void registerAgent(const AgentMetadata& agent);
    void unregisterAgent(const std::string& agentId);
    std::string submitTask(const AgentTask& task);
    bool cancelTask(const std::string& taskId);
    AgentTaskState getTaskState(const std::string& taskId) const;
    std::vector<AgentTask> getActiveTasks() const;
    void executeReadyTasks();

private:
    void* m_parent;
    std::vector<AgentMetadata> m_agents;
    std::vector<AgentTask> m_tasks;
};

#endif
