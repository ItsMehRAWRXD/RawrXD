#include "agent_coordinator.hpp"
#include <iostream>
#include <algorithm>

AgentCoordinator::AgentCoordinator(void* parent)
    : m_parent(parent)
{
}

AgentCoordinator::~AgentCoordinator() = default;

void AgentCoordinator::registerAgent(const AgentMetadata& agent) {
    m_agents.push_back(agent);
}

void AgentCoordinator::unregisterAgent(const std::string& agentId) {
    m_agents.erase(
        std::remove_if(m_agents.begin(), m_agents.end(),
            [&agentId](const AgentMetadata& a) { return a.agentId == agentId; }),
        m_agents.end()
    );
}

std::string AgentCoordinator::submitTask(const AgentTask& task) {
    m_tasks.push_back(task);
    return task.id;
}

bool AgentCoordinator::cancelTask(const std::string& taskId) {
    auto it = std::find_if(m_tasks.begin(), m_tasks.end(),
        [&taskId](const AgentTask& t) { return t.id == taskId; });
    if (it != m_tasks.end()) {
        m_tasks.erase(it);
        return true;
    }
    return false;
}

AgentCoordinator::AgentTaskState AgentCoordinator::getTaskState(const std::string& taskId) const {
    (void)taskId;
    return AgentTaskState::Pending;
}

std::vector<AgentCoordinator::AgentTask> AgentCoordinator::getActiveTasks() const {
    return m_tasks;
}

void AgentCoordinator::executeReadyTasks() {
    // Stub
}
