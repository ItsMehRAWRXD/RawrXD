#include "social/AgentCollaboration.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_registeredAgents;
static std::map<std::string, nlohmann::json> s_tasks;

void AgentCollaboration::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_registeredAgents.clear();
        s_tasks.clear();
        s_initialized = true;
    }
}

void AgentCollaboration::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Process pending collaborations
    for (auto& [taskId, task] : s_tasks) {
        if (task.value("status", "") == "proposed") {
            // Auto-accept if no conflicts
            if (!task.value("conflict", false)) {
                task["status"] = "accepted";
                task["accepted_at"] = std::chrono::system_clock::now().time_since_epoch().count();
            }
        }
    }
}

bool AgentCollaboration::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void AgentCollaboration::RegisterAgent(const std::string& agentId, const nlohmann::json& capabilities) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_registeredAgents[agentId] = {
        {"id", agentId},
        {"capabilities", capabilities},
        {"registered_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"status", "active"}
    };
}

void AgentCollaboration::UnregisterAgent(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_registeredAgents.find(agentId);
    if (it != s_registeredAgents.end()) {
        it->second["status"] = "inactive";
        it->second["unregistered_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

nlohmann::json AgentCollaboration::GetRegisteredAgents() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, agent] : s_registeredAgents) {
        if (agent.value("status", "") == "active") {
            result.push_back(agent);
        }
    }
    return result;
}

void AgentCollaboration::ProposeTask(const std::string& taskId, const nlohmann::json& task) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_tasks[taskId] = {
        {"id", taskId},
        {"task", task},
        {"status", "proposed"},
        {"proposed_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"assigned_to", nullptr}
    };
}

void AgentCollaboration::AcceptTask(const std::string& taskId, const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_tasks.find(taskId);
    if (it != s_tasks.end()) {
        it->second["status"] = "accepted";
        it->second["assigned_to"] = agentId;
        it->second["accepted_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

void AgentCollaboration::CompleteTask(const std::string& taskId, const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_tasks.find(taskId);
    if (it != s_tasks.end()) {
        it->second["status"] = "completed";
        it->second["completed_by"] = agentId;
        it->second["completed_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

nlohmann::json AgentCollaboration::GetTaskStatus(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_tasks.find(taskId);
    if (it != s_tasks.end()) {
        return it->second;
    }
    return nlohmann::json{};
}

nlohmann::json AgentCollaboration::GetAllTasks() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, task] : s_tasks) {
        result.push_back(task);
    }
    return result;
}

nlohmann::json AgentCollaboration::GetCollaborationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t activeAgents = 0;
    for (const auto& [id, agent] : s_registeredAgents) {
        if (agent.value("status", "") == "active") {
            activeAgents++;
        }
    }
    
    size_t proposed = 0, accepted = 0, completed = 0;
    for (const auto& [id, task] : s_tasks) {
        std::string status = task.value("status", "");
        if (status == "proposed") proposed++;
        else if (status == "accepted") accepted++;
        else if (status == "completed") completed++;
    }
    
    return {
        {"active_agents", activeAgents},
        {"total_agents", s_registeredAgents.size()},
        {"tasks_proposed", proposed},
        {"tasks_accepted", accepted},
        {"tasks_completed", completed},
        {"collaboration_rate", activeAgents > 0 ? (completed / static_cast<double>(s_tasks.size())) : 0.0}
    };
}
