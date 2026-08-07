#pragma once
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <functional>

namespace RawrXD::Fleet {

struct AgentMeshNode {
    std::string node_id;
    std::string specialization;
    std::string status;
    size_t active_tasks = 0;
    double load_factor = 0.0;
};

class AgentMesh {
public:
    AgentMesh() = default;
    ~AgentMesh() = default;

    void RegisterAgent(const std::string& node_id, const std::string& specialization);
    void UnregisterAgent(const std::string& node_id);
    std::string RouteTask(const std::string& specialization);
    std::vector<AgentMeshNode> GetAvailableAgents() const;
    size_t GetAgentCount() const;

private:
    std::map<std::string, AgentMeshNode> agents_;
    mutable std::mutex mutex_;
};

} // namespace RawrXD::Fleet
