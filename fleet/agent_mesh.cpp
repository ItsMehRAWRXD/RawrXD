#include "agent_mesh.hpp"
#include <algorithm>
#include <iostream>

namespace RawrXD::Fleet {

void AgentMesh::RegisterAgent(const std::string& node_id, const std::string& specialization) {
    std::lock_guard<std::mutex> lock(mutex_);
    AgentMeshNode node;
    node.node_id = node_id;
    node.specialization = specialization;
    node.status = "ready";
    agents_[node_id] = node;
}

void AgentMesh::UnregisterAgent(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    agents_.erase(node_id);
}

std::string AgentMesh::RouteTask(const std::string& specialization) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find agent with matching specialization and lowest load
    AgentMeshNode* best = nullptr;
    for (auto& [id, node] : agents_) {
        if (node.specialization == specialization && node.status == "ready") {
            if (!best || node.load_factor < best->load_factor) {
                best = &node;
            }
        }
    }
    
    if (best) {
        best->active_tasks++;
        best->load_factor = static_cast<double>(best->active_tasks) / 10.0;
        return best->node_id;
    }
    return "";
}

std::vector<AgentMeshNode> AgentMesh::GetAvailableAgents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AgentMeshNode> result;
    for (const auto& [id, node] : agents_) {
        if (node.status == "ready") result.push_back(node);
    }
    return result;
}

size_t AgentMesh::GetAgentCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return agents_.size();
}

} // namespace RawrXD::Fleet
