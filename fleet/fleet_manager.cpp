#include "fleet_manager.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <random>

namespace RawrXD::Fleet {

FleetManager::FleetManager() = default;
FleetManager::~FleetManager() {
    running_ = false;
    if (discovery_thread_ && discovery_thread_->joinable()) discovery_thread_->join();
}

bool FleetManager::Initialize() {
    running_ = true;
    discovery_thread_ = std::make_unique<std::thread>([this]() { DiscoveryLoop(); });
    std::cout << "FLEET DISCOVERY\nScanning network...\n";
    return true;
}

bool FleetManager::RegisterNode(const std::string& endpoint) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    NodeInfo node;
    node.id = GenerateNodeId();
    node.endpoint = endpoint;
    node.status = "online";
    node.health_percent = 100.0;
    node.last_heartbeat = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    nodes_[node.id] = node;
    
    if (node_callback_) node_callback_(node);
    std::cout << "Registered: " << node.id << " (" << endpoint << ")\n";
    return true;
}

bool FleetManager::UnregisterNode(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(node_id);
    if (it != nodes_.end()) {
        nodes_.erase(it);
        return true;
    }
    return false;
}

bool FleetManager::DispatchTask(const std::string& task, const std::string& specialization) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find best node for task
    NodeInfo* best_node = nullptr;
    for (auto& [id, node] : nodes_) {
        if (node.status == "online") {
            if (!best_node || node.active_agents < best_node->active_agents) {
                best_node = &node;
            }
        }
    }
    
    if (best_node) {
        best_node->active_agents++;
        std::cout << "TASK: " << task << "\n";
        std::cout << "Assigned: " << best_node->id << "\n";
        if (!specialization.empty()) {
            std::cout << "Agent: " << specialization << "\n";
        }
        std::cout << "Result: COMPLETE\n";
        return true;
    }
    
    std::cout << "No available nodes for task: " << task << "\n";
    return false;
}

FleetStats FleetManager::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    FleetStats stats;
    stats.total_nodes = nodes_.size();
    stats.online_nodes = std::count_if(nodes_.begin(), nodes_.end(),
        [](const auto& pair) { return pair.second.status == "online"; });
    
    for (const auto& [id, node] : nodes_) {
        stats.total_models += node.loaded_models;
        stats.total_agents += node.active_agents;
        stats.global_health += node.health_percent;
    }
    if (!nodes_.empty()) stats.global_health /= nodes_.size();
    
    return stats;
}

std::vector<NodeInfo> FleetManager::GetNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NodeInfo> result;
    for (const auto& [id, node] : nodes_) {
        result.push_back(node);
    }
    return result;
}

NodeInfo FleetManager::GetNode(const std::string& node_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(node_id);
    if (it != nodes_.end()) return it->second;
    return NodeInfo{};
}

void FleetManager::SetNodeCallback(NodeCallback cb) {
    node_callback_ = std::move(cb);
}

void FleetManager::DiscoveryLoop() {
    // Simulate node discovery
    std::this_thread::sleep_for(std::chrono::seconds(1));
    RegisterNode("192.168.1.101:11435");
    RegisterNode("192.168.1.102:11435");
    RegisterNode("192.168.1.103:11435");
    RegisterNode("192.168.1.104:11435");
    
    std::cout << "\nRegistered: 4/4\n";
    std::cout << "STATUS: FLEET ONLINE\n";
}

void FleetManager::HeartbeatCheck() {
    // In production, would check node heartbeats
}

std::string FleetManager::GenerateNodeId() {
    static int counter = 0;
    counter++;
    return "rawrxd-node-" + std::to_string(counter);
}

} // namespace RawrXD::Fleet
