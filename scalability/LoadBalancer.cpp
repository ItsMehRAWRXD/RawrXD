#include "scalability/LoadBalancer.hpp"
#include <mutex>
#include <map>
#include <chrono>
#include <algorithm>

static std::mutex s_mutex;
static bool s_initialized = false;

struct NodeInfo {
    std::string id;
    nlohmann::json capabilities;
    double currentLoad;
    bool healthy;
    int64_t lastUpdated;
    size_t requestCount;
};

static std::map<std::string, NodeInfo> s_nodes;
static std::string s_strategy = "least_loaded";
static size_t s_roundRobinIndex = 0;
static size_t s_totalRequests = 0;
static size_t s_failedRequests = 0;

void LoadBalancer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_nodes.clear();
        s_strategy = "least_loaded";
        s_roundRobinIndex = 0;
        s_totalRequests = 0;
        s_failedRequests = 0;
        s_initialized = true;
    }
}

void LoadBalancer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update node health based on last update time
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    for (auto& [id, node] : s_nodes) {
        if ((now - node.lastUpdated) > 30000000000) { // 30 seconds
            node.healthy = false;
        }
    }
}

bool LoadBalancer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json LoadBalancer::DistributeLoad(const std::string& taskType, const nlohmann::json& task) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    s_totalRequests++;
    
    // Filter healthy nodes
    std::vector<std::string> healthyNodes;
    for (const auto& [id, node] : s_nodes) {
        if (node.healthy) {
            healthyNodes.push_back(id);
        }
    }
    
    if (healthyNodes.empty()) {
        s_failedRequests++;
        return {
            {"success", false},
            {"reason", "no_healthy_nodes"}
        };
    }
    
    std::string selectedNode;
    
    if (s_strategy == "round_robin") {
        selectedNode = healthyNodes[s_roundRobinIndex % healthyNodes.size()];
        s_roundRobinIndex++;
    } else if (s_strategy == "least_loaded") {
        // Find node with lowest load
        double minLoad = std::numeric_limits<double>::max();
        for (const auto& nodeId : healthyNodes) {
            if (s_nodes[nodeId].currentLoad < minLoad) {
                minLoad = s_nodes[nodeId].currentLoad;
                selectedNode = nodeId;
            }
        }
    } else if (s_strategy == "weighted") {
        // Simple weighted random selection based on capabilities
        selectedNode = healthyNodes[0]; // Default to first
        double maxWeight = 0;
        for (const auto& nodeId : healthyNodes) {
            double weight = s_nodes[nodeId].capabilities.value("weight", 1.0);
            if (weight > maxWeight) {
                maxWeight = weight;
                selectedNode = nodeId;
            }
        }
    }
    
    // Update node load
    if (!selectedNode.empty()) {
        s_nodes[selectedNode].currentLoad += 0.1;
        s_nodes[selectedNode].requestCount++;
        s_nodes[selectedNode].lastUpdated = std::chrono::system_clock::now().time_since_epoch().count();
    }
    
    return {
        {"success", true},
        {"node_id", selectedNode},
        {"strategy", s_strategy},
        {"task_type", taskType}
    };
}

nlohmann::json LoadBalancer::GetNodeLoad(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_nodes.find(nodeId);
    if (it != s_nodes.end()) {
        return {
            {"node_id", it->second.id},
            {"current_load", it->second.currentLoad},
            {"healthy", it->second.healthy},
            {"request_count", it->second.requestCount}
        };
    }
    return nlohmann::json{};
}

nlohmann::json LoadBalancer::GetAllNodeLoads() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::object();
    for (const auto& [id, node] : s_nodes) {
        result[id] = {
            {"current_load", node.currentLoad},
            {"healthy", node.healthy},
            {"request_count", node.requestCount}
        };
    }
    return result;
}

void LoadBalancer::RegisterNode(const std::string& nodeId, const nlohmann::json& capabilities) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    NodeInfo node;
    node.id = nodeId;
    node.capabilities = capabilities;
    node.currentLoad = 0.0;
    node.healthy = true;
    node.lastUpdated = std::chrono::system_clock::now().time_since_epoch().count();
    node.requestCount = 0;
    
    s_nodes[nodeId] = node;
}

void LoadBalancer::UnregisterNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_nodes.erase(nodeId);
}

void LoadBalancer::UpdateNodeHealth(const std::string& nodeId, bool healthy) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_nodes.find(nodeId);
    if (it != s_nodes.end()) {
        it->second.healthy = healthy;
        it->second.lastUpdated = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

void LoadBalancer::SetStrategy(const std::string& strategy) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    if (strategy == "round_robin" || strategy == "least_loaded" || strategy == "weighted") {
        s_strategy = strategy;
    }
}

nlohmann::json LoadBalancer::GetStrategy() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"strategy", s_strategy},
        {"available", nlohmann::json::array({"round_robin", "least_loaded", "weighted"})}
    };
}

nlohmann::json LoadBalancer::GetLoadBalancerMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t healthyCount = 0;
    size_t unhealthyCount = 0;
    double totalLoad = 0.0;
    
    for (const auto& [id, node] : s_nodes) {
        if (node.healthy) healthyCount++;
        else unhealthyCount++;
        totalLoad += node.currentLoad;
    }
    
    return {
        {"total_nodes", s_nodes.size()},
        {"healthy_nodes", healthyCount},
        {"unhealthy_nodes", unhealthyCount},
        {"total_requests", s_totalRequests},
        {"failed_requests", s_failedRequests},
        {"average_load", s_nodes.empty() ? 0.0 : totalLoad / s_nodes.size()},
        {"current_strategy", s_strategy}
    };
}
