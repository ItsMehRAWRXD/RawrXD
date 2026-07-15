#include "federation/FederationGraph.hpp"
#include <mutex>
#include <map>
#include <set>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct Link {
    std::string from;
    std::string to;
    double weight;
    int64_t createdAt;
};

struct NodeInfo {
    std::string id;
    nlohmann::json metadata;
    int64_t registeredAt;
    bool active;
};

static std::map<std::string, NodeInfo> s_nodes;
static std::vector<Link> s_links;

void FederationGraph::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_nodes.clear();
        s_links.clear();
        s_initialized = true;
    }
}

void FederationGraph::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Periodic health check of links
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    (void)now; // For future use
}

bool FederationGraph::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void FederationGraph::AddLink(const std::string& from, const std::string& to, double weight) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Check if link already exists
    for (auto& link : s_links) {
        if (link.from == from && link.to == to) {
            link.weight = weight;
            return;
        }
    }
    
    Link link;
    link.from = from;
    link.to = to;
    link.weight = weight;
    link.createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    s_links.push_back(link);
}

void FederationGraph::RemoveLink(const std::string& from, const std::string& to) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_links.erase(
        std::remove_if(s_links.begin(), s_links.end(),
            [&from, &to](const Link& link) {
                return link.from == from && link.to == to;
            }),
        s_links.end()
    );
}

bool FederationGraph::HasLink(const std::string& from, const std::string& to) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return false;
    
    for (const auto& link : s_links) {
        if (link.from == from && link.to == to) {
            return true;
        }
    }
    return false;
}

nlohmann::json FederationGraph::GetLinks() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& link : s_links) {
        result.push_back({
            {"from", link.from},
            {"to", link.to},
            {"weight", link.weight},
            {"created_at", link.createdAt}
        });
    }
    return result;
}

nlohmann::json FederationGraph::GetNeighbors(const std::string& node) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& link : s_links) {
        if (link.from == node) {
            result.push_back({
                {"node", link.to},
                {"weight", link.weight}
            });
        }
    }
    return result;
}

nlohmann::json FederationGraph::GetGraphMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    return {
        {"node_count", s_nodes.size()},
        {"link_count", s_links.size()},
        {"density", s_nodes.size() > 1 ? (double)s_links.size() / (s_nodes.size() * (s_nodes.size() - 1)) : 0.0}
    };
}

void FederationGraph::RegisterNode(const std::string& nodeId, const nlohmann::json& metadata) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    NodeInfo node;
    node.id = nodeId;
    node.metadata = metadata;
    node.registeredAt = std::chrono::system_clock::now().time_since_epoch().count();
    node.active = true;
    s_nodes[nodeId] = node;
}

void FederationGraph::UnregisterNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_nodes.erase(nodeId);
    
    // Remove associated links
    s_links.erase(
        std::remove_if(s_links.begin(), s_links.end(),
            [&nodeId](const Link& link) {
                return link.from == nodeId || link.to == nodeId;
            }),
        s_links.end()
    );
}

nlohmann::json FederationGraph::GetNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_nodes.find(nodeId);
    if (it != s_nodes.end()) {
        return {
            {"id", it->second.id},
            {"metadata", it->second.metadata},
            {"registered_at", it->second.registeredAt},
            {"active", it->second.active}
        };
    }
    return nlohmann::json{};
}

nlohmann::json FederationGraph::GetAllNodes() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::object();
    for (const auto& [id, node] : s_nodes) {
        result[id] = {
            {"metadata", node.metadata},
            {"active", node.active}
        };
    }
    return result;
}
