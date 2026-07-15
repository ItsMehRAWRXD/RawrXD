// Sovereign Distributed Runtime - Phase D.3 Batch 1/5
// Node Discovery Implementation
// Copyright (c) 2026 RawrXD Team

#include "SovereignNodeDiscovery.hpp"
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// NodeIdentity Implementation
// ============================================================================

std::string NodeIdentity::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"node_id\":\"" << node_id << "\",";
    oss << "\"hostname\":\"" << hostname << "\",";
    oss << "\"ip_address\":\"" << ip_address << "\",";
    oss << "\"port\":" << port << ",";
    oss << "\"datacenter\":\"" << datacenter << "\",";
    oss << "\"rack\":\"" << rack << "\",";
    oss << "\"version\":\"" << version << "\",";
    oss << "\"capabilities\":[";
    for (size_t i = 0; i < capabilities.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << capabilities[i] << "\"";
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

NodeIdentity NodeIdentity::FromJson(const std::string& json) {
    NodeIdentity identity;
    // Simple JSON parsing - production would use proper JSON library
    size_t pos = 0;
    auto extractString = [&](const std::string& key) -> std::string {
        size_t keyPos = json.find("\"" + key + "\":");
        if (keyPos == std::string::npos) return "";
        size_t start = json.find("\"", keyPos + key.length() + 3);
        if (start == std::string::npos) return "";
        size_t end = json.find("\"", start + 1);
        if (end == std::string::npos) return "";
        return json.substr(start + 1, end - start - 1);
    };
    
    auto extractInt = [&](const std::string& key) -> int {
        size_t keyPos = json.find("\"" + key + "\":");
        if (keyPos == std::string::npos) return 0;
        size_t start = keyPos + key.length() + 3;
        size_t end = json.find_first_of(",}", start);
        if (end == std::string::npos) return 0;
        return std::stoi(json.substr(start, end - start));
    };
    
    identity.node_id = extractString("node_id");
    identity.hostname = extractString("hostname");
    identity.ip_address = extractString("ip_address");
    identity.port = extractInt("port");
    identity.datacenter = extractString("datacenter");
    identity.rack = extractString("rack");
    identity.version = extractString("version");
    
    return identity;
}

// ============================================================================
// ClusterTopology Implementation
// ============================================================================

bool ClusterTopology::AddNode(const NodeIdentity& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if node already exists
    for (const auto& n : nodes_) {
        if (n.node_id == node.node_id) {
            return false;
        }
    }
    
    nodes_.push_back(node);
    node_health_[node.node_id] = NodeHealth::HEALTHY;
    last_heartbeat_[node.node_id] = std::chrono::steady_clock::now();
    return true;
}

bool ClusterTopology::RemoveNode(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::remove_if(nodes_.begin(), nodes_.end(),
        [&node_id](const NodeIdentity& n) { return n.node_id == node_id; });
    
    if (it != nodes_.end()) {
        nodes_.erase(it, nodes_.end());
        node_health_.erase(node_id);
        last_heartbeat_.erase(node_id);
        
        // If leader left, clear leader
        if (leader_id_ == node_id) {
            leader_id_.clear();
        }
        
        return true;
    }
    
    return false;
}

std::vector<NodeIdentity> ClusterTopology::GetHealthyNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<NodeIdentity> healthy;
    for (const auto& node : nodes_) {
        auto it = node_health_.find(node.node_id);
        if (it != node_health_.end() && 
            (it->second == NodeHealth::HEALTHY || it->second == NodeHealth::DEGRADED)) {
            healthy.push_back(node);
        }
    }
    return healthy;
}

int ClusterTopology::GetQuorumSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    int healthy_count = 0;
    for (const auto& node : nodes_) {
        auto it = node_health_.find(node.node_id);
        if (it != node_health_.end() && it->second == NodeHealth::HEALTHY) {
            healthy_count++;
        }
    }
    return (healthy_count / 2) + 1;
}

bool ClusterTopology::HasQuorum() const {
    std::lock_guard<std::mutex> lock(mutex_);
    int healthy_count = 0;
    for (const auto& node : nodes_) {
        auto it = node_health_.find(node.node_id);
        if (it != node_health_.end() && it->second == NodeHealth::HEALTHY) {
            healthy_count++;
        }
    }
    return healthy_count >= GetQuorumSize();
}

void ClusterTopology::SetLeader(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    leader_id_ = node_id;
}

std::string ClusterTopology::GetLeader() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return leader_id_;
}

bool ClusterTopology::IsLeader(const std::string& node_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return leader_id_ == node_id;
}

void ClusterTopology::UpdateHealth(const std::string& node_id, NodeHealth health) {
    std::lock_guard<std::mutex> lock(mutex_);
    node_health_[node_id] = health;
    last_heartbeat_[node_id] = std::chrono::steady_clock::now();
}

NodeHealth ClusterTopology::GetHealth(const std::string& node_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = node_health_.find(node_id);
    if (it != node_health_.end()) {
        return it->second;
    }
    return NodeHealth::OFFLINE;
}

std::string ClusterTopology::ToJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ostringstream oss;
    oss << "{";
    oss << "\"nodes\":[";
    for (size_t i = 0; i < nodes_.size(); ++i) {
        if (i > 0) oss << ",";
        oss << nodes_[i].ToJson();
    }
    oss << "],";
    oss << "\"leader_id\":\"" << leader_id_ << "\",";
    oss << "\"version\":" << version_;
    oss << "}";
    return oss.str();
}

// ============================================================================
// NodeDiscovery Implementation
// ============================================================================

NodeDiscovery::NodeDiscovery(const Config& config) : config_(config) {
    topology_ = std::make_shared<ClusterTopology>();
}

NodeDiscovery::~NodeDiscovery() {
    Shutdown();
}

bool NodeDiscovery::Initialize() {
    if (initialized_) {
        return true;
    }
    
    // Generate node ID if not provided
    if (config_.self.node_id.empty()) {
        config_.self.node_id = GenerateNodeId();
    }
    
    // Add self to topology
    topology_->AddNode(config_.self);
    
    running_ = true;
    
    // Start heartbeat thread
    heartbeat_thread_ = std::thread(&NodeDiscovery::HeartbeatLoop, this);
    
    // Start discovery based on method
    switch (config_.method) {
        case DiscoveryMethod::STATIC:
            // Already have static nodes in config
            for (const auto& node : config_.static_nodes) {
                if (node.node_id != config_.self.node_id) {
                    topology_->AddNode(node);
                }
            }
            break;
            
        case DiscoveryMethod::MULTICAST:
            discovery_thread_ = std::thread(&NodeDiscovery::MulticastDiscovery, this);
            break;
            
        case DiscoveryMethod::CONSUL:
            discovery_thread_ = std::thread(&NodeDiscovery::ConsulDiscovery, this);
            break;
            
        case DiscoveryMethod::KUBERNETES:
            discovery_thread_ = std::thread(&NodeDiscovery::KubernetesDiscovery, this);
            break;
    }
    
    initialized_ = true;
    return true;
}

void NodeDiscovery::Shutdown() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    
    if (discovery_thread_.joinable()) {
        discovery_thread_.join();
    }
    
    initialized_ = false;
}

std::shared_ptr<ClusterTopology> NodeDiscovery::GetTopology() const {
    return topology_;
}

std::vector<NodeIdentity> NodeDiscovery::GetAllNodes() const {
    return topology_->GetHealthyNodes();
}

std::vector<NodeIdentity> NodeDiscovery::GetNodesInDatacenter(
    const std::string& datacenter) const {
    std::vector<NodeIdentity> result;
    auto nodes = topology_->GetHealthyNodes();
    for (const auto& node : nodes) {
        if (node.datacenter == datacenter) {
            result.push_back(node);
        }
    }
    return result;
}

std::vector<NodeIdentity> NodeDiscovery::GetNodesInRack(
    const std::string& rack) const {
    std::vector<NodeIdentity> result;
    auto nodes = topology_->GetHealthyNodes();
    for (const auto& node : nodes) {
        if (node.rack == rack) {
            result.push_back(node);
        }
    }
    return result;
}

bool NodeDiscovery::IsLeader() const {
    return topology_->IsLeader(config_.self.node_id);
}

std::string NodeDiscovery::GetLeaderId() const {
    return topology_->GetLeader();
}

bool NodeDiscovery::ElectLeader() {
    if (!IsLeader()) {
        // Simple leader election: lowest node ID wins
        auto nodes = topology_->GetHealthyNodes();
        std::string lowest_id = config_.self.node_id;
        
        for (const auto& node : nodes) {
            if (node.node_id < lowest_id) {
                lowest_id = node.node_id;
            }
        }
        
        topology_->SetLeader(lowest_id);
        
        if (lowest_id == config_.self.node_id && on_leader_elected_) {
            on_leader_elected_();
        }
    }
    
    return IsLeader();
}

void NodeDiscovery::StepDown() {
    if (IsLeader()) {
        topology_->SetLeader("");
    }
}

void NodeDiscovery::OnLeaderElected(std::function<void()> callback) {
    on_leader_elected_ = callback;
}

void NodeDiscovery::OnNodeJoined(std::function<void(const NodeIdentity&)> callback) {
    on_node_joined_ = callback;
}

void NodeDiscovery::OnNodeLeft(std::function<void(const NodeIdentity&)> callback) {
    on_node_left_ = callback;
}

void NodeDiscovery::HeartbeatLoop() {
    while (running_) {
        // Send heartbeat to all known nodes
        auto nodes = topology_->GetHealthyNodes();
        for (const auto& node : nodes) {
            if (node.node_id != config_.self.node_id) {
                SendHeartbeat(node);
            }
        }
        
        // Check for stale nodes
        CheckStaleNodes();
        
        // Leader election check
        if (topology_->GetLeader().empty()) {
            ElectLeader();
        }
        
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.heartbeat_interval_ms));
    }
}

void NodeDiscovery::SendHeartbeat(const NodeIdentity& node) {
    // Placeholder for actual network implementation
    // In production, this would send UDP/TCP heartbeat
}

void NodeDiscovery::CheckStaleNodes() {
    // Placeholder for stale node detection
    // In production, check last_heartbeat timestamps
}

void NodeDiscovery::MulticastDiscovery() {
    // Placeholder for multicast discovery
    // In production, join multicast group and listen for announcements
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void NodeDiscovery::ConsulDiscovery() {
    // Placeholder for Consul discovery
    // In production, query Consul API for service instances
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void NodeDiscovery::KubernetesDiscovery() {
    // Placeholder for Kubernetes discovery
    // In production, query K8s API for endpoints
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

std::string NodeDiscovery::GenerateNodeId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::ostringstream oss;
    oss << "node-";
    for (int i = 0; i < 8; ++i) {
        oss << std::hex << dis(gen);
    }
    return oss.str();
}

// ============================================================================
// ServiceRegistry Implementation
// ============================================================================

ServiceRegistry::ServiceRegistry(std::shared_ptr<NodeDiscovery> discovery)
    : discovery_(discovery) {
}

bool ServiceRegistry::RegisterService(const ServiceInfo& service) {
    std::lock_guard<std::mutex> lock(services_mutex_);
    
    // Check if service already registered
    auto& instances = services_[service.service_name];
    for (const auto& inst : instances) {
        if (inst.instance_id == service.instance_id) {
            return false;
        }
    }
    
    instances.push_back(service);
    return true;
}

bool ServiceRegistry::DeregisterService(const std::string& service_name,
                                       const std::string& instance_id) {
    std::lock_guard<std::mutex> lock(services_mutex_);
    
    auto it = services_.find(service_name);
    if (it == services_.end()) {
        return false;
    }
    
    auto& instances = it->second;
    auto inst_it = std::remove_if(instances.begin(), instances.end(),
        [&instance_id](const ServiceInfo& s) { return s.instance_id == instance_id; });
    
    if (inst_it != instances.end()) {
        instances.erase(inst_it, instances.end());
        return true;
    }
    
    return false;
}

std::vector<ServiceInfo> ServiceRegistry::DiscoverService(
    const std::string& service_name) const {
    std::lock_guard<std::mutex> lock(services_mutex_);
    
    auto it = services_.find(service_name);
    if (it != services_.end()) {
        return it->second;
    }
    
    return {};
}

ServiceInfo ServiceRegistry::GetHealthyInstance(const std::string& service_name) const {
    auto instances = DiscoverService(service_name);
    
    for (const auto& inst : instances) {
        if (inst.status == ServiceStatus::HEALTHY) {
            return inst;
        }
    }
    
    return {};  // Return empty if no healthy instance
}

} // namespace Distributed
} // namespace Sovereign
