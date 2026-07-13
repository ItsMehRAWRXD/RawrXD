// RawrXD Cluster Manager Implementation
// Phase O.1: Distributed cluster coordination

#include "ClusterManager.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Distributed {

// ClusterManager Implementation

ClusterManager::ClusterManager()
    : running_(false)
    , initialized_(false)
    , currentState_(ClusterState::INITIALIZING)
    , currentRole_(NodeRole::FOLLOWER)
    , term_(0)
    , votesReceived_(0)
{
}

ClusterManager::~ClusterManager() {
    shutdown();
}

bool ClusterManager::initialize(const ClusterConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    localNodeId_ = config.nodeId;
    
    // Initialize node info
    localNodeInfo_.nodeId = localNodeId_;
    localNodeInfo_.address = config.listenAddress;
    localNodeInfo_.port = config.listenPort;
    localNodeInfo_.capabilities = config.capabilities;
    localNodeInfo_.state = NodeState::JOINING;
    localNodeInfo_.joinedAt = std::chrono::steady_clock::now();
    localNodeInfo_.lastSeen = std::chrono::steady_clock::now();
    
    // Set resources
    localNodeInfo_.resources.totalVRAM = config.resources.totalVRAM;
    localNodeInfo_.resources.availableVRAM = config.resources.totalVRAM;
    localNodeInfo_.resources.totalRAM = config.resources.totalRAM;
    localNodeInfo_.resources.availableRAM = config.resources.totalRAM;
    localNodeInfo_.resources.cpuCores = config.resources.cpuCores;
    localNodeInfo_.resources.gpuCount = config.resources.gpuCount;
    
    // Initialize health
    localNodeInfo_.health.isHealthy = true;
    localNodeInfo_.health.cpuUsagePercent = 0.0f;
    localNodeInfo_.health.memoryUsagePercent = 0.0f;
    localNodeInfo_.health.gpuUsagePercent = 0.0f;
    localNodeInfo_.health.latencyMs = 0;
    
    running_ = true;
    
    // Start background threads
    heartbeatThread_ = std::thread(&ClusterManager::heartbeatLoop, this);
    electionThread_ = std::thread(&ClusterManager::electionLoop, this);
    monitorThread_ = std::thread(&ClusterManager::monitorLoop, this);
    
    // Join cluster
    if (!config_.seedNodes.empty()) {
        joinCluster();
    } else {
        // First node becomes leader
        becomeLeader();
    }
    
    initialized_ = true;
    currentState_ = ClusterState::HEALTHY;
    
    return true;
}

bool ClusterManager::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    // Notify other nodes
    if (currentRole_ == NodeRole::LEADER) {
        notifyLeadershipChange("");
    }
    
    // Stop threads
    if (heartbeatThread_.joinable()) {
        heartbeatThread_.join();
    }
    if (electionThread_.joinable()) {
        electionThread_.join();
    }
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
    
    initialized_ = false;
    currentState_ = ClusterState::DEGRADED;
    
    return true;
}

// Node management
bool ClusterManager::joinCluster() {
    for (const auto& seed : config_.seedNodes) {
        if (sendJoinRequest(seed)) {
            return true;
        }
    }
    return false;
}

bool ClusterManager::leaveCluster() {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    for (auto& pair : nodes_) {
        sendLeaveNotification(pair.first);
    }
    
    nodes_.clear();
    return true;
}

bool ClusterManager::addNode(const NodeInfo& node) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    if (nodes_.find(node.nodeId) != nodes_.end()) {
        return false; // Already exists
    }
    
    nodes_[node.nodeId] = node;
    
    // Notify callback
    if (eventCallback_) {
        ClusterEvent event;
        event.type = ClusterEventType::NODE_JOINED;
        event.nodeId = node.nodeId;
        event.timestamp = std::chrono::steady_clock::now();
        eventCallback_(event);
    }
    
    return true;
}

bool ClusterManager::removeNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end()) {
        return false;
    }
    
    nodes_.erase(it);
    
    // Notify callback
    if (eventCallback_) {
        ClusterEvent event;
        event.type = ClusterEventType::NODE_LEFT;
        event.nodeId = nodeId;
        event.timestamp = std::chrono::steady_clock::now();
        eventCallback_(event);
    }
    
    return true;
}

std::vector<NodeInfo> ClusterManager::getAllNodes() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    std::vector<NodeInfo> result;
    for (const auto& pair : nodes_) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<NodeInfo> ClusterManager::getHealthyNodes() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    std::vector<NodeInfo> result;
    for (const auto& pair : nodes_) {
        if (pair.second.state == NodeState::HEALTHY &&
            pair.second.health.isHealthy) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<NodeInfo> ClusterManager::getNodesByCapability(NodeCapability capability) const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    std::vector<NodeInfo> result;
    for (const auto& pair : nodes_) {
        if ((pair.second.capabilities & static_cast<uint32_t>(capability)) != 0) {
            result.push_back(pair.second);
        }
    }
    return result;
}

NodeInfo ClusterManager::getNode(const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        return it->second;
    }
    return NodeInfo();
}

bool ClusterManager::updateNodeHealth(const std::string& nodeId, const NodeHealth& health) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end()) {
        return false;
    }
    
    it->second.health = health;
    it->second.lastSeen = std::chrono::steady_clock::now();
    
    return true;
}

// Leader election
bool ClusterManager::becomeLeader() {
    if (currentRole_ == NodeRole::LEADER) {
        return true;
    }
    
    currentRole_ = NodeRole::LEADER;
    leaderNodeId_ = localNodeId_;
    term_++;
    
    // Update local node
    localNodeInfo_.state = NodeState::HEALTHY;
    
    // Notify others
    notifyLeadershipChange(localNodeId_);
    
    // Trigger callback
    if (eventCallback_) {
        ClusterEvent event;
        event.type = ClusterEventType::LEADER_ELECTED;
        event.nodeId = localNodeId_;
        event.timestamp = std::chrono::steady_clock::now();
        eventCallback_(event);
    }
    
    return true;
}

bool ClusterManager::stepDown() {
    if (currentRole_ != NodeRole::LEADER) {
        return false;
    }
    
    currentRole_ = NodeRole::FOLLOWER;
    votesReceived_ = 0;
    
    return true;
}

std::string ClusterManager::getLeaderNodeId() const {
    return leaderNodeId_;
}

bool ClusterManager::isLeader() const {
    return currentRole_ == NodeRole::LEADER;
}

// Statistics
ClusterStats ClusterManager::getStats() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    ClusterStats stats;
    stats.totalNodes = nodes_.size() + 1; // +1 for local node
    stats.healthyNodes = 1; // Local node
    stats.unhealthyNodes = 0;
    
    for (const auto& pair : nodes_) {
        if (pair.second.health.isHealthy) {
            stats.healthyNodes++;
        } else {
            stats.unhealthyNodes++;
        }
    }
    
    // Calculate total resources
    stats.totalVRAM = localNodeInfo_.resources.totalVRAM;
    stats.availableVRAM = localNodeInfo_.resources.availableVRAM;
    stats.totalRAM = localNodeInfo_.resources.totalRAM;
    stats.availableRAM = localNodeInfo_.resources.availableRAM;
    
    for (const auto& pair : nodes_) {
        stats.totalVRAM += pair.second.resources.totalVRAM;
        stats.availableVRAM += pair.second.resources.availableVRAM;
        stats.totalRAM += pair.second.resources.totalRAM;
        stats.availableRAM += pair.second.resources.availableRAM;
    }
    
    return stats;
}

// Internal methods
void ClusterManager::heartbeatLoop() {
    while (running_) {
        // Send heartbeats to all nodes
        if (currentRole_ == NodeRole::LEADER) {
            sendHeartbeatsToAll();
        }
        
        // Check for node timeouts
        checkNodeTimeouts();
        
        // Sleep for heartbeat interval
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.heartbeatIntervalMs));
    }
}

void ClusterManager::electionLoop() {
    while (running_) {
        if (currentRole_ != NodeRole::LEADER) {
            // Check if leader is alive
            auto leader = getNode(leaderNodeId_);
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - leader.lastSeen).count();
            
            if (elapsed > config_.leaderTimeoutMs) {
                // Leader timeout - start election
                startElection();
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ClusterManager::monitorLoop() {
    while (running_) {
        // Update local health metrics
        updateLocalHealth();
        
        // Check cluster state
        updateClusterState();
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void ClusterManager::startElection() {
    currentRole_ = NodeRole::CANDIDATE;
    term_++;
    votesReceived_ = 1; // Vote for self
    
    // Request votes from all nodes
    std::lock_guard<std::mutex> lock(nodesMutex_);
    for (const auto& pair : nodes_) {
        sendVoteRequest(pair.first);
    }
}

void ClusterManager::sendHeartbeatsToAll() {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    for (const auto& pair : nodes_) {
        sendHeartbeat(pair.first);
    }
}

void ClusterManager::checkNodeTimeouts() {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> timedOutNodes;
    
    for (const auto& pair : nodes_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - pair.second.lastSeen).count();
        
        if (elapsed > config_.nodeTimeoutMs) {
            timedOutNodes.push_back(pair.first);
        }
    }
    
    // Remove timed out nodes
    for (const auto& nodeId : timedOutNodes) {
        nodes_.erase(nodeId);
        
        if (eventCallback_) {
            ClusterEvent event;
            event.type = ClusterEventType::NODE_TIMEOUT;
            event.nodeId = nodeId;
            event.timestamp = now;
            eventCallback_(event);
        }
    }
}

void ClusterManager::updateLocalHealth() {
    // Update local node health (would integrate with system monitoring)
    localNodeInfo_.lastSeen = std::chrono::steady_clock::now();
}

void ClusterManager::updateClusterState() {
    auto stats = getStats();
    
    if (stats.unhealthyNodes == 0) {
        currentState_ = ClusterState::HEALTHY;
    } else if (stats.unhealthyNodes < stats.totalNodes / 2) {
        currentState_ = ClusterState::DEGRADED;
    } else {
        currentState_ = ClusterState::RECOVERING;
    }
}

// Network communication stubs (would be implemented with actual RPC)
bool ClusterManager::sendJoinRequest(const std::string& seedNode) {
    // Implementation would send actual RPC
    return true;
}

bool ClusterManager::sendLeaveNotification(const std::string& nodeId) {
    // Implementation would send actual RPC
    return true;
}

bool ClusterManager::sendHeartbeat(const std::string& nodeId) {
    // Implementation would send actual RPC
    return true;
}

bool ClusterManager::sendVoteRequest(const std::string& nodeId) {
    // Implementation would send actual RPC
    return true;
}

bool ClusterManager::notifyLeadershipChange(const std::string& newLeaderId) {
    // Implementation would send actual RPC
    return true;
}

} // namespace Distributed
} // namespace RawrXD
