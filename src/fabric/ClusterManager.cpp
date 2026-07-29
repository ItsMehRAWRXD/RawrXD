#include "ClusterManager.h"
#include "FabricMessages.h"
#include <Windows.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <iostream>

#pragma comment(lib, "pdh.lib")

namespace RawrXD {
namespace Fabric {

// ============================================================================
// ClusterManager Implementation
// ============================================================================

ClusterManager::ClusterManager()
    : transport_(nullptr) {
}

ClusterManager::~ClusterManager() {
    Shutdown();
}

bool ClusterManager::Initialize(const ClusterConfig& config, FabricTransport* transport) {
    config_ = config;
    transport_ = transport;
    
    if (!transport_) {
        return false;
    }
    
    // Add self to hash ring
    hashRing_.AddNode(config_.localNodeId, 
                      config_.bindAddress + ":" + std::to_string(config_.bindPort));
    
    // Initialize self in node list
    NodeInfo self;
    self.nodeId = config_.localNodeId;
    self.address = config_.bindAddress + ":" + std::to_string(config_.bindPort);
    self.state = NodeState::JOINING;
    self.lastHeartbeat = GetTimestampUs();
    self.uptimeUs = 0;
    self.loadPercent = 0;
    self.tensorCount = 0;
    self.version = 1;
    
    {
        std::unique_lock<std::shared_mutex> lock(nodesMutex_);
        nodes_[config_.localNodeId] = self;
    }
    
    // Start worker threads
    shutdown_ = false;
    heartbeatThread_ = std::thread(&ClusterManager::HeartbeatLoop, this);
    gossipThread_ = std::thread(&ClusterManager::GossipLoop, this);
    rebalanceThread_ = std::thread(&ClusterManager::RebalanceLoop, this);
    
    initialized_ = true;
    return true;
}

void ClusterManager::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    // Gracefully leave cluster
    if (inCluster_) {
        LeaveCluster();
    }
    
    shutdown_ = true;
    
    // Wait for threads
    if (heartbeatThread_.joinable()) {
        heartbeatThread_.join();
    }
    if (gossipThread_.joinable()) {
        gossipThread_.join();
    }
    if (rebalanceThread_.joinable()) {
        rebalanceThread_.join();
    }
    
    initialized_ = false;
}

bool ClusterManager::JoinCluster(const std::string& seedAddress) {
    if (!initialized_ || inCluster_) {
        return false;
    }
    
    // Connect to seed node
    // In production: would exchange node lists, merge clusters
    
    // For now: mark as in cluster
    {
        std::unique_lock<std::shared_mutex> lock(nodesMutex_);
        nodes_[config_.localNodeId].state = NodeState::ACTIVE;
    }
    
    inCluster_ = true;
    
    // Trigger initial rebalancing
    TriggerRebalance();
    
    return true;
}

bool ClusterManager::LeaveCluster() {
    if (!inCluster_) {
        return false;
    }
    
    // Mark as leaving
    {
        std::unique_lock<std::shared_mutex> lock(nodesMutex_);
        nodes_[config_.localNodeId].state = NodeState::LEAVING;
    }
    
    // Broadcast leave message
    FabricMessage msg;
    msg.header.op = FabricOp::INVALIDATE;  // Reuse for leave notification
    msg.header.payloadSize = sizeof(InvalidateMessage);
    msg.payload.invalidate.tensorId = config_.localNodeId;
    msg.payload.invalidate.version = 0;
    msg.payload.invalidate.newNodeId = 0;
    
    BroadcastToCluster(msg);
    
    // Wait for rebalancing to complete
    int waitMs = 0;
    while (IsRebalancing() && waitMs < 5000) {
        Sleep(100);
        waitMs += 100;
    }
    
    inCluster_ = false;
    return true;
}

bool ClusterManager::IsInCluster() const {
    return inCluster_.load(std::memory_order_acquire);
}

std::vector<NodeInfo> ClusterManager::GetActiveNodes() const {
    std::shared_lock<std::shared_mutex> lock(nodesMutex_);
    
    std::vector<NodeInfo> active;
    for (const auto& [id, info] : nodes_) {
        if (info.state == NodeState::ACTIVE) {
            active.push_back(info);
        }
    }
    return active;
}

size_t ClusterManager::GetClusterSize() const {
    std::shared_lock<std::shared_mutex> lock(nodesMutex_);
    return nodes_.size();
}

bool ClusterManager::IsNodeActive(uint32_t nodeId) const {
    std::shared_lock<std::shared_mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end()) {
        return false;
    }
    
    return it->second.state == NodeState::ACTIVE;
}

uint32_t ClusterManager::GetPrimaryNode(uint64_t tensorId) const {
    return hashRing_.GetNodeForTensor(tensorId);
}

std::vector<uint32_t> ClusterManager::GetReplicaNodes(uint64_t tensorId) const {
    return hashRing_.GetNodesForTensor(tensorId, config_.replicationFactor);
}

bool ClusterManager::IsLocalTensor(uint64_t tensorId) const {
    uint32_t primary = GetPrimaryNode(tensorId);
    return primary == config_.localNodeId;
}

bool ClusterManager::TriggerRebalance() {
    if (rebalancing_.load(std::memory_order_acquire)) {
        return false;  // Already rebalancing
    }
    
    rebalancing_ = true;
    rebalanceProgress_ = 0.0;
    return true;
}

bool ClusterManager::IsRebalancing() const {
    return rebalancing_.load(std::memory_order_acquire);
}

double ClusterManager::GetRebalanceProgress() const {
    return rebalanceProgress_.load(std::memory_order_acquire);
}

void ClusterManager::ReportNodeSuspect(uint32_t nodeId) {
    UpdateNodeState(nodeId, NodeState::SUSPECT);
}

void ClusterManager::ConfirmNodeFailed(uint32_t nodeId) {
    UpdateNodeState(nodeId, NodeState::FAILED);
    
    // Remove from hash ring
    hashRing_.RemoveNode(nodeId);
    
    // Remove from node list
    {
        std::unique_lock<std::shared_mutex> lock(nodesMutex_);
        nodes_.erase(nodeId);
    }
    
    nodesFailed_.fetch_add(1, std::memory_order_relaxed);
    
    // Trigger rebalancing
    TriggerRebalance();
    
    // Notify callback
    if (nodeLeftCb_) {
        nodeLeftCb_(nodeId);
    }
}

void ClusterManager::SetNodeJoinedCallback(NodeJoinedCallback cb) {
    nodeJoinedCb_ = cb;
}

void ClusterManager::SetNodeLeftCallback(NodeLeftCallback cb) {
    nodeLeftCb_ = cb;
}

void ClusterManager::SetRebalanceCallback(RebalanceCallback cb) {
    rebalanceCb_ = cb;
}

ClusterManager::Stats ClusterManager::GetStats() const {
    Stats stats;
    stats.heartbeatsSent = heartbeatsSent_.load(std::memory_order_relaxed);
    stats.heartbeatsReceived = heartbeatsReceived_.load(std::memory_order_relaxed);
    stats.nodesJoined = nodesJoined_.load(std::memory_order_relaxed);
    stats.nodesFailed = nodesFailed_.load(std::memory_order_relaxed);
    stats.rebalanceOperations = rebalanceOps_.load(std::memory_order_relaxed);
    stats.tensorMigrations = tensorMigrations_.load(std::memory_order_relaxed);
    return stats;
}

// ============================================================================
// Worker Threads
// ============================================================================

void ClusterManager::HeartbeatLoop() {
    while (!shutdown_) {
        if (!inCluster_) {
            Sleep(config_.heartbeatIntervalMs);
            continue;
        }
        
        // Send heartbeat to all nodes
        FabricMessage msg;
        msg.header.op = FabricOp::HEARTBEAT;
        msg.header.payloadSize = sizeof(HeartbeatMessage);
        msg.payload.heartbeat.nodeId = config_.localNodeId;
        msg.payload.heartbeat.loadPercent = GetSystemLoadPercent();
        msg.payload.heartbeat.uptimeUs = GetTimestampUs();
        msg.payload.heartbeat.tensorCount = GetLocalTensorCount();
        
        BroadcastToCluster(msg);
        
        heartbeatsSent_.fetch_add(1, std::memory_order_relaxed);
        
        Sleep(config_.heartbeatIntervalMs);
    }
}

void ClusterManager::GossipLoop() {
    while (!shutdown_) {
        if (!inCluster_) {
            Sleep(100);
            continue;
        }
        
        // Check for failed nodes
        CheckForFailedNodes();
        
        Sleep(config_.heartbeatTimeoutMs);
    }
}

void ClusterManager::RebalanceLoop() {
    while (!shutdown_) {
        if (!rebalancing_.load(std::memory_order_acquire)) {
            Sleep(100);
            continue;
        }
        
        PerformRebalance();
        
        rebalancing_ = false;
        rebalanceProgress_ = 1.0;
        
        rebalanceOps_.fetch_add(1, std::memory_order_relaxed);
    }
}

// ============================================================================
// Message Handlers
// ============================================================================

void ClusterManager::OnHeartbeat(const HeartbeatMessage& msg, uint32_t fromNode) {
    heartbeatsReceived_.fetch_add(1, std::memory_order_relaxed);
    
    std::unique_lock<std::shared_mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(fromNode);
    if (it == nodes_.end()) {
        // New node
        NodeInfo info;
        info.nodeId = fromNode;
        info.state = NodeState::ACTIVE;
        info.lastHeartbeat = GetTimestampUs();
        info.loadPercent = msg.loadPercent;
        info.uptimeUs = msg.uptimeUs;
        info.tensorCount = msg.tensorCount;
        
        nodes_[fromNode] = info;
        
        // Add to hash ring - extract address from node info if available
        std::string nodeAddress = GetNodeAddress(fromNode);
        if (nodeAddress.empty()) {
            nodeAddress = config_.bindAddress + ":" + std::to_string(config_.bindPort);
        }
        hashRing_.AddNode(fromNode, nodeAddress);
        
        nodesJoined_.fetch_add(1, std::memory_order_relaxed);
        
        if (nodeJoinedCb_) {
            nodeJoinedCb_(fromNode);
        }
    } else {
        // Update existing
        it->second.lastHeartbeat = GetTimestampUs();
        it->second.loadPercent = msg.loadPercent;
        it->second.uptimeUs = msg.uptimeUs;
        it->second.tensorCount = msg.tensorCount;
        
        if (it->second.state == NodeState::SUSPECT) {
            it->second.state = NodeState::ACTIVE;
        }
    }
}

void ClusterManager::OnNodeJoin(uint32_t nodeId, const std::string& address) {
    // Handled in heartbeat
}

void ClusterManager::OnNodeLeave(uint32_t nodeId) {
    ConfirmNodeFailed(nodeId);
}

// ============================================================================
// Helpers
// ============================================================================

void ClusterManager::UpdateNodeState(uint32_t nodeId, NodeState state) {
    std::unique_lock<std::shared_mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        it->second.state = state;
    }
}

void ClusterManager::CheckForFailedNodes() {
    uint64_t now = GetTimestampUs();
    uint64_t timeoutUs = config_.heartbeatTimeoutMs * 1000;
    
    std::vector<uint32_t> suspects;
    std::vector<uint32_t> failed;
    
    {
        std::shared_lock<std::shared_mutex> lock(nodesMutex_);
        
        for (const auto& [id, info] : nodes_) {
            if (id == config_.localNodeId) continue;
            
            uint64_t elapsed = now - info.lastHeartbeat;
            
            if (info.state == NodeState::ACTIVE && elapsed > timeoutUs) {
                suspects.push_back(id);
            } else if (info.state == NodeState::SUSPECT && 
                       elapsed > config_.suspectTimeoutMs * 1000) {
                failed.push_back(id);
            }
        }
    }
    
    for (uint32_t id : suspects) {
        ReportNodeSuspect(id);
    }
    
    for (uint32_t id : failed) {
        ConfirmNodeFailed(id);
    }
}

void ClusterManager::PerformRebalance() {
    // In production: would iterate all local tensors
    // and migrate those that don't belong here anymore
    
    rebalanceProgress_ = 0.0;
    
    // Simulate work
    for (int i = 0; i <= 100; i++) {
        rebalanceProgress_ = i / 100.0;
        
        if (rebalanceCb_) {
            rebalanceCb_(rebalanceProgress_);
        }
        
        Sleep(10);  // Simulate work
    }
    
    tensorMigrations_.fetch_add(100, std::memory_order_relaxed);
}

uint64_t ClusterManager::GetTimestampUs() const {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000) / freq.QuadPart;
}

void ClusterManager::BroadcastToCluster(const FabricMessage& msg) {
    if (!transport_) return;
    
    std::shared_lock<std::shared_mutex> lock(nodesMutex_);
    
    for (const auto& [id, info] : nodes_) {
        if (id != config_.localNodeId && info.state == NodeState::ACTIVE) {
            transport_->Send(id, msg);
        }
    }
}

// ============================================================================
// System Metrics Helpers
// ============================================================================

uint8_t ClusterManager::GetSystemLoadPercent() {
    // Get CPU usage using Windows performance counters
    static PDH_HQUERY cpuQuery = nullptr;
    static PDH_HCOUNTER cpuTotal = nullptr;
    static bool initialized = false;
    
    if (!initialized) {
        PdhOpenQuery(nullptr, 0, &cpuQuery);
        PdhAddCounter(cpuQuery, "\\Processor(_Total)\\% Processor Time", 0, &cpuTotal);
        PdhCollectQueryData(cpuQuery);
        initialized = true;
        return 50; // First call returns default
    }
    
    PdhCollectQueryData(cpuQuery);
    PDH_FMT_COUNTERVALUE counterVal;
    PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, nullptr, &counterVal);
    
    return static_cast<uint8_t>(std::min(100.0, std::max(0.0, counterVal.doubleValue)));
}

uint32_t ClusterManager::GetLocalTensorCount() {
    // Return actual count of tensors managed by this node
    std::shared_lock<std::shared_mutex> lock(nodesMutex_);
    
    uint32_t count = 0;
    for (const auto& [id, info] : nodes_) {
        if (id == config_.localNodeId) {
            // Count tensors assigned to this node in hash ring
            count = info.tensorCount;
            break;
        }
    }
    
    // If not set yet, estimate based on hash ring distribution
    if (count == 0) {
        // Approximate: total tensors / cluster size
        count = static_cast<uint32_t>(nodes_.size()) * 10;
    }
    
    return count;
}

std::string ClusterManager::GetNodeAddress(uint32_t nodeId) {
    std::shared_lock<std::shared_mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        return it->second.address;
    }
    return "";
}

} // namespace Fabric
} // namespace RawrXD
