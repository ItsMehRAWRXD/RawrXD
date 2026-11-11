// ============================================================================
// HiveSync.cpp - HiveSync RDMA Gossip Protocol Implementation
// ============================================================================

#include "HiveSync.hpp"
#include <cstring>
#include <iostream>
#include <chrono>
#include <thread>
#include <random>

namespace Sovereign {

HiveSync::HiveSync() = default;
HiveSync::~HiveSync() {
    Shutdown();
}

bool HiveSync::Initialize(const HiveConfig& config) {
    config_ = config;
    
    // Generate unique node ID if not set
    if (nodeId_ == 0) {
        std::random_device rd;
        nodeId_ = (static_cast<uint64_t>(rd()) << 32) | rd();
    }
    
    // Add seed nodes
    for (const auto& [addr, port] : config_.seedNodes) {
        HiveNode seed;
        seed.id = 0;
        seed.address = addr;
        seed.port = port;
        seed.state = HiveNodeState::DISCOVERED;
        peers_[0] = seed;
    }
    
    initialized_ = true;
    return true;
}

void HiveSync::Shutdown() {
    Stop();
    initialized_ = false;
}

void HiveSync::Start() {
    if (running_.exchange(true)) return;
    
    gossipThread_ = std::thread(&HiveSync::GossipLoop, this);
    syncThread_ = std::thread(&HiveSync::SyncLoop, this);
    cleanupThread_ = std::thread(&HiveSync::CleanupLoop, this);
}

void HiveSync::Stop() {
    if (!running_.exchange(false)) return;
    
    if (gossipThread_.joinable()) gossipThread_.join();
    if (syncThread_.joinable()) syncThread_.join();
    if (cleanupThread_.joinable()) cleanupThread_.join();
}

bool HiveSync::AddPeer(const std::string& address, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    HiveNode peer;
    peer.id = std::hash<std::string>{}(address + std::to_string(port));
    peer.address = address;
    peer.port = port;
    peer.state = HiveNodeState::DISCOVERED;
    peer.lastSeen = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    peers_[peer.id] = peer;
    stats_.peersDiscovered++;
    return true;
}

bool HiveSync::RemovePeer(uint64_t nodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return peers_.erase(nodeId) > 0;
}

std::vector<HiveNode> HiveSync::GetPeers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HiveNode> result;
    for (const auto& [id, node] : peers_) {
        result.push_back(node);
    }
    return result;
}

bool HiveSync::SendMessage(const HiveMessage& message) {
    // In production: UDP/TCP send to target
    stats_.messagesSent++;
    stats_.bytesSent += message.payload.size();
    return true;
}

bool HiveSync::BroadcastMessage(const HiveMessage& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, node] : peers_) {
        if (node.state == HiveNodeState::ACTIVE) {
            HiveMessage msg = message;
            msg.targetId = id;
            SendMessage(msg);
        }
    }
    return true;
}

void HiveSync::GossipLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.gossipIntervalMs));
        if (!running_.load()) break;
        
        SendGossipUpdate();
    }
}

void HiveSync::SyncLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.syncIntervalMs));
        if (!running_.load()) break;
        
        // Request sync from random active peer
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, node] : peers_) {
            if (node.state == HiveNodeState::ACTIVE) {
                RequestSync(id);
                break;
            }
        }
    }
}

void HiveSync::CleanupLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.cleanupIntervalMs));
        if (!running_.load()) break;
        
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = peers_.begin();
        while (it != peers_.end()) {
            if (now - it->second.lastSeen > config_.failureTimeoutMs) {
                it->second.state = HiveNodeState::DEAD;
                stats_.peersLost++;
                it = peers_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void HiveSync::SendGossipUpdate() {
    HiveMessage msg;
    msg.type = HiveMessageType::GOSSIP;
    msg.senderId = nodeId_;
    msg.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Gossip to random fanout peers
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint64_t> activePeers;
    for (const auto& [id, node] : peers_) {
        if (node.state == HiveNodeState::ACTIVE) activePeers.push_back(id);
    }
    
    if (activePeers.empty()) return;
    
    std::shuffle(activePeers.begin(), activePeers.end(), 
                 std::mt19937(std::random_device{}()));
    
    size_t fanout = std::min(config_.gossipFanout, (uint32_t)activePeers.size());
    for (size_t i = 0; i < fanout; ++i) {
        msg.targetId = activePeers[i];
        SendMessage(msg);
    }
}

void HiveSync::PerformElection() {
    // Bully algorithm
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t highestId = nodeId_;
    for (const auto& [id, node] : peers_) {
        if (node.state == HiveNodeState::ACTIVE && id > highestId) {
            highestId = id;
        }
    }
    
    if (highestId == nodeId_) {
        isCoordinator_ = true;
        coordinatorId_ = nodeId_;
    }
}

HiveStats HiveSync::GetStats() const {
    return stats_;
}

// ============================================================
// ConsensusProtocol
// ============================================================

ConsensusProtocol::ConsensusProtocol() = default;
ConsensusProtocol::~ConsensusProtocol() {
    Shutdown();
}

bool ConsensusProtocol::Initialize(uint64_t nodeId, const std::vector<uint64_t>& clusterNodes) {
    nodeId_ = nodeId;
    clusterNodes_ = clusterNodes;
    return true;
}

void ConsensusProtocol::Shutdown() {
    if (heartbeatThread_.joinable()) heartbeatThread_.join();
}

bool ConsensusProtocol::StartElection() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    currentTerm_++;
    votedFor_ = nodeId_;
    isLeader_ = false;
    
    // Request votes from all other nodes
    uint64_t votes = 1; // Vote for self
    for (uint64_t member : clusterNodes_) {
        if (member != nodeId_) {
            HandleVoteRequest(nodeId_, currentTerm_);
            votes++;
        }
    }
    
    uint64_t majority = clusterNodes_.size() / 2 + 1;
    if (votes >= majority) {
        isLeader_ = true;
        leaderId_ = nodeId_;
        stats_.electionsWon++;
        
        // Start sending heartbeats
        heartbeatThread_ = std::thread(&ConsensusProtocol::HeartbeatLoop, this);
        return true;
    }
    
    return false;
}

bool ConsensusProtocol::AppendEntry(const std::string& command) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!isLeader_) return false;
    
    log_.push_back(command);
    stats_.entriesAppended++;
    return true;
}

bool ConsensusProtocol::CommitEntry(uint64_t index) {
    if (index >= log_.size()) return false;
    
    if (stateMachine_ && stateMachine_(log_[index])) {
        commitIndex_ = index;
        lastApplied_ = index;
        stats_.entriesCommitted++;
        return true;
    }
    return false;
}

void ConsensusProtocol::HeartbeatLoop() {
    while (isLeader_) {
        SendHeartbeat();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ConsensusProtocol::SendHeartbeat() {
    stats_.heartbeatsSent++;
    // In production: send AppendEntries RPC with empty entries
}

ConsensusProtocol::ConsensusStats ConsensusProtocol::GetStats() const {
    ConsensusStats s;
    s.currentTerm = currentTerm_;
    s.electionsStarted = stats_.electionsStarted;
    s.electionsWon = stats_.electionsWon;
    s.entriesAppended = stats_.entriesAppended;
    s.entriesCommitted = stats_.entriesCommitted;
    s.heartbeatsSent = stats_.heartbeatsSent;
    s.heartbeatsReceived = stats_.heartbeatsReceived;
    return s;
}

} // namespace Sovereign
