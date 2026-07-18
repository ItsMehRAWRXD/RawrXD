// Sovereign Distributed Runtime - Phase D.3 Batch 4/5
// State Replication Implementation
// Copyright (c) 2026 RawrXD Team

#include "SovereignStateReplication.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <zlib.h>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// ReplicatedState Implementation
// ============================================================================

std::string ReplicatedState::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"state_id\":\"" << state_id << "\",";
    oss << "\"state_type\":\"" << state_type << "\",";
    oss << "\"node_id\":\"" << node_id << "\",";
    oss << "\"version\":" << version << ",";
    oss << "\"checksum\":\"" << checksum << "\",";
    oss << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count() << ",";
    oss << "\"data\":\"";
    // Base64 encode data
    for (const auto& byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    oss << "\",";
    oss << "\"metadata\":{";
    bool first = true;
    for (const auto& [key, value] : metadata) {
        if (!first) oss << ",";
        oss << "\"" << key << "\":\"" << value << "\"";
        first = false;
    }
    oss << "}";
    oss << "}";
    return oss.str();
}

ReplicatedState ReplicatedState::FromJson(const std::string& json) {
    ReplicatedState state;
    // Simple JSON parsing
    auto extractString = [&](const std::string& key) -> std::string {
        size_t keyPos = json.find("\"" + key + "\":");
        if (keyPos == std::string::npos) return "";
        size_t start = json.find("\"", keyPos + key.length() + 3);
        if (start == std::string::npos) return "";
        size_t end = json.find("\"", start + 1);
        if (end == std::string::npos) return "";
        return json.substr(start + 1, end - start - 1);
    };
    
    auto extractInt = [&](const std::string& key) -> int64_t {
        size_t keyPos = json.find("\"" + key + "\":");
        if (keyPos == std::string::npos) return 0;
        size_t start = keyPos + key.length() + 3;
        size_t end = json.find_first_of(",}", start);
        if (end == std::string::npos) return 0;
        return std::stoll(json.substr(start, end - start));
    };
    
    state.state_id = extractString("state_id");
    state.state_type = extractString("state_type");
    state.node_id = extractString("node_id");
    state.version = extractInt("version");
    state.checksum = extractString("checksum");
    
    return state;
}

// ============================================================================
// StateReplicationEngine Implementation
// ============================================================================

StateReplicationEngine::StateReplicationEngine(const Config& config) : config_(config) {
}

StateReplicationEngine::~StateReplicationEngine() {
    Shutdown();
}

bool StateReplicationEngine::Initialize(std::shared_ptr<NodeDiscovery> discovery) {
    discovery_ = discovery;
    running_ = true;
    
    // Start sync thread
    sync_thread_ = std::thread(&StateReplicationEngine::SyncLoop, this);
    
    return true;
}

void StateReplicationEngine::Shutdown() {
    running_ = false;
    
    if (sync_thread_.joinable()) {
        sync_thread_.join();
    }
}

bool StateReplicationEngine::PublishState(const ReplicatedState& state) {
    // Store locally
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        local_state_[state.state_id] = state;
    }
    
    // Replicate to other nodes based on strategy
    switch (config_.strategy) {
        case ReplicationStrategy::PRIMARY_BACKUP:
            // Replicate to backup nodes
            if (IsPrimary()) {
                ReplicateToBackups(state);
            }
            break;
            
        case ReplicationStrategy::MULTI_MASTER:
            // Replicate to all other nodes
            ReplicateToAllNodes(state);
            break;
            
        case ReplicationStrategy::QUORUM:
            // Replicate to quorum
            ReplicateToQuorum(state);
            break;
            
        case ReplicationStrategy::STATE_MACHINE:
            // Append to replication log
            AppendToLog(state);
            break;
    }
    
    return true;
}

bool StateReplicationEngine::UpdateState(const ReplicatedState& state) {
    // Increment version
    ReplicatedState updated = state;
    updated.version++;
    updated.timestamp = std::chrono::steady_clock::now();
    
    return PublishState(updated);
}

bool StateReplicationEngine::DeleteState(const std::string& state_id) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return local_state_.erase(state_id) > 0;
}

ReplicatedState StateReplicationEngine::GetState(const std::string& state_id) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    auto it = local_state_.find(state_id);
    if (it != local_state_.end()) {
        return it->second;
    }
    
    // Try to fetch from remote
    auto nodes = discovery_->GetTopology()->GetHealthyNodes();
    for (const auto& node : nodes) {
        if (node.node_id != discovery_->GetTopology()->GetHealthyNodes()[0].node_id) {
            auto remote = RequestState(node.node_id, state_id);
            if (!remote.state_id.empty()) {
                // Cache it
                remote_state_cache_[node.node_id][state_id] = remote;
                return remote;
            }
        }
    }
    
    return {};
}

std::vector<ReplicatedState> StateReplicationEngine::GetStatesByType(
    const std::string& state_type) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    std::vector<ReplicatedState> result;
    for (const auto& [id, state] : local_state_) {
        if (state.state_type == state_type) {
            result.push_back(state);
        }
    }
    return result;
}

ReplicatedState StateReplicationEngine::GetStateFromNode(
    const std::string& state_id, const std::string& node_id) {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        auto node_it = remote_state_cache_.find(node_id);
        if (node_it != remote_state_cache_.end()) {
            auto state_it = node_it->second.find(state_id);
            if (state_it != node_it->second.end()) {
                return state_it->second;
            }
        }
    }
    
    return RequestState(node_id, state_id);
}

bool StateReplicationEngine::SyncState(const std::string& state_id) {
    auto state = GetState(state_id);
    if (state.state_id.empty()) {
        return false;
    }
    
    // Replicate to all nodes
    auto nodes = discovery_->GetTopology()->GetHealthyNodes();
    bool success = true;
    
    for (const auto& node : nodes) {
        if (node.node_id != state.node_id) {
            if (!ReplicateToNode(node.node_id, state)) {
                success = false;
            }
        }
    }
    
    return success;
}

bool StateReplicationEngine::SyncAll() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    bool success = true;
    for (const auto& [id, state] : local_state_) {
        if (!SyncState(id)) {
            success = false;
        }
    }
    
    return success;
}

int64_t StateReplicationEngine::GetLatestSequenceNumber() const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    return sequence_counter_;
}

void StateReplicationEngine::SetConflictResolver(
    const std::string& state_type, ConflictResolver resolver) {
    std::lock_guard<std::mutex> lock(resolver_mutex_);
    conflict_resolvers_[state_type] = resolver;
}

void StateReplicationEngine::OnStateChange(StateChangeCallback cb) {
    on_state_change_ = cb;
}

StateReplicationEngine::Stats StateReplicationEngine::GetStats() const {
    Stats stats;
    
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        stats.states_published = local_state_.size();
    }
    
    stats.states_replicated = replication_count_.load();
    
    int64_t total_latency = total_replication_latency_us_.load();
    int64_t count = replication_count_.load();
    if (count > 0) {
        stats.avg_replication_latency_ms = (total_latency / count) / 1000.0;
    }
    
    stats.bytes_transferred = bytes_transferred_.load();
    
    return stats;
}

void StateReplicationEngine::SyncLoop() {
    while (running_) {
        // Periodic sync based on consistency level
        if (config_.consistency == ConsistencyLevel::BOUNDED) {
            SyncAll();
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.sync_interval_ms));
    }
}

bool StateReplicationEngine::ReplicateToNode(
    const std::string& node_id, const ReplicatedState& state) {
    auto start = std::chrono::steady_clock::now();
    
    bool success = SendState(node_id, state);
    
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    
    total_replication_latency_us_ += elapsed_us;
    replication_count_++;
    bytes_transferred_ += state.data.size();
    
    return success;
}

bool StateReplicationEngine::ApplyRemoteState(const ReplicatedState& state) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    auto it = local_state_.find(state.state_id);
    if (it != local_state_.end()) {
        // Conflict detected
        if (it->second.version < state.version) {
            // Remote is newer
            local_state_[state.state_id] = state;
        } else if (it->second.version > state.version) {
            // Local is newer - conflict
            auto resolved = ResolveConflict(it->second, state);
            local_state_[state.state_id] = resolved;
        }
        // Same version - no change
    } else {
        // New state
        local_state_[state.state_id] = state;
    }
    
    if (on_state_change_) {
        on_state_change_(state);
    }
    
    return true;
}

ReplicatedState StateReplicationEngine::ResolveConflict(
    const ReplicatedState& local, const ReplicatedState& remote) {
    std::lock_guard<std::mutex> lock(resolver_mutex_);
    
    auto it = conflict_resolvers_.find(local.state_type);
    if (it != conflict_resolvers_.end()) {
        return it->second(local, remote);
    }
    
    // Default: last-write-wins
    if (local.timestamp > remote.timestamp) {
        return local;
    }
    return remote;
}

std::vector<std::string> StateReplicationEngine::SelectReplicationTargets() {
    auto nodes = discovery_->GetTopology()->GetHealthyNodes();
    std::vector<std::string> targets;
    
    for (const auto& node : nodes) {
        if (node.node_id != discovery_->GetTopology()->GetHealthyNodes()[0].node_id) {
            targets.push_back(node.node_id);
        }
    }
    
    return targets;
}

bool StateReplicationEngine::IsQuorumAvailable() {
    return discovery_->GetTopology()->HasQuorum();
}

bool StateReplicationEngine::SendState(
    const std::string& node_id, const ReplicatedState& state) {
    // Placeholder - in production, send via network
    return true;
}

ReplicatedState StateReplicationEngine::RequestState(
    const std::string& node_id, const std::string& state_id) {
    // Placeholder - in production, request via network
    return {};
}

bool StateReplicationEngine::IsPrimary() {
    return discovery_->IsLeader();
}

void StateReplicationEngine::ReplicateToBackups(const ReplicatedState& state) {
    auto targets = SelectReplicationTargets();
    for (const auto& node_id : targets) {
        ReplicateToNode(node_id, state);
    }
}

void StateReplicationEngine::ReplicateToAllNodes(const ReplicatedState& state) {
    auto targets = SelectReplicationTargets();
    for (const auto& node_id : targets) {
        ReplicateToNode(node_id, state);
    }
}

void StateReplicationEngine::ReplicateToQuorum(const ReplicatedState& state) {
    auto targets = SelectReplicationTargets();
    int quorum = discovery_->GetTopology()->GetQuorumSize();
    
    int replicated = 0;
    for (const auto& node_id : targets) {
        if (ReplicateToNode(node_id, state)) {
            replicated++;
            if (replicated >= quorum) {
                break;
            }
        }
    }
}

void StateReplicationEngine::AppendToLog(const ReplicatedState& state) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    ReplicationEntry entry;
    entry.sequence_number = ++sequence_counter_;
    entry.operation = "UPDATE";
    entry.state = state;
    entry.committed = false;
    
    replication_log_.push_back(entry);
    
    // Trim log if too large
    while (replication_log_.size() > static_cast<size_t>(config_.batch_size * 10)) {
        replication_log_.erase(replication_log_.begin());
    }
}

// ============================================================================
// DistributedMemorySync Implementation
// ============================================================================

DistributedMemorySync::DistributedMemorySync(const Config& config) : config_(config) {
}

bool DistributedMemorySync::Initialize(std::shared_ptr<StateReplicationEngine> replication) {
    replication_ = replication;
    return true;
}

bool DistributedMemorySync::StoreMemory(
    const std::string& key, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(memory_mutex_);
    
    MemoryEntry entry;
    entry.data = data;
    entry.access_count = 1;
    entry.last_access = std::chrono::steady_clock::now();
    
    memory_cache_[key] = entry;
    
    // Replicate if configured
    ReplicatedState state;
    state.state_id = "memory:" + key;
    state.state_type = "memory";
    state.data = data;
    state.timestamp = std::chrono::steady_clock::now();
    
    replication_->PublishState(state);
    
    return true;
}

std::vector<uint8_t> DistributedMemorySync::RetrieveMemory(const std::string& key) {
    std::lock_guard<std::mutex> lock(memory_mutex_);
    
    auto it = memory_cache_.find(key);
    if (it != memory_cache_.end()) {
        it->second.access_count++;
        it->second.last_access = std::chrono::steady_clock::now();
        local_hits_++;
        return it->second.data;
    }
    
    // Try to fetch from remote
    auto state = replication_->GetState("memory:" + key);
    if (!state.state_id.empty()) {
        MemoryEntry entry;
        entry.data = state.data;
        entry.access_count = 1;
        entry.last_access = std::chrono::steady_clock::now();
        memory_cache_[key] = entry;
        
        remote_fetches_++;
        return state.data;
    }
    
    return {};
}

bool DistributedMemorySync::InvalidateMemory(const std::string& key) {
    std::lock_guard<std::mutex> lock(memory_mutex_);
    return memory_cache_.erase(key) > 0;
}

bool DistributedMemorySync::WarmCache(const std::string& node_id) {
    // Fetch frequently accessed memories from remote node
    // Placeholder implementation
    return true;
}

bool DistributedMemorySync::EvictFromCache(
    const std::string& key, const std::string& node_id) {
    // Evict from specific node's cache
    // Placeholder implementation
    return true;
}

DistributedMemorySync::Stats DistributedMemorySync::GetStats() const {
    Stats stats;
    stats.local_hits = local_hits_.load();
    stats.remote_fetches = remote_fetches_.load();
    stats.syncs_completed = syncs_completed_.load();
    
    int64_t total = stats.local_hits + stats.remote_fetches;
    if (total > 0) {
        stats.cache_hit_ratio = static_cast<double>(stats.local_hits) / total;
    }
    
    return stats;
}

} // namespace Distributed
} // namespace Sovereign
