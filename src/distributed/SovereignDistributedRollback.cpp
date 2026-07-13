// Sovereign Distributed Runtime - Phase D.3 Batch 3/5
// Distributed Rollback Implementation
// Copyright (c) 2026 RawrXD Team

#include "SovereignDistributedRollback.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// RollbackOperation Implementation
// ============================================================================

std::string RollbackOperation::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"rollback_id\":\"" << rollback_id << "\",";
    oss << "\"operation_id\":\"" << operation_id << "\",";
    oss << "\"scope\":" << static_cast<int>(scope) << ",";
    oss << "\"initiator_node\":\"" << initiator_node << "\",";
    oss << "\"target_checkpoint\":\"" << target_checkpoint << "\",";
    oss << "\"reason\":\"" << reason << "\",";
    oss << "\"affected_nodes\":[";
    for (size_t i = 0; i < affected_nodes.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << affected_nodes[i] << "\"";
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

RollbackOperation RollbackOperation::FromJson(const std::string& json) {
    RollbackOperation op;
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
    
    auto extractInt = [&](const std::string& key) -> int {
        size_t keyPos = json.find("\"" + key + "\":");
        if (keyPos == std::string::npos) return 0;
        size_t start = keyPos + key.length() + 3;
        size_t end = json.find_first_of(",}", start);
        if (end == std::string::npos) return 0;
        return std::stoi(json.substr(start, end - start));
    };
    
    op.rollback_id = extractString("rollback_id");
    op.operation_id = extractString("operation_id");
    op.scope = static_cast<RollbackScope>(extractInt("scope"));
    op.initiator_node = extractString("initiator_node");
    op.target_checkpoint = extractString("target_checkpoint");
    op.reason = extractString("reason");
    
    return op;
}

// ============================================================================
// RollbackCheckpoint Implementation
// ============================================================================

std::string RollbackCheckpoint::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"checkpoint_id\":\"" << checkpoint_id << "\",";
    oss << "\"node_id\":\"" << node_id << "\",";
    oss << "\"sequence_number\":" << sequence_number << ",";
    oss << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count() << ",";
    oss << "\"checksum\":\"" << checksum << "\",";
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

// ============================================================================
// RollbackResult Implementation
// ============================================================================

std::string RollbackResult::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"rollback_id\":\"" << rollback_id << "\",";
    oss << "\"success\":" << (success ? "true" : "false") << ",";
    oss << "\"final_phase\":\"" << PhaseToString(final_phase) << "\",";
    oss << "\"completed_nodes\":" << completed_nodes << ",";
    oss << "\"failed_nodes\":" << failed_nodes << ",";
    oss << "\"duration_ms\":" << duration_ms << ",";
    oss << "\"error_message\":\"" << error_message << "\",";
    oss << "\"node_results\":[";
    bool first = true;
    for (const auto& [node, result] : node_results) {
        if (!first) oss << ",";
        oss << "{\"node\":\"" << node << "\",\"success\":" << (result ? "true" : "false") << "}";
        first = false;
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

std::string RollbackResult::PhaseToString(RollbackPhase phase) {
    switch (phase) {
        case RollbackPhase::PREPARE: return "PREPARE";
        case RollbackPhase::EXECUTE: return "EXECUTE";
        case RollbackPhase::VERIFY: return "VERIFY";
        case RollbackPhase::COMPLETE: return "COMPLETE";
        case RollbackPhase::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// DistributedRollbackCoordinator Implementation
// ============================================================================

DistributedRollbackCoordinator::DistributedRollbackCoordinator(const Config& config)
    : config_(config) {
}

DistributedRollbackCoordinator::~DistributedRollbackCoordinator() {
    Shutdown();
}

bool DistributedRollbackCoordinator::Initialize(
    std::shared_ptr<NodeDiscovery> discovery,
    std::shared_ptr<ConsensusEngine> consensus) {
    discovery_ = discovery;
    consensus_ = consensus;
    running_ = true;
    
    // Start coordinator thread
    coordinator_thread_ = std::thread(
        &DistributedRollbackCoordinator::CoordinatorLoop, this);
    
    return true;
}

void DistributedRollbackCoordinator::Shutdown() {
    running_ = false;
    
    if (coordinator_thread_.joinable()) {
        coordinator_thread_.join();
    }
}

std::string DistributedRollbackCoordinator::InitiateRollback(
    const RollbackOperation& operation) {
    std::string rollback_id = operation.rollback_id;
    if (rollback_id.empty()) {
        rollback_id = GenerateRollbackId();
    }
    
    RollbackContext context;
    context.operation = operation;
    context.operation.rollback_id = rollback_id;
    context.current_phase = RollbackPhase::PREPARE;
    context.start_time = std::chrono::steady_clock::now();
    
    // Determine affected nodes based on scope
    auto topology = discovery_->GetTopology();
    auto nodes = topology->GetHealthyNodes();
    
    switch (operation.scope) {
        case RollbackScope::LOCAL:
            // Only this node
            context.operation.affected_nodes = {discovery_->GetTopology()->GetHealthyNodes()[0].node_id};
            break;
        case RollbackScope::PARTITION:
            // Nodes in same datacenter/rack
            context.operation.affected_nodes.clear();
            for (const auto& node : nodes) {
                if (node.datacenter == operation.initiator_node) {
                    context.operation.affected_nodes.push_back(node.node_id);
                }
            }
            break;
        case RollbackScope::CLUSTER:
        case RollbackScope::GLOBAL:
            // All healthy nodes
            context.operation.affected_nodes.clear();
            for (const auto& node : nodes) {
                context.operation.affected_nodes.push_back(node.node_id);
            }
            break;
    }
    
    // For cluster/global scope, require consensus
    if (operation.scope == RollbackScope::CLUSTER || 
        operation.scope == RollbackScope::GLOBAL) {
        SafetyProposal proposal;
        proposal.proposal_id = "rollback-" + rollback_id;
        proposal.operation_id = operation.operation_id;
        proposal.proposer_node = operation.initiator_node;
        proposal.proposed_decision = SafetyDecision::ROLLBACK;
        proposal.priority = SafetyPriority::CRITICAL;
        proposal.context = "Rollback: " + operation.reason;
        proposal.affected_nodes = context.operation.affected_nodes;
        
        auto commit = consensus_->Propose(proposal);
        if (!commit.committed) {
            RollbackResult result;
            result.rollback_id = rollback_id;
            result.success = false;
            result.final_phase = RollbackPhase::FAILED;
            result.error_message = "Consensus failed: " + commit.rationale;
            
            std::lock_guard<std::mutex> lock(results_mutex_);
            results_[rollback_id] = result;
            return rollback_id;
        }
    }
    
    // Store context and start rollback
    {
        std::lock_guard<std::mutex> lock(contexts_mutex_);
        contexts_[rollback_id] = context;
    }
    
    // Execute rollback phases
    ExecuteRollbackPhases(rollback_id);
    
    return rollback_id;
}

RollbackResult DistributedRollbackCoordinator::GetRollbackResult(
    const std::string& rollback_id) const {
    std::lock_guard<std::mutex> lock(results_mutex_);
    auto it = results_.find(rollback_id);
    if (it != results_.end()) {
        return it->second;
    }
    
    // Return in-progress result
    RollbackResult result;
    result.rollback_id = rollback_id;
    result.success = false;
    result.final_phase = RollbackPhase::PREPARE;
    result.error_message = "Rollback in progress";
    return result;
}

std::vector<RollbackCheckpoint> DistributedRollbackCoordinator::GetCheckpoints(
    const std::string& node_id) const {
    std::lock_guard<std::mutex> lock(checkpoints_mutex_);
    
    auto it = checkpoints_.find(node_id);
    if (it != checkpoints_.end()) {
        return it->second;
    }
    
    return {};
}

RollbackCheckpoint DistributedRollbackCoordinator::GetLatestCheckpoint(
    const std::string& node_id) const {
    auto checkpoints = GetCheckpoints(node_id);
    if (!checkpoints.empty()) {
        return checkpoints.back();
    }
    return {};
}

bool DistributedRollbackCoordinator::CreateCheckpoint(
    const RollbackCheckpoint& checkpoint) {
    std::lock_guard<std::mutex> lock(checkpoints_mutex_);
    
    auto& node_checkpoints = checkpoints_[checkpoint.node_id];
    
    // Check for duplicate
    for (const auto& cp : node_checkpoints) {
        if (cp.checkpoint_id == checkpoint.checkpoint_id) {
            return false;
        }
    }
    
    node_checkpoints.push_back(checkpoint);
    
    // Prune old checkpoints
    while (node_checkpoints.size() > static_cast<size_t>(config_.max_checkpoints)) {
        node_checkpoints.erase(node_checkpoints.begin());
    }
    
    return true;
}

void DistributedRollbackCoordinator::OnRollbackComplete(
    std::function<void(const RollbackResult&)> callback) {
    on_complete_ = callback;
}

void DistributedRollbackCoordinator::CoordinatorLoop() {
    while (running_) {
        // Process active rollbacks
        std::vector<std::string> active_ids;
        {
            std::lock_guard<std::mutex> lock(contexts_mutex_);
            for (const auto& [id, context] : contexts_) {
                if (context.current_phase != RollbackPhase::COMPLETE &&
                    context.current_phase != RollbackPhase::FAILED) {
                    active_ids.push_back(id);
                }
            }
        }
        
        for (const auto& id : active_ids) {
            ProcessRollbackPhase(id);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void DistributedRollbackCoordinator::ExecuteRollbackPhases(
    const std::string& rollback_id) {
    RollbackContext context;
    {
        std::lock_guard<std::mutex> lock(contexts_mutex_);
        auto it = contexts_.find(rollback_id);
        if (it == contexts_.end()) {
            return;
        }
        context = it->second;
    }
    
    // Phase 1: PREPARE
    if (!ExecutePreparePhase(rollback_id)) {
        FailRollback(rollback_id, "Prepare phase failed");
        return;
    }
    
    // Phase 2: EXECUTE
    if (!ExecuteExecutePhase(rollback_id)) {
        FailRollback(rollback_id, "Execute phase failed");
        return;
    }
    
    // Phase 3: VERIFY
    if (!ExecuteVerifyPhase(rollback_id)) {
        FailRollback(rollback_id, "Verify phase failed");
        return;
    }
    
    // Complete
    CompleteRollback(rollback_id);
}

bool DistributedRollbackCoordinator::ExecutePreparePhase(
    const std::string& rollback_id) {
    RollbackContext context;
    {
        std::lock_guard<std::mutex> lock(contexts_mutex_);
        auto it = contexts_.find(rollback_id);
        if (it == contexts_.end()) {
            return false;
        }
        context = it->second;
        it->second.current_phase = RollbackPhase::PREPARE;
    }
    
    // Send prepare to all affected nodes
    for (const auto& node_id : context.operation.affected_nodes) {
        if (!SendPrepareToNode(node_id, context.operation)) {
            return false;
        }
    }
    
    // Wait for prepare acknowledgments
    auto start = std::chrono::steady_clock::now();
    while (true) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() >
            config_.prepare_timeout_ms) {
            return false;
        }
        
        // Check if all nodes prepared
        bool all_prepared = true;
        {
            std::lock_guard<std::mutex> lock(contexts_mutex_);
            auto it = contexts_.find(rollback_id);
            if (it != contexts_.end()) {
                for (const auto& node_id : context.operation.affected_nodes) {
                    if (it->second.node_results.find(node_id) == it->second.node_results.end()) {
                        all_prepared = false;
                        break;
                    }
                }
            }
        }
        
        if (all_prepared) {
            return true;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool DistributedRollbackCoordinator::ExecuteExecutePhase(
    const std::string& rollback_id) {
    {
        std::lock_guard<std::mutex> lock(contexts_mutex_);
        auto it = contexts_.find(rollback_id);
        if (it != contexts_.end()) {
            it->second.current_phase = RollbackPhase::EXECUTE;
        }
    }
    
    // Send execute to all affected nodes
    // Implementation similar to prepare phase
    return true;
}

bool DistributedRollbackCoordinator::ExecuteVerifyPhase(
    const std::string& rollback_id) {
    {
        std::lock_guard<std::mutex> lock(contexts_mutex_);
        auto it = contexts_.find(rollback_id);
        if (it != contexts_.end()) {
            it->second.current_phase = RollbackPhase::VERIFY;
        }
    }
    
    // Verify rollback on all affected nodes
    // Implementation similar to prepare phase
    return true;
}

void DistributedRollbackCoordinator::ProcessRollbackPhase(
    const std::string& rollback_id) {
    // Process phase transitions
}

void DistributedRollbackCoordinator::CompleteRollback(
    const std::string& rollback_id) {
    RollbackContext context;
    {
        std::lock_guard<std::mutex> lock(contexts_mutex_);
        auto it = contexts_.find(rollback_id);
        if (it == contexts_.end()) {
            return;
        }
        context = it->second;
        it->second.current_phase = RollbackPhase::COMPLETE;
    }
    
    RollbackResult result;
    result.rollback_id = rollback_id;
    result.success = true;
    result.final_phase = RollbackPhase::COMPLETE;
    result.completed_nodes = context.operation.affected_nodes.size();
    result.failed_nodes = 0;
    result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - context.start_time).count();
    result.node_results = context.node_results;
    
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        results_[rollback_id] = result;
    }
    
    if (on_complete_) {
        on_complete_(result);
    }
}

void DistributedRollbackCoordinator::FailRollback(
    const std::string& rollback_id, const std::string& reason) {
    RollbackContext context;
    {
        std::lock_guard<std::mutex> lock(contexts_mutex_);
        auto it = contexts_.find(rollback_id);
        if (it != contexts_.end()) {
            context = it->second;
            it->second.current_phase = RollbackPhase::FAILED;
        }
    }
    
    RollbackResult result;
    result.rollback_id = rollback_id;
    result.success = false;
    result.final_phase = RollbackPhase::FAILED;
    result.error_message = reason;
    result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - context.start_time).count();
    
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        results_[rollback_id] = result;
    }
    
    if (on_complete_) {
        on_complete_(result);
    }
}

bool DistributedRollbackCoordinator::SendPrepareToNode(
    const std::string& node_id, const RollbackOperation& operation) {
    // Placeholder - in production, send via network
    return true;
}

std::string DistributedRollbackCoordinator::GenerateRollbackId() {
    static std::atomic<int64_t> counter{0};
    int64_t id = counter.fetch_add(1);
    
    std::ostringstream oss;
    oss << "rollback-" << id << "-" << 
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    return oss.str();
}

// ============================================================================
// LocalRollbackHandler Implementation
// ============================================================================

LocalRollbackHandler::LocalRollbackHandler() {
}

LocalRollbackHandler::~LocalRollbackHandler() {
}

bool LocalRollbackHandler::RegisterComponent(
    const std::string& component_name,
    CheckpointCallback checkpoint_cb,
    RollbackCallback rollback_cb) {
    std::lock_guard<std::mutex> lock(components_mutex_);
    
    ComponentCallbacks callbacks;
    callbacks.checkpoint = checkpoint_cb;
    callbacks.rollback = rollback_cb;
    
    components_[component_name] = callbacks;
    return true;
}

bool LocalRollbackHandler::UnregisterComponent(const std::string& component_name) {
    std::lock_guard<std::mutex> lock(components_mutex_);
    return components_.erase(component_name) > 0;
}

RollbackCheckpoint LocalRollbackHandler::CreateCheckpoint(
    const std::string& component_name) {
    std::lock_guard<std::mutex> lock(components_mutex_);
    
    auto it = components_.find(component_name);
    if (it != components_.end() && it->second.checkpoint) {
        return it->second.checkpoint();
    }
    
    return {};
}

bool LocalRollbackHandler::ExecuteRollback(
    const std::string& component_name,
    const RollbackCheckpoint& checkpoint) {
    std::lock_guard<std::mutex> lock(components_mutex_);
    
    auto it = components_.find(component_name);
    if (it != components_.end() && it->second.rollback) {
        return it->second.rollback(checkpoint);
    }
    
    return false;
}

std::vector<std::string> LocalRollbackHandler::GetRegisteredComponents() const {
    std::lock_guard<std::mutex> lock(components_mutex_);
    
    std::vector<std::string> names;
    for (const auto& [name, _] : components_) {
        names.push_back(name);
    }
    return names;
}

} // namespace Distributed
} // namespace Sovereign
