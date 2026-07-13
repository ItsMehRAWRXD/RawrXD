/**
 * FaultDetector.cpp
 *
 * Phase D.3 Batch 5/5: Fault Tolerance & Recovery
 *
 * Implementation of fault detection and recovery coordination.
 */

#include "FaultDetector.hpp"
#include "../core/Logger.hpp"
#include "../core/ErrorCodes.hpp"
#include <chrono>
#include <math>

namespace Distributed {

// ============================================================================
// String Helpers
// ============================================================================

std::string FaultTypeToString(FaultType type) {
    switch (type) {
        case FaultType::NODE_CRASH:          return "node_crash";
        case FaultType::NODE_UNRESPONSIVE:   return "node_unresponsive";
        case FaultType::NETWORK_PARTITION:   return "network_partition";
        case FaultType::SLOW_NODE:          return "slow_node";
        case FaultType::RESOURCE_EXHAUSTION: return "resource_exhaustion";
        case FaultType::BYZANTINE_FAULT:    return "byzantine_fault";
        case FaultType::DISK_FAILURE:        return "disk_failure";
        case FaultType::MEMORY_CORRUPTION:   return "memory_corruption";
        default: return "unknown";
    }
}

// ============================================================================
// FaultEvent Implementation
// ============================================================================

std::string FaultEvent::ToJson() const {
    std::string json = "{";
    json += "\"faultId\":\"" + faultId + "\",";
    json += "\"type\":\"" + FaultTypeToString(type) + "\",";
    json += "\"severity\":" + std::to_string(static_cast<int>(severity)) + ",";
    json += "\"nodeId\":\"" + nodeId + "\",";
    json += "\"description\":\"" + description + "\",";
    json += "\"timestamp\":" + std::to_string(timestamp) + ",";
    json += "\"isConfirmed\":" + std::string(isConfirmed ? "true" : "false");
    json += "}";
    return json;
}

FaultEvent FaultEvent::FromJson(const std::string& json) {
    FaultEvent event;
    // Simplified parsing
    return event;
}

// ============================================================================
// NodeHealth Implementation
// ============================================================================

std::string NodeHealth::ToJson() const {
    std::string statusStr;
    switch (status) {
        case Status::HEALTHY:   statusStr = "healthy"; break;
        case Status::SUSPECTED: statusStr = "suspected"; break;
        case Status::UNHEALTHY: statusStr = "unhealthy"; break;
        case Status::ISOLATED:  statusStr = "isolated"; break;
    }
    
    std::string json = "{";
    json += "\"nodeId\":\"" + nodeId + "\",";
    json += "\"status\":\"" + statusStr + "\",";
    json += "\"phiValue\":" + std::to_string(phiValue) + ",";
    json += "\"lastHeartbeat\":" + std::to_string(lastHeartbeat) + ",";
    json += "\"consecutiveMisses\":" + std::to_string(consecutiveMisses);
    json += "}";
    return json;
}

// ============================================================================
// Phi Accrual Detector Implementation
// ============================================================================

PhiAccrualDetector::PhiAccrualDetector(const DetectorConfig& config) : config_(config) {}

PhiAccrualDetector::~PhiAccrualDetector() {
    Shutdown();
}

bool PhiAccrualDetector::Initialize() {
    return true;
}

void PhiAccrualDetector::Shutdown() {}

void PhiAccrualDetector::ReportHeartbeat(const std::string& nodeId, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& history = histories_[nodeId];
    
    if (history.lastTimestamp > 0) {
        uint64_t interval = timestamp - history.lastTimestamp;
        UpdateStatistics(history, interval);
    }
    
    history.lastTimestamp = timestamp;
}

double PhiAccrualDetector::CalculatePhi(const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = histories_.find(nodeId);
    if (it == histories_.end()) {
        return 0.0;
    }
    
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return CalculatePhiValue(it->second, now);
}

bool PhiAccrualDetector::IsSuspected(const std::string& nodeId) const {
    return CalculatePhi(nodeId) >= config_.phiThreshold;
}

bool PhiAccrualDetector::IsFailed(const std::string& nodeId) const {
    double phi = CalculatePhi(nodeId);
    return phi >= config_.phiThreshold * 2;  // Higher threshold for confirmed failure
}

std::optional<NodeHealth> PhiAccrualDetector::GetNodeHealth(const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = histories_.find(nodeId);
    if (it == histories_.end()) {
        return std::nullopt;
    }
    
    NodeHealth health;
    health.nodeId = nodeId;
    health.phiValue = CalculatePhiValue(it->second,
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    health.lastHeartbeat = it->second.lastTimestamp;
    
    if (IsFailed(nodeId)) {
        health.status = NodeHealth::Status::UNHEALTHY;
    } else if (IsSuspected(nodeId)) {
        health.status = NodeHealth::Status::SUSPECTED;
    } else {
        health.status = NodeHealth::Status::HEALTHY;
    }
    
    return health;
}

std::vector<NodeHealth> PhiAccrualDetector::GetAllNodeHealth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<NodeHealth> result;
    for (const auto& [nodeId, history] : histories_) {
        auto health = GetNodeHealth(nodeId);
        if (health) {
            result.push_back(*health);
        }
    }
    return result;
}

void PhiAccrualDetector::RemoveNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    histories_.erase(nodeId);
}

void PhiAccrualDetector::UpdateStatistics(HeartbeatHistory& history, uint64_t interval) {
    history.intervals.push_back(interval);
    
    // Keep window size limited
    while (history.intervals.size() > config_.phiWindowSize) {
        history.intervals.pop_front();
    }
    
    // Calculate mean and variance
    if (history.intervals.size() >= 2) {
        double sum = 0.0;
        for (uint64_t val : history.intervals) {
            sum += val;
        }
        history.mean = sum / history.intervals.size();
        
        double varianceSum = 0.0;
        for (uint64_t val : history.intervals) {
            double diff = val - history.mean;
            varianceSum += diff * diff;
        }
        history.variance = varianceSum / history.intervals.size();
    }
}

double PhiAccrualDetector::CalculatePhiValue(
    const HeartbeatHistory& history,
    uint64_t now
) const {
    if (history.intervals.size() < 2 || history.mean == 0) {
        return 0.0;
    }
    
    uint64_t timeSinceLast = now - history.lastTimestamp;
    
    // Calculate phi using exponential distribution assumption
    // phi = -log10(P(X > timeSinceLast))
    // For exponential: P(X > t) = exp(-t/mean)
    
    double probability = std::exp(-static_cast<double>(timeSinceLast) / history.mean);
    
    // Avoid log(0)
    if (probability < 1e-10) {
        return 100.0;
    }
    
    return -std::log10(probability);
}

// ============================================================================
// Gossip Protocol Implementation
// ============================================================================

GossipProtocol::GossipProtocol(
    std::shared_ptr<CommunicationManager> commManager,
    const DetectorConfig& config
) : commManager_(commManager), config_(config) {}

GossipProtocol::~GossipProtocol() {
    Shutdown();
}

bool GossipProtocol::Initialize() {
    running_ = true;
    gossipThread_ = std::thread(&GossipProtocol::GossipLoop, this);
    return true;
}

void GossipProtocol::Shutdown() {
    running_ = false;
    
    if (gossipThread_.joinable()) {
        gossipThread_.join();
    }
}

void GossipProtocol::SpreadSuspicion(const std::string& nodeId, const std::string& reason) {
    Message msg;
    msg.header.type = MessageType::HEARTBEAT;  // Reuse heartbeat for gossip
    msg.header.flags = 0x01;  // Suspicion flag
    msg.payload = "{\"suspect\":\"" + nodeId + "\",\"reason\":\"" + reason + "\"}";
    
    auto targets = SelectGossipTargets();
    for (const auto& target : targets) {
        commManager_->SendMessage(target, msg);
    }
}

void GossipProtocol::SpreadConfirmation(const FaultEvent& fault) {
    Message msg;
    msg.header.type = MessageType::HEARTBEAT;
    msg.header.flags = 0x02;  // Confirmation flag
    msg.payload = fault.ToJson();
    
    auto targets = SelectGossipTargets();
    for (const auto& target : targets) {
        commManager_->SendMessage(target, msg);
    }
}

void GossipProtocol::SpreadRecovery(const std::string& nodeId) {
    Message msg;
    msg.header.type = MessageType::HEARTBEAT;
    msg.header.flags = 0x04;  // Recovery flag
    msg.payload = "{\"recovered\":\"" + nodeId + "\"}";
    
    auto targets = SelectGossipTargets();
    for (const auto& target : targets) {
        commManager_->SendMessage(target, msg);
    }
}

std::map<std::string, NodeHealth> GossipProtocol::GetGossipState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return gossipState_;
}

void GossipProtocol::OnSuspicion(SuspicionCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    suspicionCallback_ = callback;
}

void GossipProtocol::OnConfirmation(ConfirmationCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    confirmationCallback_ = callback;
}

void GossipProtocol::GossipLoop() {
    while (running_) {
        // Periodic gossip
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.gossipIntervalMs));
        
        if (!running_) break;
        
        // Share gossip state with random peers
        auto targets = SelectGossipTargets();
        for (const auto& target : targets) {
            Message msg;
            msg.header.type = MessageType::HEARTBEAT;
            msg.header.flags = 0x08;  // Gossip sync flag
            
            // Serialize gossip state
            std::string payload = "{";
            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (const auto& [id, health] : gossipState_) {
                    if (!payload.empty() && payload != "{") payload += ",";
                    payload += "\"" + id + "\":" + health.ToJson();
                }
            }
            payload += "}";
            
            msg.payload = payload;
            commManager_->SendMessage(target, msg);
        }
    }
}

void GossipProtocol::HandleGossipMessage(const Message& message) {
    // Parse and update gossip state
    // Simplified implementation
}

void GossipProtocol::HandleSuspicion(const std::string& nodeId, const std::string& reason) {
    NotifySuspicion(nodeId, reason);
}

void GossipProtocol::HandleConfirmation(const FaultEvent& fault) {
    NotifyConfirmation(fault);
}

std::vector<std::string> GossipProtocol::SelectGossipTargets() {
    // Get connected nodes and select random subset
    auto nodes = commManager_->GetConnectedNodes();
    std::vector<std::string> targets;
    
    for (const auto& node : nodes) {
        targets.push_back(node.nodeId);
    }
    
    // Shuffle and take fanout
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(targets.begin(), targets.end(), gen);
    
    if (targets.size() > config_.gossipFanout) {
        targets.resize(config_.gossipFanout);
    }
    
    return targets;
}

void GossipProtocol::NotifySuspicion(const std::string& nodeId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (suspicionCallback_) {
        suspicionCallback_(nodeId, reason);
    }
}

void GossipProtocol::NotifyConfirmation(const FaultEvent& fault) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (confirmationCallback_) {
        confirmationCallback_(fault);
    }
}

// ============================================================================
// Partition Detector Implementation
// ============================================================================

PartitionDetector::PartitionDetector(
    std::shared_ptr<CommunicationManager> commManager,
    const DetectorConfig& config
) : commManager_(commManager), config_(config) {}

PartitionDetector::~PartitionDetector() = default;

bool PartitionDetector::Initialize() {
    return true;
}

void PartitionDetector::Shutdown() {}

bool PartitionDetector::IsPartitioned() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !unreachableNodes_.empty();
}

bool PartitionDetector::IsInMajorityPartition() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return IsMajority(reachableNodes_.size(),
                      reachableNodes_.size() + unreachableNodes_.size());
}

std::vector<std::string> PartitionDetector::GetReachableNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<std::string>(reachableNodes_.begin(), reachableNodes_.end());
}

std::vector<std::string> PartitionDetector::GetUnreachableNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<std::string>(unreachableNodes_.begin(), unreachableNodes_.end());
}

size_t PartitionDetector::GetPartitionSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reachableNodes_.size();
}

size_t PartitionDetector::GetTotalClusterSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reachableNodes_.size() + unreachableNodes_.size();
}

void PartitionDetector::OnPartitionChange(PartitionCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    partitionCallback_ = callback;
}

void PartitionDetector::DetectPartition() {
    // Query all nodes for their view
    // Simplified implementation
}

bool PartitionDetector::IsMajority(size_t partitionSize, size_t totalSize) const {
    return partitionSize > totalSize / 2;
}

void PartitionDetector::NotifyPartitionChange(bool isPartitioned, bool isMajority) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (partitionCallback_) {
        partitionCallback_(isPartitioned, isMajority);
    }
}

// ============================================================================
// Fault Detector Implementation
// ============================================================================

FaultDetector::FaultDetector(
    std::shared_ptr<CommunicationManager> commManager,
    const DetectorConfig& config
) : commManager_(commManager), config_(config) {}

FaultDetector::~FaultDetector() {
    Shutdown();
}

bool FaultDetector::Initialize() {
    running_ = true;
    
    phiDetector_ = std::make_unique<PhiAccrualDetector>(config_);
    phiDetector_->Initialize();
    
    gossip_ = std::make_unique<GossipProtocol>(commManager_, config_);
    gossip_->Initialize();
    
    gossip_->OnSuspicion(
        [this](const std::string& nodeId, const std::string& reason) {
            HandleSuspectedNode(nodeId, reason);
        }
    );
    
    gossip_->OnConfirmation(
        [this](const FaultEvent& fault) {
            HandleConfirmedFault(fault);
        }
    );
    
    partitionDetector_ = std::make_unique<PartitionDetector>(commManager_, config_);
    partitionDetector_->Initialize();
    
    detectionThread_ = std::thread(&FaultDetector::DetectionLoop, this);
    
    return true;
}

void FaultDetector::Shutdown() {
    running_ = false;
    
    if (detectionThread_.joinable()) {
        detectionThread_.join();
    }
    
    if (gossip_) {
        gossip_->Shutdown();
    }
    if (phiDetector_) {
        phiDetector_->Shutdown();
    }
    if (partitionDetector_) {
        partitionDetector_->Shutdown();
    }
}

void FaultDetector::RegisterNode(const std::string& nodeId) {
    // Node is automatically registered on first heartbeat
}

void FaultDetector::UnregisterNode(const std::string& nodeId) {
    phiDetector_->RemoveNode(nodeId);
}

void FaultDetector::ReportHeartbeat(const std::string& nodeId) {
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    ReportHeartbeat(nodeId, now);
}

void FaultDetector::ReportHeartbeat(const std::string& nodeId, uint64_t timestamp) {
    phiDetector_->ReportHeartbeat(nodeId, timestamp);
}

void FaultDetector::ReportFault(const FaultEvent& fault) {
    std::lock_guard<std::mutex> lock(faultMutex_);
    activeFaults_[fault.faultId] = fault;
    faultHistory_.push_back(fault);
    
    NotifyFaultDetected(fault);
}

void FaultDetector::ReportSuspicion(const std::string& nodeId, const std::string& reason) {
    FaultEvent fault;
    fault.faultId = GenerateFaultId();
    fault.type = FaultType::NODE_UNRESPONSIVE;
    fault.severity = FaultSeverity::WARNING;
    fault.nodeId = nodeId;
    fault.description = reason;
    fault.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    fault.isConfirmed = false;
    
    ReportFault(fault);
    
    // Spread via gossip
    gossip_->SpreadSuspicion(nodeId, reason);
}

std::vector<FaultEvent> FaultDetector::GetActiveFaults() const {
    std::lock_guard<std::mutex> lock(faultMutex_);
    
    std::vector<FaultEvent> result;
    for (const auto& [id, fault] : activeFaults_) {
        result.push_back(fault);
    }
    return result;
}

std::vector<FaultEvent> FaultDetector::GetFaultHistory() const {
    std::lock_guard<std::mutex> lock(faultMutex_);
    return faultHistory_;
}

std::optional<NodeHealth> FaultDetector::GetNodeHealth(const std::string& nodeId) const {
    return phiDetector_->GetNodeHealth(nodeId);
}

std::vector<NodeHealth> FaultDetector::GetAllNodeHealth() const {
    return phiDetector_->GetAllNodeHealth();
}

void FaultDetector::ConfirmFault(const std::string& faultId) {
    std::lock_guard<std::mutex> lock(faultMutex_);
    
    auto it = activeFaults_.find(faultId);
    if (it != activeFaults_.end()) {
        it->second.isConfirmed = true;
        NotifyFaultConfirmed(it->second);
    }
}

void FaultDetector::ResolveFault(const std::string& faultId) {
    FaultEvent resolved;
    
    {
        std::lock_guard<std::mutex> lock(faultMutex_);
        
        auto it = activeFaults_.find(faultId);
        if (it == activeFaults_.end()) {
            return;
        }
        
        resolved = it->second;
        activeFaults_.erase(it);
    }
    
    NotifyFaultResolved(resolved);
    
    // Spread recovery via gossip
    gossip_->SpreadRecovery(resolved.nodeId);
}

void FaultDetector::OnFaultDetected(FaultCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    faultDetectedCallback_ = callback;
}

void FaultDetector::OnFaultConfirmed(FaultCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    faultConfirmedCallback_ = callback;
}

void FaultDetector::OnFaultResolved(FaultCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    faultResolvedCallback_ = callback;
}

void FaultDetector::OnNodeRecovered(RecoveryCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    nodeRecoveredCallback_ = callback;
}

std::string FaultDetector::GetStatusJson() const {
    auto faults = GetActiveFaults();
    auto health = GetAllNodeHealth();
    
    std::string json = "{";
    json += "\"activeFaults\":" + std::to_string(faults.size()) + ",";
    json += "\"monitoredNodes\":" + std::to_string(health.size()) + ",";
    json += "\"partitioned\":" + std::string(partitionDetector_->IsPartitioned() ? "true" : "false") + ",";
    json += "\"healthy\":" + std::string(IsHealthy() ? "true" : "false");
    json += "}";
    return json;
}

bool FaultDetector::IsHealthy() const {
    auto faults = GetActiveFaults();
    for (const auto& fault : faults) {
        if (fault.severity == FaultSeverity::FATAL) {
            return false;
        }
    }
    return true;
}

void FaultDetector::DetectionLoop() {
    while (running_) {
        // Check all nodes for suspicion
        auto health = phiDetector_->GetAllNodeHealth();
        
        for (const auto& h : health) {
            if (h.status == NodeHealth::Status::SUSPECTED) {
                ReportSuspicion(h.nodeId, "Phi threshold exceeded");
            } else if (h.status == NodeHealth::Status::UNHEALTHY) {
                // Confirm fault
                FaultEvent fault;
                fault.faultId = GenerateFaultId();
                fault.type = FaultType::NODE_UNRESPONSIVE;
                fault.severity = FaultSeverity::CRITICAL;
                fault.nodeId = h.nodeId;
                fault.description = "Node unresponsive - phi value: " + std::to_string(h.phiValue);
                fault.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                fault.isConfirmed = true;
                
                ReportFault(fault);
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void FaultDetector::HandleSuspectedNode(const std::string& nodeId, const std::string& reason) {
    // Already handled in detection loop
}

void FaultDetector::HandleConfirmedFault(const FaultEvent& fault) {
    ConfirmFault(fault.faultId);
}

void FaultDetector::HandleNodeRecovery(const std::string& nodeId) {
    // Resolve any active faults for this node
    auto faults = GetActiveFaults();
    for (const auto& fault : faults) {
        if (fault.nodeId == nodeId) {
            ResolveFault(fault.faultId);
        }
    }
    
    NotifyNodeRecovered(nodeId);
}

std::string FaultDetector::GenerateFaultId() {
    static std::atomic<uint64_t> counter{0};
    uint64_t id = counter.fetch_add(1);
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return "fault-" + std::to_string(now) + "-" + std::to_string(id);
}

void FaultDetector::NotifyFaultDetected(const FaultEvent& fault) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (faultDetectedCallback_) {
        faultDetectedCallback_(fault);
    }
}

void FaultDetector::NotifyFaultConfirmed(const FaultEvent& fault) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (faultConfirmedCallback_) {
        faultConfirmedCallback_(fault);
    }
}

void FaultDetector::NotifyFaultResolved(const FaultEvent& fault) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (faultResolvedCallback_) {
        faultResolvedCallback_(fault);
    }
}

void FaultDetector::NotifyNodeRecovered(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (nodeRecoveredCallback_) {
        nodeRecoveredCallback_(nodeId);
    }
}

// ============================================================================
// Recovery Coordinator Implementation
// ============================================================================

RecoveryCoordinator::RecoveryCoordinator(
    std::shared_ptr<CommunicationManager> commManager,
    std::shared_ptr<WorkScheduler> scheduler
) : commManager_(commManager), scheduler_(scheduler) {}

RecoveryCoordinator::~RecoveryCoordinator() {
    Shutdown();
}

bool RecoveryCoordinator::Initialize() {
    running_ = true;
    return true;
}

void RecoveryCoordinator::Shutdown() {
    running_ = false;
}

RecoveryCoordinator::RecoveryPlan RecoveryCoordinator::CreatePlan(const FaultEvent& fault) {
    RecoveryPlan plan;
    plan.faultId = fault.faultId;
    plan.nodeId = fault.nodeId;
    
    switch (fault.type) {
        case FaultType::NODE_CRASH:
        case FaultType::NODE_UNRESPONSIVE:
            plan.actions = {RecoveryAction::MIGRATE_TASKS,
                          RecoveryAction::ELECT_NEW_LEADER,
                          RecoveryAction::SHRINK_CLUSTER};
            plan.estimatedTimeMs = 30000;
            break;
            
        case FaultType::SLOW_NODE:
            plan.actions = {RecoveryAction::MIGRATE_TASKS};
            plan.estimatedTimeMs = 60000;
            break;
            
        case FaultType::RESOURCE_EXHAUSTION:
            plan.actions = {RecoveryAction::MIGRATE_TASKS,
                          RecoveryAction::ALERT_OPERATOR};
            plan.estimatedTimeMs = 120000;
            plan.requiresConfirmation = true;
            break;
            
        default:
            plan.actions = {RecoveryAction::ALERT_OPERATOR};
            plan.requiresConfirmation = true;
            break;
    }
    
    return plan;
}

RecoveryCoordinator::RecoveryResult RecoveryCoordinator::ExecuteRecovery(
    const RecoveryPlan& plan
) {
    RecoveryResult result;
    result.success = true;
    
    auto start = std::chrono::steady_clock::now();
    
    for (const auto& action : plan.actions) {
        bool actionSuccess = false;
        
        switch (action) {
            case RecoveryAction::RESTART_NODE:
                actionSuccess = DoRestartNode(plan.nodeId);
                break;
                
            case RecoveryAction::MIGRATE_TASKS:
                // Get tasks from failed node
                actionSuccess = DoMigrateTasks(plan.nodeId, {});
                break;
                
            case RecoveryAction::ELECT_NEW_LEADER:
                actionSuccess = DoElectNewLeader();
                break;
                
            case RecoveryAction::SHRINK_CLUSTER:
                actionSuccess = DoShrinkCluster(plan.nodeId);
                break;
                
            case RecoveryAction::ALERT_OPERATOR:
                // Just log for now
                LOG_WARNING("Operator alert: Fault " + plan.faultId + " on node " + plan.nodeId);
                actionSuccess = true;
                break;
        }
        
        if (actionSuccess) {
            result.completedActions.push_back(std::to_string(static_cast<int>(action)));
        } else {
            result.success = false;
            result.message = "Action failed: " + std::to_string(static_cast<int>(action));
            break;
        }
    }
    
    auto end = std::chrono::steady_clock::now();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start).count();
    
    NotifyRecoveryComplete(result);
    
    return result;
}

bool RecoveryCoordinator::RestartNode(const std::string& nodeId) {
    return DoRestartNode(nodeId);
}

bool RecoveryCoordinator::MigrateTasks(
    const std::string& fromNode,
    const std::vector<std::string>& taskIds
) {
    return DoMigrateTasks(fromNode, taskIds);
}

bool RecoveryCoordinator::ElectNewLeader() {
    return DoElectNewLeader();
}

bool RecoveryCoordinator::ShrinkCluster(const std::string& nodeId) {
    return DoShrinkCluster(nodeId);
}

void RecoveryCoordinator::OnRecoveryComplete(RecoveryCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    recoveryCallback_ = callback;
}

std::string RecoveryCoordinator::GetStatusJson() const {
    std::string json = "{";
    json += "\"recovering\":" + std::string(recovering_ ? "true" : "false");
    json += "}";
    return json;
}

bool RecoveryCoordinator::IsRecovering() const {
    return recovering_.load();
}

bool RecoveryCoordinator::DoRestartNode(const std::string& nodeId) {
    // Send restart command to node
    Message msg;
    msg.header.type = MessageType::RPC_REQUEST;
    msg.header.destinationNode = nodeId;
    msg.payload = "{\"action\":\"restart\"}";
    
    return commManager_->SendMessage(nodeId, msg);
}

bool RecoveryCoordinator::DoMigrateTasks(
    const std::string& fromNode,
    const std::vector<std::string>& taskIds
) {
    // Get tasks from scheduler
    auto tasks = scheduler_->GetTasksByNode(fromNode);
    
    for (const auto& task : tasks) {
        if (task.state == TaskState::RUNNING) {
            // Cancel on old node
            scheduler_->CancelTask(task.taskId);
            
            // Get spec and resubmit
            auto spec = scheduler_->GetTaskSpec(task.taskId);
            if (spec) {
                scheduler_->SubmitTask(*spec);
            }
        }
    }
    
    return true;
}

bool RecoveryCoordinator::DoElectNewLeader() {
    // Trigger leader election via consensus
    // Simplified - would integrate with RaftConsensus
    return true;
}

bool RecoveryCoordinator::DoShrinkCluster(const std::string& nodeId) {
    // Remove node from cluster membership
    // Simplified implementation
    return true;
}

void RecoveryCoordinator::NotifyRecoveryComplete(const RecoveryResult& result) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (recoveryCallback_) {
        recoveryCallback_(result);
    }
}

// ============================================================================
// Fault Tolerance Manager Implementation
// ============================================================================

FaultToleranceManager::FaultToleranceManager(
    std::shared_ptr<CommunicationManager> commManager,
    std::shared_ptr<WorkScheduler> scheduler,
    const DetectorConfig& config
) {
    detector_ = std::make_unique<FaultDetector>(commManager, config);
    coordinator_ = std::make_unique<RecoveryCoordinator>(commManager, scheduler);
}

FaultToleranceManager::~FaultToleranceManager() {
    Shutdown();
}

bool FaultToleranceManager::Initialize() {
    if (!detector_->Initialize()) {
        return false;
    }
    
    if (!coordinator_->Initialize()) {
        return false;
    }
    
    // Set up automatic recovery
    detector_->OnFaultConfirmed(
        [this](const FaultEvent& fault) {
            faultCount_++;
            
            auto plan = coordinator_->CreatePlan(fault);
            auto result = coordinator_->ExecuteRecovery(plan);
            
            if (result.success) {
                recoveryCount_++;
            }
        }
    );
    
    return true;
}

void FaultToleranceManager::Shutdown() {
    if (coordinator_) {
        coordinator_->Shutdown();
    }
    if (detector_) {
        detector_->Shutdown();
    }
}

void FaultToleranceManager::RegisterNode(const std::string& nodeId) {
    detector_->RegisterNode(nodeId);
}

void FaultToleranceManager::UnregisterNode(const std::string& nodeId) {
    detector_->UnregisterNode(nodeId);
}

void FaultToleranceManager::SendHeartbeat() {
    // Heartbeat is sent by the communication manager
}

void FaultToleranceManager::ReceiveHeartbeat(const std::string& nodeId) {
    detector_->ReportHeartbeat(nodeId);
}

bool FaultToleranceManager::IsNodeHealthy(const std::string& nodeId) const {
    auto health = detector_->GetNodeHealth(nodeId);
    if (health) {
        return health->status == NodeHealth::Status::HEALTHY;
    }
    return false;
}

bool FaultToleranceManager::IsClusterHealthy() const {
    return detector_->IsHealthy();
}

std::string FaultToleranceManager::GetStatusJson() const {
    std::string json = "{";
    json += "\"detector\":" + detector_->GetStatusJson() + ",";
    json += "\"coordinator\":" + coordinator_->GetStatusJson() + ",";
    json += "\"faultCount\":" + std::to_string(faultCount_.load()) + ",";
    json += "\"recoveryCount\":" + std::to_string(recoveryCount_.load()) + ",";
    json += "\"availability\":" + std::to_string(GetAvailability());
    json += "}";
    return json;
}

uint64_t FaultToleranceManager::GetFaultCount() const {
    return faultCount_.load();
}

uint64_t FaultToleranceManager::GetRecoveryCount() const {
    return recoveryCount_.load();
}

float FaultToleranceManager::GetAvailability() const {
    uint64_t faults = faultCount_.load();
    uint64_t recoveries = recoveryCount_.load();
    
    if (faults == 0) {
        return 100.0f;
    }
    
    return (static_cast<float>(recoveries) / faults) * 100.0f;
}

} // namespace Distributed
