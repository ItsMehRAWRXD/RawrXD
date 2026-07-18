/**
 * AutonomousSafetyGuard.cpp
 *
 * Phase D.1 Batch 4/5: Security / Safety Envelope
 */

#include "AutonomousSafetyGuard.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>

namespace Security {

// ============================================================================
// SafetyViolation Utilities
// ============================================================================

std::string SafetyViolationToString(SafetyViolation violation) {
    switch (violation) {
        case SafetyViolation::MUTATION_LIMIT_EXCEEDED: return "MUTATION_LIMIT_EXCEEDED";
        case SafetyViolation::RESOURCE_CAP_EXCEEDED: return "RESOURCE_CAP_EXCEEDED";
        case SafetyViolation::ROLLBACK_NOT_AVAILABLE: return "ROLLBACK_NOT_AVAILABLE";
        case SafetyViolation::APPROVAL_REQUIRED: return "APPROVAL_REQUIRED";
        case SafetyViolation::UNSAFE_MODE_TRANSITION: return "UNSAFE_MODE_TRANSITION";
        case SafetyViolation::CRITICAL_SUBSYSTEM_MODIFICATION: return "CRITICAL_SUBSYSTEM_MODIFICATION";
        case SafetyViolation::EMERGENCY_STOP_TRIGGERED: return "EMERGENCY_STOP_TRIGGERED";
        case SafetyViolation::NONE: return "NONE";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// SafetyPolicy Implementation
// ============================================================================

std::string SafetyPolicy::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"maxMutationsPerCycle\":" << maxMutationsPerCycle << ",";
    json << "\"maxConcurrentMutations\":" << maxConcurrentMutations << ",";
    json << "\"maxMutationRisk\":" << maxMutationRisk << ",";
    json << "\"maxCpuUtilization\":" << maxCpuUtilization << ",";
    json << "\"maxMemoryUtilization\":" << maxMemoryUtilization << ",";
    json << "\"maxActiveWorkers\":" << maxActiveWorkers << ",";
    json << "\"requireApprovalForCritical\":" << (requireApprovalForCritical ? "true" : "false") << ",";
    json << "\"requireApprovalForSelfOptimizing\":" << (requireApprovalForSelfOptimizing ? "true" : "false") << ",";
    json << "\"requireApprovalForTermination\":" << (requireApprovalForTermination ? "true" : "false") << ",";
    json << "\"requireRollbackForMutations\":" << (requireRollbackForMutations ? "true" : "false") << ",";
    json << "\"maxRollbackDepth\":" << maxRollbackDepth << ",";
    json << "\"emergencyStabilityThreshold\":" << emergencyStabilityThreshold << ",";
    json << "\"emergencyFaultThreshold\":" << emergencyFaultThreshold;
    json << "}";
    return json.str();
}

// ============================================================================
// SafetyCheckResult Implementation
// ============================================================================

std::string SafetyCheckResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"allowed\":" << (allowed ? "true" : "false") << ",";
    json << "\"violation\":\"" << SafetyViolationToString(violation) << "\",";
    json << "\"reason\":\"" << reason << "\",";
    json << "\"requiredAction\":\"" << requiredAction << "\"";
    json << "}";
    return json.str();
}

SafetyCheckResult SafetyCheckResult::Allow() {
    SafetyCheckResult result;
    result.allowed = true;
    result.violation = SafetyViolation::NONE;
    return result;
}

SafetyCheckResult SafetyCheckResult::Deny(SafetyViolation violation, const std::string& reason) {
    SafetyCheckResult result;
    result.allowed = false;
    result.violation = violation;
    result.reason = reason;
    return result;
}

// ============================================================================
// ApprovalRequest Implementation
// ============================================================================

std::string ApprovalRequest::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"requestId\":\"" << requestId << "\",";
    json << "\"decisionId\":\"" << decisionId << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"riskAssessment\":\"" << riskAssessment << "\",";
    json << "\"timestampMs\":" << timestampMs << ",";
    json << "\"timeoutMs\":" << timeoutMs;
    json << "}";
    return json.str();
}

// ============================================================================
// AutonomousSafetyGuard Implementation
// ============================================================================

AutonomousSafetyGuard::AutonomousSafetyGuard() = default;
AutonomousSafetyGuard::~AutonomousSafetyGuard() = default;

bool AutonomousSafetyGuard::Initialize(const SafetyPolicy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    policy_ = policy;
    initialized_ = true;
    emergencyStopActive_ = false;
    mutationsThisCycle_ = 0;
    concurrentMutations_ = 0;
    
    std::cout << "[AutonomousSafetyGuard] Initialized\n";
    std::cout << "  Mutation limit: " << policy.maxMutationsPerCycle << " per cycle\n";
    std::cout << "  CPU cap: " << (policy.maxCpuUtilization * 100) << "%\n";
    std::cout << "  Memory cap: " << (policy.maxMemoryUtilization * 100) << "%\n";
    
    return true;
}

void AutonomousSafetyGuard::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    pendingApprovals_.clear();
    grantedApprovals_.clear();
    initialized_ = false;
    
    std::cout << "[AutonomousSafetyGuard] Shutdown complete\n";
}

SafetyCheckResult AutonomousSafetyGuard::CheckDecision(const Autonomy::Decision& decision,
                                                       const Core::SovereignState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return SafetyCheckResult::Deny(SafetyViolation::NONE, "Safety guard not initialized");
    }
    
    // Check emergency stop
    if (emergencyStopActive_) {
        return SafetyCheckResult::Deny(SafetyViolation::EMERGENCY_STOP_TRIGGERED, 
                                       "Emergency stop is active");
    }
    
    // Check mutation limits
    auto mutationCheck = CheckMutationLimits(decision);
    if (!mutationCheck.allowed) return mutationCheck;
    
    // Check resource caps
    auto resourceCheck = CheckResourceCaps(state);
    if (!resourceCheck.allowed) return resourceCheck;
    
    // Check approval requirements
    auto approvalCheck = CheckApprovalRequirements(decision);
    if (!approvalCheck.allowed) return approvalCheck;
    
    return SafetyCheckResult::Allow();
}

SafetyCheckResult AutonomousSafetyGuard::CheckMutation(const Autonomy::SEGMutation& mutation,
                                                       const Core::SovereignState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return SafetyCheckResult::Deny(SafetyViolation::NONE, "Safety guard not initialized");
    }
    
    // Check emergency stop
    if (emergencyStopActive_) {
        return SafetyCheckResult::Deny(SafetyViolation::EMERGENCY_STOP_TRIGGERED, 
                                       "Emergency stop is active");
    }
    
    // Check mutation risk
    if (mutation.riskScore > policy_.maxMutationRisk) {
        return SafetyCheckResult::Deny(SafetyViolation::MUTATION_LIMIT_EXCEEDED,
                                       "Mutation risk exceeds threshold: " + 
                                       std::to_string(static_cast<int>(mutation.riskScore * 100)) + "%");
    }
    
    // Check rollback availability
    auto rollbackCheck = CheckRollbackAvailability(mutation);
    if (!rollbackCheck.allowed) return rollbackCheck;
    
    return SafetyCheckResult::Allow();
}

SafetyCheckResult AutonomousSafetyGuard::CheckModeTransition(Core::ExecutionMode from,
                                                             Core::ExecutionMode to,
                                                             const Core::SovereignState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return SafetyCheckResult::Deny(SafetyViolation::NONE, "Safety guard not initialized");
    }
    
    // Check emergency stop
    if (emergencyStopActive_ && to != Core::ExecutionMode::IDLE) {
        return SafetyCheckResult::Deny(SafetyViolation::EMERGENCY_STOP_TRIGGERED,
                                       "Cannot transition while emergency stop is active");
    }
    
    // Check if transition to SELF_OPTIMIZING requires approval
    if (to == Core::ExecutionMode::SELF_OPTIMIZING && policy_.requireApprovalForSelfOptimizing) {
        // Would check for approval
    }
    
    // Check stability for autonomous modes
    if ((to == Core::ExecutionMode::AUTONOMOUS || to == Core::ExecutionMode::SELF_OPTIMIZING) &&
        state.stability < policy_.emergencyStabilityThreshold) {
        return SafetyCheckResult::Deny(SafetyViolation::UNSAFE_MODE_TRANSITION,
                                       "System stability too low for autonomous mode: " +
                                       std::to_string(static_cast<int>(state.stability * 100)) + "%");
    }
    
    return SafetyCheckResult::Allow();
}

std::string AutonomousSafetyGuard::RequestApproval(const ApprovalRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string requestId = GenerateRequestId();
    
    ApprovalRequest newRequest = request;
    newRequest.requestId = requestId;
    newRequest.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    pendingApprovals_.push_back(requestId);
    
    std::cout << "[AutonomousSafetyGuard] Approval requested: " << requestId << "\n";
    std::cout << "  Description: " << request.description << "\n";
    std::cout << "  Risk: " << request.riskAssessment << "\n";
    
    return requestId;
}

bool AutonomousSafetyGuard::GrantApproval(const std::string& requestId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::find(pendingApprovals_.begin(), pendingApprovals_.end(), requestId);
    if (it == pendingApprovals_.end()) {
        return false;
    }
    
    pendingApprovals_.erase(it);
    grantedApprovals_.push_back(requestId);
    
    std::cout << "[AutonomousSafetyGuard] Approval granted: " << requestId << "\n";
    return true;
}

bool AutonomousSafetyGuard::DenyApproval(const std::string& requestId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::find(pendingApprovals_.begin(), pendingApprovals_.end(), requestId);
    if (it == pendingApprovals_.end()) {
        return false;
    }
    
    pendingApprovals_.erase(it);
    
    std::cout << "[AutonomousSafetyGuard] Approval denied: " << requestId << " - " << reason << "\n";
    return true;
}

bool AutonomousSafetyGuard::IsApprovalPending(const std::string& requestId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    return std::find(pendingApprovals_.begin(), pendingApprovals_.end(), requestId) 
           != pendingApprovals_.end();
}

void AutonomousSafetyGuard::TriggerEmergencyStop(const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    emergencyStopActive_ = true;
    
    std::cerr << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cerr << "║     EMERGENCY STOP TRIGGERED                                     ║\n";
    std::cerr << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cerr << "║  Reason: " << std::left << std::setw(52) << reason << " ║\n";
    std::cerr << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void AutonomousSafetyGuard::ClearEmergencyStop() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    emergencyStopActive_ = false;
    
    std::cout << "[AutonomousSafetyGuard] Emergency stop cleared\n";
}

bool AutonomousSafetyGuard::IsEmergencyStopActive() const {
    return emergencyStopActive_.load();
}

std::vector<std::string> AutonomousSafetyGuard::GetActiveConstraints() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> constraints;
    
    constraints.push_back("Max mutations per cycle: " + std::to_string(policy_.maxMutationsPerCycle));
    constraints.push_back("Max CPU: " + std::to_string(static_cast<int>(policy_.maxCpuUtilization * 100)) + "%");
    constraints.push_back("Max memory: " + std::to_string(static_cast<int>(policy_.maxMemoryUtilization * 100)) + "%");
    
    if (policy_.requireApprovalForCritical) {
        constraints.push_back("Approval required for critical decisions");
    }
    
    if (policy_.requireRollbackForMutations) {
        constraints.push_back("Rollback required for mutations");
    }
    
    return constraints;
}

void AutonomousSafetyGuard::UpdatePolicy(const SafetyPolicy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    policy_ = policy;
    
    std::cout << "[AutonomousSafetyGuard] Policy updated\n";
}

SafetyPolicy AutonomousSafetyGuard::GetPolicy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return policy_;
}

void AutonomousSafetyGuard::PrintStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     AUTONOMOUS SAFETY GUARD STATUS                               ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Initialized:      " << std::setw(10) << (initialized_ ? "YES" : "NO") << std::string(26, ' ') << "║\n";
    std::cout << "║  Emergency Stop:    " << std::setw(10) << (emergencyStopActive_ ? "ACTIVE" : "INACTIVE") << std::string(26, ' ') << "║\n";
    std::cout << "║  Mutations This Cycle: " << std::setw(8) << mutationsThisCycle_ << std::string(26, ' ') << "║\n";
    std::cout << "║  Concurrent Mutations: " << std::setw(7) << concurrentMutations_ << std::string(26, ' ') << "║\n";
    std::cout << "║  Pending Approvals:  " << std::setw(10) << pendingApprovals_.size() << std::string(26, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Active Constraints:                                             ║\n";
    
    auto constraints = GetActiveConstraints();
    for (const auto& constraint : constraints) {
        std::cout << "║    - " << std::left << std::setw(55) << constraint << " ║\n";
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Check Methods
// ============================================================================

SafetyCheckResult AutonomousSafetyGuard::CheckMutationLimits(const Autonomy::Decision& decision) {
    if (mutationsThisCycle_ >= policy_.maxMutationsPerCycle) {
        return SafetyCheckResult::Deny(SafetyViolation::MUTATION_LIMIT_EXCEEDED,
                                       "Mutation limit exceeded: " + 
                                       std::to_string(mutationsThisCycle_) + "/" + 
                                       std::to_string(policy_.maxMutationsPerCycle));
    }
    
    if (concurrentMutations_ >= policy_.maxConcurrentMutations) {
        return SafetyCheckResult::Deny(SafetyViolation::MUTATION_LIMIT_EXCEEDED,
                                       "Concurrent mutation limit exceeded: " +
                                       std::to_string(concurrentMutations_) + "/" +
                                       std::to_string(policy_.maxConcurrentMutations));
    }
    
    return SafetyCheckResult::Allow();
}

SafetyCheckResult AutonomousSafetyGuard::CheckResourceCaps(const Core::SovereignState& state) {
    // Check CPU
    if (state.runtime.cpuUtilization > policy_.maxCpuUtilization) {
        return SafetyCheckResult::Deny(SafetyViolation::RESOURCE_CAP_EXCEEDED,
                                       "CPU utilization exceeds cap: " +
                                       std::to_string(static_cast<int>(state.runtime.cpuUtilization * 100)) + "% > " +
                                       std::to_string(static_cast<int>(policy_.maxCpuUtilization * 100)) + "%");
    }
    
    // Check memory
    // Would calculate actual memory usage
    
    // Check workers
    if (state.activeWorkers > static_cast<size_t>(policy_.maxActiveWorkers)) {
        return SafetyCheckResult::Deny(SafetyViolation::RESOURCE_CAP_EXCEEDED,
                                       "Active workers exceeds cap: " +
                                       std::to_string(state.activeWorkers) + " > " +
                                       std::to_string(policy_.maxActiveWorkers));
    }
    
    return SafetyCheckResult::Allow();
}

SafetyCheckResult AutonomousSafetyGuard::CheckRollbackAvailability(const Autonomy::SEGMutation& mutation) {
    if (!policy_.requireRollbackForMutations) {
        return SafetyCheckResult::Allow();
    }
    
    if (!mutation.isReversible) {
        return SafetyCheckResult::Deny(SafetyViolation::ROLLBACK_NOT_AVAILABLE,
                                       "Mutation is not reversible and rollback is required");
    }
    
    return SafetyCheckResult::Allow();
}

SafetyCheckResult AutonomousSafetyGuard::CheckApprovalRequirements(const Autonomy::Decision& decision) {
    // Check for critical decisions
    if (policy_.requireApprovalForCritical && decision.RequiresApproval()) {
        // Would check if approval was granted
        // For now, allow through
    }
    
    // Check for termination
    if (policy_.requireApprovalForTermination && 
        decision.type == Autonomy::DecisionType::TERMINATE_GRACEFULLY) {
        // Would require approval
    }
    
    return SafetyCheckResult::Allow();
}

// ============================================================================
// Helpers
// ============================================================================

std::string AutonomousSafetyGuard::GenerateRequestId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "approval-" << ms << "-" << dis(gen);
    return id.str();
}

void AutonomousSafetyGuard::ResetCycleCounters() {
    mutationsThisCycle_ = 0;
}

// ============================================================================
// SafetyEnvelopeValidator Implementation
// ============================================================================

SafetyCheckResult SafetyEnvelopeValidator::Validate(const Autonomy::Decision& decision,
                                                   const SafetyPolicy& policy,
                                                   const Core::SovereignState& state) {
    // Check mutation risk
    if (decision.riskScore > policy.maxMutationRisk) {
        return SafetyCheckResult::Deny(SafetyViolation::MUTATION_LIMIT_EXCEEDED,
                                       "Decision risk exceeds threshold");
    }
    
    // Check resource availability
    if (state.runtime.cpuUtilization > policy.maxCpuUtilization) {
        return SafetyCheckResult::Deny(SafetyViolation::RESOURCE_CAP_EXCEEDED,
                                       "Insufficient resources");
    }
    
    return SafetyCheckResult::Allow();
}

SafetyCheckResult SafetyEnvelopeValidator::Validate(const Autonomy::SEGMutation& mutation,
                                                   const SafetyPolicy& policy,
                                                   const Core::SovereignState& state) {
    // Check mutation risk
    if (mutation.riskScore > policy.maxMutationRisk) {
        return SafetyCheckResult::Deny(SafetyViolation::MUTATION_LIMIT_EXCEEDED,
                                       "Mutation risk exceeds threshold");
    }
    
    // Check rollback availability
    if (policy.requireRollbackForMutations && !mutation.isReversible) {
        return SafetyCheckResult::Deny(SafetyViolation::ROLLBACK_NOT_AVAILABLE,
                                       "Non-reversible mutation requires rollback capability");
    }
    
    return SafetyCheckResult::Allow();
}

} // namespace Security
