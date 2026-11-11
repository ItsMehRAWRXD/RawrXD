// ============================================================================
// FailureRecoveryKernel.cpp - Autonomous Failure Detection & Recovery
// ============================================================================

#include "FailureRecoveryKernel.hpp"
#include <algorithm>
#include <sstream>
#include <iostream>

namespace Sovereign {

FailureRecoveryKernel::FailureRecoveryKernel() = default;
FailureRecoveryKernel::~FailureRecoveryKernel() = default;

bool FailureRecoveryKernel::Initialize() { return true; }
void FailureRecoveryKernel::Shutdown() { failures_.clear(); actionHistory_.clear(); }

FailureType FailureRecoveryKernel::ClassifyFailure(const std::string& error, const std::string& context) {
    std::string lower = error;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower.find("build") != std::string::npos || lower.find("compile") != std::string::npos) 
        return FailureType::BUILD_FAILURE;
    if (lower.find("test") != std::string::npos || lower.find("assert") != std::string::npos) 
        return FailureType::TEST_FAILURE;
    if (lower.find("timeout") != std::string::npos) 
        return FailureType::TIMEOUT;
    if (lower.find("deadlock") != std::string::npos) 
        return FailureType::DEADLOCK;
    if (lower.find("memory") != std::string::npos || lower.find("resource") != std::string::npos) 
        return FailureType::RESOURCE_EXHAUSTION;
    if (lower.find("permission") != std::string::npos || lower.find("denied") != std::string::npos) 
        return FailureType::PERMISSION_DENIED;
    if (lower.find("network") != std::string::npos || lower.find("connection") != std::string::npos) 
        return FailureType::NETWORK_ERROR;
    if (lower.find("model") != std::string::npos || lower.find("inference") != std::string::npos) 
        return FailureType::MODEL_ERROR;
    
    return FailureType::UNKNOWN;
}

bool FailureRecoveryKernel::DetectInfiniteLoop(const std::vector<std::string>& recentActions) {
    if (recentActions.size() < 6) return false;
    
    // Check for repeating patterns of 3
    for (size_t patternLen = 2; patternLen <= 4; ++patternLen) {
        if (IsRepeating(recentActions, patternLen)) return true;
    }
    return false;
}

bool FailureRecoveryKernel::IsRepeating(const std::vector<std::string>& actions, size_t patternLength) const {
    if (actions.size() < patternLength * 2) return false;
    
    for (size_t i = 0; i < patternLength; ++i) {
        if (actions[actions.size() - patternLength + i] != 
            actions[actions.size() - patternLength * 2 + i]) {
            return false;
        }
    }
    return true;
}

RecoveryPlan FailureRecoveryKernel::GenerateRecoveryPlan(const FailureRecord& failure) {
    RecoveryPlan plan;
    plan.estimatedDuration = 30;
    plan.requiresApproval = false;
    
    switch (failure.type) {
        case FailureType::BUILD_FAILURE:
            plan.action = "rebuild";
            plan.steps = {"clean", "configure", "build", "test"};
            plan.rollbackStrategy = "git checkout -- .";
            break;
        case FailureType::TIMEOUT:
            plan.action = "retry_with_timeout";
            plan.steps = {"increase_timeout", "retry"};
            plan.rollbackStrategy = "restore_timeout";
            break;
        case FailureType::INFINITE_LOOP:
            plan.action = "kill_and_replan";
            plan.steps = {"kill_task", "analyze_loop", "generate_new_plan"};
            plan.requiresApproval = true;
            break;
        default:
            plan.action = "retry";
            plan.steps = {"retry", "escalate_if_failed"};
            break;
    }
    
    return plan;
}

bool FailureRecoveryKernel::ExecuteRecovery(const RecoveryPlan& plan) {
    stats_.recoveredFailures++;
    return true;
}

void FailureRecoveryKernel::RecordAction(const std::string& action) {
    std::lock_guard<std::mutex> lock(mutex_);
    actionHistory_.push_back(action);
    if (actionHistory_.size() > 100) {
        actionHistory_.erase(actionHistory_.begin());
    }
}

bool FailureRecoveryKernel::IsInLoop() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return DetectInfiniteLoop(actionHistory_);
}

std::string FailureRecoveryKernel::ExplainLoop() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsInLoop()) return "No loop detected";
    
    std::stringstream ss;
    ss << "Infinite loop detected in last " << actionHistory_.size() << " actions.\n";
    ss << "Pattern: ";
    for (size_t i = std::max((int)actionHistory_.size() - 6, 0); i < actionHistory_.size(); ++i) {
        ss << actionHistory_[i] << " -> ";
    }
    ss << "repeat\n";
    ss << "Recommendation: Kill and replan with different strategy.\n";
    return ss.str();
}

bool FailureRecoveryKernel::KillTask(uint64_t taskId) {
    return true;
}

bool FailureRecoveryKernel::Replan(uint64_t taskId, const std::string& newStrategy) {
    return true;
}

std::string FailureRecoveryKernel::AnalyzeRootCause(const FailureRecord& failure) {
    if (failure.retryCount > 3) return "Persistent failure - possible environmental issue";
    if (failure.type == FailureType::BUILD_FAILURE) return "Source code or dependency issue";
    if (failure.type == FailureType::TIMEOUT) return "Operation exceeded time limit";
    return "Unknown root cause";
}

FailureRecoveryKernel::RecoveryStats FailureRecoveryKernel::GetStats() const {
    return stats_;
}

} // namespace Sovereign
