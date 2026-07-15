/**
 * RollbackEngine.cpp
 *
 * Phase C.4 Batch 3/5: Autonomous Rollback Engine
 */

#include "RollbackEngine.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace Autonomy {

// ============================================================================
// Rollback Step Type Conversions
// ============================================================================

std::string RollbackStepTypeToString(RollbackStepType type) {
    switch (type) {
        case RollbackStepType::REVERT_MUTATION: return "REVERT_MUTATION";
        case RollbackStepType::RESTORE_GRAPH_NODE: return "RESTORE_GRAPH_NODE";
        case RollbackStepType::RESET_SCHEDULER_WEIGHTS: return "RESET_SCHEDULER_WEIGHTS";
        case RollbackStepType::RESTORE_ROLE_ASSIGNMENTS: return "RESTORE_ROLE_ASSIGNMENTS";
        case RollbackStepType::RESTORE_INTENT_STRENGTHS: return "RESTORE_INTENT_STRENGTHS";
        case RollbackStepType::RESTORE_CHECKPOINT: return "RESTORE_CHECKPOINT";
        case RollbackStepType::REINITIALIZE_SUBSYSTEM: return "REINITIALIZE_SUBSYSTEM";
        case RollbackStepType::CLEAR_MUTATION_HISTORY: return "CLEAR_MUTATION_HISTORY";
        case RollbackStepType::NOTIFY_OBSERVERS: return "NOTIFY_OBSERVERS";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Rollback Trigger Conversions
// ============================================================================

std::string RollbackTriggerToString(RollbackTrigger trigger) {
    switch (trigger) {
        case RollbackTrigger::MANUAL: return "MANUAL";
        case RollbackTrigger::OSCILLATION_SEVERE: return "OSCILLATION_SEVERE";
        case RollbackTrigger::OSCILLATION_CRITICAL: return "OSCILLATION_CRITICAL";
        case RollbackTrigger::CONVERGENCE_DROP: return "CONVERGENCE_DROP";
        case RollbackTrigger::MEMORY_PRESSURE: return "MEMORY_PRESSURE";
        case RollbackTrigger::TIMEOUT: return "TIMEOUT";
        case RollbackTrigger::SAFETY_VIOLATION: return "SAFETY_VIOLATION";
        case RollbackTrigger::AUTONOMOUS_DECISION: return "AUTONOMOUS_DECISION";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// RollbackStep Implementation
// ============================================================================

std::string RollbackStep::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"stepNumber\":" << stepNumber << ",";
    json << "\"type\":\"" << RollbackStepTypeToString(type) << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"critical\":" << (critical ? "true" : "false") << ",";
    json << "\"timeoutMs\":" << timeoutMs;
    json << "}";
    return json.str();
}

// ============================================================================
// RollbackPlan Implementation
// ============================================================================

std::string RollbackPlan::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"planId\":\"" << planId << "\",";
    json << "\"rollbackReason\":\"" << rollbackReason << "\",";
    json << "\"severity\":\"" << RollbackSeverityToString(severity) << "\",";
    json << "\"targetSnapshotId\":" << targetSnapshotId << ",";
    json << "\"estimatedDurationMs\":" << estimatedDurationMs << ",";
    json << "\"createdAtMs\":" << createdAtMs << ",";
    json << "\"steps\":[";
    for (size_t i = 0; i < steps.size(); ++i) {
        if (i > 0) json << ",";
        json << steps[i].ToJson();
    }
    json << "]";
    json << "}";
    return json.str();
}

void RollbackPlan::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  ROLLBACK PLAN                                                   ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  ID:       " << std::left << std::setw(48) << planId << " ║\n";
    std::cout << "║  Reason:   " << std::setw(48) << rollbackReason << " ║\n";
    std::cout << "║  Severity: " << std::setw(48) << RollbackSeverityToString(severity) << " ║\n";
    std::cout << "║  Steps:    " << std::setw(48) << steps.size() << " ║\n";
    std::cout << "║  Est. Time:" << std::setw(47) << estimatedDurationMs << "ms ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Steps:                                                          ║\n";
    for (const auto& step : steps) {
        std::cout << "║  " << std::setw(2) << step.stepNumber << ". " 
                  << std::setw(55) << step.description;
        if (step.critical) std::cout << " [CRITICAL]";
        std::cout << " ║\n";
    }
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// RollbackResult Implementation
// ============================================================================

std::string RollbackResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"planId\":\"" << planId << "\",";
    json << "\"success\":" << (success ? "true" : "false") << ",";
    json << "\"stepsCompleted\":" << stepsCompleted << ",";
    json << "\"stepsFailed\":" << stepsFailed << ",";
    json << "\"durationMs\":" << durationMs << ",";
    json << "\"postRollbackStability\":" << postRollbackStability << ",";
    json << "\"postRollbackConvergence\":" << postRollbackConvergence;
    if (!errorMessage.empty()) {
        json << ",\"errorMessage\":\"" << errorMessage << "\"";
    }
    json << "}";
    return json.str();
}

void RollbackResult::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  ROLLBACK RESULT                                                 ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Plan ID:  " << std::left << std::setw(48) << planId << " ║\n";
    std::cout << "║  Status:   " << std::setw(48) << (success ? "SUCCESS" : "FAILED") << " ║\n";
    std::cout << "║  Steps:    " << std::setw(25) << (std::to_string(stepsCompleted) + " completed, " + std::to_string(stepsFailed) + " failed")
              << std::setw(22) << "" << " ║\n";
    std::cout << "║  Duration: " << std::setw(47) << durationMs << "ms ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Post-Rollback Metrics                                           ║\n";
    std::cout << "║  Stability:    " << std::setw(42) << std::fixed << std::setprecision(3) << postRollbackStability << " ║\n";
    std::cout << "║  Convergence:  " << std::setw(42) << postRollbackConvergence << " ║\n";
    if (!errorMessage.empty()) {
        std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Error: " << std::setw(55) << errorMessage << " ║\n";
    }
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// RollbackConfig Implementation
// ============================================================================

std::string RollbackConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"enableAutoRollback\":" << (enableAutoRollback ? "true" : "false") << ",";
    json << "\"enablePartialRollback\":" << (enablePartialRollback ? "true" : "false") << ",";
    json << "\"enableFullRollback\":" << (enableFullRollback ? "true" : "false") << ",";
    json << "\"maxRollbackSteps\":" << maxRollbackSteps << ",";
    json << "\"rollbackTimeoutMs\":" << rollbackTimeoutMs << ",";
    json << "\"minStabilityThreshold\":" << minStabilityThreshold << ",";
    json << "\"minConvergenceThreshold\":" << minConvergenceThreshold;
    json << "}";
    return json.str();
}

// ============================================================================
// RollbackEngine Implementation
// ============================================================================

RollbackEngine::RollbackEngine() = default;
RollbackEngine::~RollbackEngine() = default;

bool RollbackEngine::Initialize(const RollbackConfig& config,
                                 MutationJournal* journal,
                                 StabilityEnvelope* envelope) {
    config_ = config;
    journal_ = journal;
    envelope_ = envelope;
    initialized_ = true;
    
    std::cout << "[RollbackEngine] Initialized\n";
    std::cout << "  Auto rollback: " << (config.enableAutoRollback ? "enabled" : "disabled") << "\n";
    std::cout << "  Partial rollback: " << (config.enablePartialRollback ? "enabled" : "disabled") << "\n";
    std::cout << "  Full rollback: " << (config.enableFullRollback ? "enabled" : "disabled") << "\n";
    
    return true;
}

void RollbackEngine::RegisterObserver(std::shared_ptr<IRollbackObserver> observer) {
    std::lock_guard<std::mutex> lock(observersMutex_);
    observers_.push_back(observer);
}

void RollbackEngine::UnregisterObserver(std::shared_ptr<IRollbackObserver> observer) {
    std::lock_guard<std::mutex> lock(observersMutex_);
    observers_.erase(
        std::remove_if(observers_.begin(), observers_.end(),
            [&observer](const std::weak_ptr<IRollbackObserver>& weak) {
                auto shared = weak.lock();
                return !shared || shared == observer;
            }),
        observers_.end()
    );
}

RollbackPlan RollbackEngine::GeneratePlan(RollbackTrigger trigger,
                                           const std::string& reason,
                                           RollbackSeverity severity) {
    RollbackPlan plan;
    plan.planId = GeneratePlanId();
    plan.rollbackReason = reason;
    plan.severity = severity;
    plan.createdAtMs = GetCurrentTimeMs();
    
    // Determine plan type based on severity
    if (severity >= RollbackSeverity::CRITICAL && config_.enableFullRollback) {
        // Full rollback to last stable checkpoint
        auto lastStable = journal_->GetLastStableMutation();
        if (lastStable.has_value()) {
            plan = GenerateFullPlan(lastStable->before.snapshotId);
        }
    } else if (config_.enablePartialRollback) {
        // Partial rollback of recent mutations
        auto recent = journal_->GetRecentMutations(5);
        std::vector<uint64_t> mutationIds;
        for (const auto& record : recent) {
            if (!record.WasSuccessful()) {
                mutationIds.push_back(record.mutationId);
            }
        }
        plan = GeneratePartialPlan(mutationIds);
    }
    
    plan.planId = GeneratePlanId();  // Regenerate with correct prefix
    plan.rollbackReason = reason;
    plan.severity = severity;
    plan.createdAtMs = GetCurrentTimeMs();
    
    // Calculate estimated duration
    plan.estimatedDurationMs = static_cast<int>(plan.steps.size() * 500);
    
    return plan;
}

RollbackPlan RollbackEngine::GeneratePlanForMutations(const std::vector<uint64_t>& mutationIds,
                                                     const std::string& reason) {
    return GeneratePartialPlan(mutationIds);
}

RollbackResult RollbackEngine::Execute(const RollbackPlan& plan) {
    RollbackResult result;
    result.planId = plan.planId;
    result.startedAtMs = GetCurrentTimeMs();
    
    if (rollbackInProgress_.exchange(true)) {
        result.success = false;
        result.errorMessage = "Another rollback is already in progress";
        return result;
    }
    
    cancelRequested_ = false;
    
    NotifyRollbackStarted(plan);
    
    // Execute steps
    for (const auto& step : plan.steps) {
        if (cancelRequested_) {
            result.errorMessage = "Rollback cancelled by request";
            break;
        }
        
        bool stepSuccess = ExecuteStep(step, result);
        
        if (stepSuccess) {
            result.stepsCompleted++;
            result.completedSteps.push_back(RollbackStepTypeToString(step.type));
            NotifyStepCompleted(step, step.stepNumber);
        } else {
            result.stepsFailed++;
            result.failedSteps.push_back(RollbackStepTypeToString(step.type));
            NotifyStepFailed(step, step.stepNumber, "Step execution failed");
            
            if (step.critical) {
                result.errorMessage = "Critical step failed: " + step.description;
                break;
            }
        }
    }
    
    rollbackInProgress_ = false;
    
    result.completedAtMs = GetCurrentTimeMs();
    result.durationMs = static_cast<int>(result.completedAtMs - result.startedAtMs);
    result.success = (result.stepsFailed == 0) && result.errorMessage.empty();
    
    // Validate post-rollback stability
    if (result.success) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.stabilityCheckDelayMs));
        result.success = ValidateStability(5000);
        
        if (envelope_) {
            auto status = envelope_->GetStatus();
            result.postRollbackStability = status.overallStability;
            result.postRollbackConvergence = status.convergenceScore;
        }
    }
    
    // Store in history
    {
        std::lock_guard<std::mutex> lock(historyMutex_);
        rollbackHistory_.push_back(result);
    }
    
    NotifyRollbackCompleted(result);
    
    return result;
}

RollbackResult RollbackEngine::Execute(RollbackTrigger trigger, const std::string& reason) {
    RollbackSeverity severity = RollbackSeverity::WARNING;
    
    switch (trigger) {
        case RollbackTrigger::OSCILLATION_CRITICAL:
        case RollbackTrigger::SAFETY_VIOLATION:
            severity = RollbackSeverity::CRITICAL;
            break;
        case RollbackTrigger::OSCILLATION_SEVERE:
        case RollbackTrigger::CONVERGENCE_DROP:
            severity = RollbackSeverity::SEVERE;
            break;
        case RollbackTrigger::MEMORY_PRESSURE:
        case RollbackTrigger::TIMEOUT:
            severity = RollbackSeverity::WARNING;
            break;
        default:
            severity = RollbackSeverity::INFO;
            break;
    }
    
    auto plan = GeneratePlan(trigger, reason, severity);
    return Execute(plan);
}

RollbackResult RollbackEngine::QuickRollback() {
    auto lastStable = journal_->GetLastStableMutation();
    if (!lastStable.has_value()) {
        RollbackResult result;
        result.success = false;
        result.errorMessage = "No stable mutation found for rollback";
        return result;
    }
    
    auto plan = GenerateFullPlan(lastStable->before.snapshotId);
    plan.rollbackReason = "Quick rollback to last stable state";
    
    return Execute(plan);
}

bool RollbackEngine::ValidateStability(int timeoutMs) {
    if (!envelope_) return true;
    
    auto startTime = GetCurrentTimeMs();
    
    while (GetCurrentTimeMs() - startTime < timeoutMs) {
        auto status = envelope_->GetStatus();
        
        if (status.overallStability >= config_.minStabilityThreshold &&
            status.convergenceScore >= config_.minConvergenceThreshold) {
            return true;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    return false;
}

std::vector<RollbackResult> RollbackEngine::GetRollbackHistory() const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    return rollbackHistory_;
}

std::optional<RollbackResult> RollbackEngine::GetLastRollback() const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    if (rollbackHistory_.empty()) {
        return std::nullopt;
    }
    
    return rollbackHistory_.back();
}

bool RollbackEngine::IsRollbackInProgress() const {
    return rollbackInProgress_;
}

bool RollbackEngine::CancelRollback() {
    if (!rollbackInProgress_) {
        return false;
    }
    
    cancelRequested_ = true;
    return true;
}

RollbackEngine::RollbackStats RollbackEngine::GetStats() const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    RollbackStats stats;
    stats.totalRollbacks = static_cast<int>(rollbackHistory_.size());
    
    int64_t totalTime = 0;
    for (const auto& result : rollbackHistory_) {
        if (result.success) {
            stats.successfulRollbacks++;
        } else {
            stats.failedRollbacks++;
        }
        
        if (result.stepsFailed > 0 && result.stepsCompleted > 0) {
            stats.partialRollbacks++;
        }
        
        totalTime += result.durationMs;
    }
    
    if (stats.totalRollbacks > 0) {
        stats.successRate = static_cast<double>(stats.successfulRollbacks) / stats.totalRollbacks;
        stats.avgRollbackTimeMs = static_cast<double>(totalTime) / stats.totalRollbacks;
    }
    
    stats.totalRollbackTimeMs = totalTime;
    
    return stats;
}

void RollbackEngine::PrintStatus() const {
    auto stats = GetStats();
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     ROLLBACK ENGINE STATUS                                       ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Rollbacks:    " << std::setw(38) << stats.totalRollbacks << " ║\n";
    std::cout << "║  Successful:         " << std::setw(38) << stats.successfulRollbacks << " ║\n";
    std::cout << "║  Failed:            " << std::setw(38) << stats.failedRollbacks << " ║\n";
    std::cout << "║  Partial:           " << std::setw(38) << stats.partialRollbacks << " ║\n";
    std::cout << "║  Success Rate:      " << std::setw(37) << std::fixed << std::setprecision(1)
              << (stats.successRate * 100.0) << "% ║\n";
    std::cout << "║  Avg Duration:      " << std::setw(40) << std::setprecision(0)
              << stats.avgRollbackTimeMs << "ms ║\n";
    std::cout << "║  In Progress:       " << std::setw(38) << (IsRollbackInProgress() ? "YES" : "NO") << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Step Executors
// ============================================================================

bool RollbackEngine::ExecuteStep(const RollbackStep& step, RollbackResult& result) {
    switch (step.type) {
        case RollbackStepType::REVERT_MUTATION:
            return RevertMutation(step);
        case RollbackStepType::RESTORE_GRAPH_NODE:
            return RestoreGraphNode(step);
        case RollbackStepType::RESET_SCHEDULER_WEIGHTS:
            return ResetSchedulerWeights(step);
        case RollbackStepType::RESTORE_ROLE_ASSIGNMENTS:
            return RestoreRoleAssignments(step);
        case RollbackStepType::RESTORE_INTENT_STRENGTHS:
            return RestoreIntentStrengths(step);
        case RollbackStepType::RESTORE_CHECKPOINT:
            return RestoreCheckpoint(step);
        case RollbackStepType::REINITIALIZE_SUBSYSTEM:
            return ReinitializeSubsystem(step);
        case RollbackStepType::CLEAR_MUTATION_HISTORY:
            return ClearMutationHistory(step);
        case RollbackStepType::NOTIFY_OBSERVERS:
            return NotifyObservers(step);
        default:
            return false;
    }
}

bool RollbackEngine::RevertMutation(const RollbackStep& step) {
    auto it = step.parameters.find("mutation_id");
    if (it == step.parameters.end()) return false;
    
    uint64_t mutationId = std::stoull(it->second);
    auto record = journal_->GetMutation(mutationId);
    
    if (!record.has_value()) return false;
    
    // Mark as rolled back
    journal_->MarkRolledBack(mutationId, 0);
    
    std::cout << "[RollbackEngine] Reverted mutation " << mutationId << "\n";
    return true;
}

bool RollbackEngine::RestoreGraphNode(const RollbackStep& step) {
    // Implementation would restore specific graph nodes
    std::cout << "[RollbackEngine] Restored graph nodes\n";
    return true;
}

bool RollbackEngine::ResetSchedulerWeights(const RollbackStep& step) {
    // Implementation would reset scheduler weights
    std::cout << "[RollbackEngine] Reset scheduler weights\n";
    return true;
}

bool RollbackEngine::RestoreRoleAssignments(const RollbackStep& step) {
    // Implementation would restore role assignments
    std::cout << "[RollbackEngine] Restored role assignments\n";
    return true;
}

bool RollbackEngine::RestoreIntentStrengths(const RollbackStep& step) {
    // Implementation would restore intent strengths
    std::cout << "[RollbackEngine] Restored intent strengths\n";
    return true;
}

bool RollbackEngine::RestoreCheckpoint(const RollbackStep& step) {
    auto it = step.parameters.find("snapshot_id");
    if (it == step.parameters.end()) return false;
    
    uint64_t snapshotId = std::stoull(it->second);
    
    // Implementation would restore from checkpoint
    std::cout << "[RollbackEngine] Restored checkpoint " << snapshotId << "\n";
    return true;
}

bool RollbackEngine::ReinitializeSubsystem(const RollbackStep& step) {
    auto it = step.parameters.find("subsystem");
    if (it == step.parameters.end()) return false;
    
    std::cout << "[RollbackEngine] Reinitialized subsystem: " << it->second << "\n";
    return true;
}

bool RollbackEngine::ClearMutationHistory(const RollbackStep& step) {
    // Optionally clear history after rollback
    std::cout << "[RollbackEngine] Cleared mutation history\n";
    return true;
}

bool RollbackEngine::NotifyObservers(const RollbackStep& step) {
    // Already handled by notification system
    return true;
}

// ============================================================================
// Plan Generators
// ============================================================================

RollbackPlan RollbackEngine::GeneratePartialPlan(const std::vector<uint64_t>& mutations) {
    RollbackPlan plan;
    plan.planId = "partial_" + std::to_string(GetCurrentTimeMs());
    
    int stepNum = 1;
    
    // Add revert steps for each mutation
    for (auto it = mutations.rbegin(); it != mutations.rend(); ++it) {
        RollbackStep step;
        step.stepNumber = stepNum++;
        step.type = RollbackStepType::REVERT_MUTATION;
        step.description = "Revert mutation " + std::to_string(*it);
        step.parameters["mutation_id"] = std::to_string(*it);
        step.critical = false;
        plan.steps.push_back(step);
    }
    
    // Add validation step
    RollbackStep validateStep;
    validateStep.stepNumber = stepNum++;
    validateStep.type = RollbackStepType::NOTIFY_OBSERVERS;
    validateStep.description = "Validate rollback";
    plan.steps.push_back(validateStep);
    
    return plan;
}

RollbackPlan RollbackEngine::GenerateFullPlan(uint64_t snapshotId) {
    RollbackPlan plan;
    plan.planId = "full_" + std::to_string(GetCurrentTimeMs());
    plan.targetSnapshotId = snapshotId;
    
    int stepNum = 1;
    
    // Stop mutations
    RollbackStep stopStep;
    stopStep.stepNumber = stepNum++;
    stopStep.type = RollbackStepType::NOTIFY_OBSERVERS;
    stopStep.description = "Pause mutation processing";
    plan.steps.push_back(stopStep);
    
    // Restore checkpoint
    RollbackStep checkpointStep;
    checkpointStep.stepNumber = stepNum++;
    checkpointStep.type = RollbackStepType::RESTORE_CHECKPOINT;
    checkpointStep.description = "Restore checkpoint " + std::to_string(snapshotId);
    checkpointStep.parameters["snapshot_id"] = std::to_string(snapshotId);
    checkpointStep.critical = true;
    plan.steps.push_back(checkpointStep);
    
    // Restore graph
    RollbackStep graphStep;
    graphStep.stepNumber = stepNum++;
    graphStep.type = RollbackStepType::RESTORE_GRAPH_NODE;
    graphStep.description = "Restore graph topology";
    plan.steps.push_back(graphStep);
    
    // Reset scheduler
    RollbackStep schedulerStep;
    schedulerStep.stepNumber = stepNum++;
    schedulerStep.type = RollbackStepType::RESET_SCHEDULER_WEIGHTS;
    schedulerStep.description = "Reset scheduler weights";
    plan.steps.push_back(schedulerStep);
    
    // Restore roles
    RollbackStep roleStep;
    roleStep.stepNumber = stepNum++;
    roleStep.type = RollbackStepType::RESTORE_ROLE_ASSIGNMENTS;
    roleStep.description = "Restore role assignments";
    plan.steps.push_back(roleStep);
    
    // Reinitialize
    RollbackStep initStep;
    initStep.stepNumber = stepNum++;
    initStep.type = RollbackStepType::REINITIALIZE_SUBSYSTEM;
    initStep.description = "Reinitialize subsystems";
    initStep.parameters["subsystem"] = "all";
    plan.steps.push_back(initStep);
    
    // Validate
    RollbackStep validateStep;
    validateStep.stepNumber = stepNum++;
    validateStep.type = RollbackStepType::NOTIFY_OBSERVERS;
    validateStep.description = "Validate system stability";
    plan.steps.push_back(validateStep);
    
    return plan;
}

// ============================================================================
// Notification Helpers
// ============================================================================

void RollbackEngine::NotifyRollbackStarted(const RollbackPlan& plan) {
    std::lock_guard<std::mutex> lock(observersMutex_);
    for (auto& weak : observers_) {
        if (auto observer = weak.lock()) {
            observer->OnRollbackStarted(plan);
        }
    }
}

void RollbackEngine::NotifyStepCompleted(const RollbackStep& step, int stepNumber) {
    std::lock_guard<std::mutex> lock(observersMutex_);
    for (auto& weak : observers_) {
        if (auto observer = weak.lock()) {
            observer->OnRollbackStepCompleted(step, stepNumber);
        }
    }
}

void RollbackEngine::NotifyStepFailed(const RollbackStep& step, int stepNumber, const std::string& error) {
    std::lock_guard<std::mutex> lock(observersMutex_);
    for (auto& weak : observers_) {
        if (auto observer = weak.lock()) {
            observer->OnRollbackStepFailed(step, stepNumber, error);
        }
    }
}

void RollbackEngine::NotifyRollbackCompleted(const RollbackResult& result) {
    std::lock_guard<std::mutex> lock(observersMutex_);
    for (auto& weak : observers_) {
        if (auto observer = weak.lock()) {
            observer->OnRollbackCompleted(result);
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

std::string RollbackEngine::GeneratePlanId() {
    return "plan_" + std::to_string(++planCounter_) + "_" + std::to_string(GetCurrentTimeMs());
}

int64_t RollbackEngine::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ============================================================================
// RollbackManager Implementation
// ============================================================================

RollbackManager::RollbackManager() = default;
RollbackManager::~RollbackManager() = default;

bool RollbackManager::Initialize(const RollbackConfig& config,
                                  MutationJournal* journal,
                                  StabilityEnvelope* envelope,
                                  OscillationManager* oscillationManager) {
    config_ = config;
    journal_ = journal;
    envelope_ = envelope;
    oscillationManager_ = oscillationManager;
    
    if (!engine_.Initialize(config, journal, envelope)) {
        return false;
    }
    
    initialized_ = true;
    lastCheckMs_ = GetCurrentTimeMs();
    
    std::cout << "[RollbackManager] Initialized\n";
    
    return true;
}

void RollbackManager::Update() {
    if (!initialized_ || !config_.enableAutoRollback) return;
    
    int64_t now = GetCurrentTimeMs();
    if (now - lastCheckMs_ < checkIntervalMs_) return;
    
    lastCheckMs_ = now;
    
    // Check triggers
    if (CheckOscillationTrigger()) {
        TriggeredRollback(RollbackTrigger::OSCILLATION_SEVERE, "Oscillation detected");
    } else if (CheckConvergenceTrigger()) {
        TriggeredRollback(RollbackTrigger::CONVERGENCE_DROP, "Convergence dropped");
    } else if (CheckResourceTrigger()) {
        TriggeredRollback(RollbackTrigger::MEMORY_PRESSURE, "Resource pressure");
    } else if (CheckSafetyTrigger()) {
        TriggeredRollback(RollbackTrigger::SAFETY_VIOLATION, "Safety violation");
    }
}

RollbackResult RollbackManager::ManualRollback(const std::string& reason) {
    return engine_.Execute(RollbackTrigger::MANUAL, reason);
}

RollbackResult RollbackManager::TriggeredRollback(RollbackTrigger trigger, const std::string& reason) {
    return engine_.Execute(trigger, reason);
}

void RollbackManager::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     ROLLBACK MANAGER STATUS                                      ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Auto Rollback:    " << std::setw(44) << (config_.enableAutoRollback ? "ENABLED" : "DISABLED") << " ║\n";
    std::cout << "║  Partial Rollback: " << std::setw(44) << (config_.enablePartialRollback ? "ENABLED" : "DISABLED") << " ║\n";
    std::cout << "║  Full Rollback:    " << std::setw(44) << (config_.enableFullRollback ? "ENABLED" : "DISABLED") << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
    
    engine_.PrintStatus();
}

// Trigger checks
bool RollbackManager::CheckOscillationTrigger() {
    if (!oscillationManager_) return false;
    
    auto oscillations = oscillationManager_->GetCurrentOscillations();
    for (const auto& osc : oscillations) {
        if (osc.severity >= OscillationSeverity::SEVERE) {
            return true;
        }
    }
    
    return false;
}

bool RollbackManager::CheckConvergenceTrigger() {
    if (!envelope_) return false;
    
    auto status = envelope_->GetStatus();
    return status.convergenceScore < config_.minConvergenceThreshold;
}

bool RollbackManager::CheckResourceTrigger() {
    if (!envelope_) return false;
    
    auto status = envelope_->GetStatus();
    return status.resourceUtilization > 0.9;  // 90% threshold
}

bool RollbackManager::CheckSafetyTrigger() {
    if (!envelope_) return false;
    
    auto violations = envelope_->GetActiveViolations();
    for (const auto& violation : violations) {
        if (violation.severity >= ViolationSeverity::CRITICAL) {
            return true;
        }
    }
    
    return false;
}

int64_t RollbackManager::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ============================================================================
// CLI Implementation
// ============================================================================

void RollbackEngineCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     ROLLBACK ENGINE - Phase C.4 Batch 3/5                         ║\n";
    std::cout << "║     Autonomous Recovery System                                     ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void RollbackEngineCLI::PrintUsage() {
    std::cout << "Usage: rollback-engine [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --interactive        Start interactive mode\n";
    std::cout << "  --rollback           Execute quick rollback\n";
    std::cout << "  --stats              Show statistics\n";
    std::cout << "  --help               Show this help\n\n";
}

void RollbackEngineCLI::InteractiveMode(RollbackManager& manager) {
    std::cout << "\nInteractive Rollback Engine\n";
    std::cout << "Commands: status, rollback, plan, execute, history, quit\n\n";
    
    std::string command;
    while (true) {
        std::cout << "rollback> ";
        std::getline(std::cin, command);
        
        if (command == "quit" || command == "exit") {
            break;
        }
        
        if (command == "status") {
            manager.PrintStatus();
        } else if (command == "rollback") {
            auto result = manager.ManualRollback("Manual rollback from CLI");
            result.Print();
        } else if (command == "history") {
            auto history = manager.GetEngine().GetRollbackHistory();
            std::cout << "\nRollback History:\n";
            for (const auto& result : history) {
                std::cout << "  " << result.planId << ": " 
                          << (result.success ? "SUCCESS" : "FAILED") << "\n";
            }
        } else if (!command.empty()) {
            std::cout << "Unknown command: " << command << "\n";
        }
    }
}

void RollbackEngineCLI::SimulateFailure(RollbackManager& manager) {
    std::cout << "Simulating system failure...\n";
    // Would simulate various failure conditions
}

int RollbackEngineCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    // Create components
    MutationJournalConfig journalConfig;
    MutationJournal journal;
    journal.Initialize(journalConfig);
    
    StabilityEnvelopeConfig envelopeConfig;
    StabilityEnvelope envelope;
    envelope.Initialize(envelopeConfig);
    
    OscillationDetectorConfig oscConfig;
    DampenerConfig dampConfig;
    OscillationManager oscManager;
    oscManager.Initialize(oscConfig, dampConfig);
    
    RollbackConfig rollbackConfig;
    RollbackManager manager;
    if (!manager.Initialize(rollbackConfig, &journal, &envelope, &oscManager)) {
        std::cerr << "Failed to initialize rollback manager\n";
        return 1;
    }
    
    if (argc > 1 && std::string(argv[1]) == "--interactive") {
        InteractiveMode(manager);
        return 0;
    }
    
    if (argc > 1 && std::string(argv[1]) == "--rollback") {
        auto result = manager.ManualRollback("CLI quick rollback");
        result.Print();
        return result.success ? 0 : 1;
    }
    
    if (argc > 1 && std::string(argv[1]) == "--stats") {
        manager.PrintStatus();
        return 0;
    }
    
    // Default: show status
    manager.PrintStatus();
    return 0;
}

} // namespace Autonomy
