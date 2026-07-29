// ============================================================================
// ExecutionSpine.cpp - Agent Runtime Loop Implementation
// ============================================================================

#include "ExecutionSpine.hpp"
#include <iostream>
#include <thread>

namespace Sovereign {

ExecutionSpine::ExecutionSpine() = default;
ExecutionSpine::~ExecutionSpine() {
    Shutdown();
}

bool ExecutionSpine::Initialize(const SpineConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

void ExecutionSpine::Shutdown() {
    Stop();
    initialized_ = false;
}

void ExecutionSpine::Start() {
    if (running_.exchange(true)) return;
    spineThread_ = std::thread(&ExecutionSpine::SpineLoop, this);
}

void ExecutionSpine::Stop() {
    if (!running_.exchange(false)) return;
    cv_.notify_all();
    if (spineThread_.joinable()) spineThread_.join();
}

uint64_t ExecutionSpine::SubmitIntent(const std::string& intent) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t id = nextIntentId_++;
    Intent in;
    in.id = id;
    in.text = intent;
    in.phase = SpinePhase::INTENT_PARSING;
    in.complete = false;
    in.created = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    intents_[id] = in;
    intentQueue_.push(id);
    stats_.totalIntents++;
    cv_.notify_one();
    
    return id;
}

void ExecutionSpine::SpineLoop() {
    while (running_.load()) {
        uint64_t intentId = 0;
        
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !intentQueue_.empty() || !running_.load(); });
            if (!running_.load()) break;
            
            intentId = intentQueue_.front();
            intentQueue_.pop();
        }
        
        if (intentId > 0) {
            ProcessIntent(intentId);
        }
    }
}

void ExecutionSpine::ProcessIntent(uint64_t intentId) {
    auto& intent = intents_[intentId];
    
    // Phase 1: Parse intent
    TransitionTo(SpinePhase::INTENT_PARSING);
    SpineEvent parseEvent;
    parseEvent.id = intentId;
    parseEvent.phase = SpinePhase::INTENT_PARSING;
    parseEvent.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    parseEvent.description = "Parsing: " + intent.text;
    parseEvent.success = true;
    intent.events.push_back(parseEvent);
    
    // Phase 2: Generate plan
    TransitionTo(SpinePhase::PLAN_GENERATION);
    if (!ExecutePlan(intentId)) {
        HandleError(intentId, "Plan generation failed");
        return;
    }
    
    // Phase 3: Execute tools
    TransitionTo(SpinePhase::TOOL_EXECUTION);
    if (!ExecuteTools(intentId)) {
        HandleError(intentId, "Tool execution failed");
        return;
    }
    
    // Phase 4: Validate
    TransitionTo(SpinePhase::VALIDATION);
    if (!ValidateResults(intentId)) {
        if (config_.autoRecover && stats_.totalValidations < config_.validationRetries) {
            TriggerRecovery("Validation failed, retrying");
            return;
        }
        HandleError(intentId, "Validation failed");
        return;
    }
    
    // Phase 5: Commit
    TransitionTo(SpinePhase::COMMIT);
    if (!CommitResults(intentId)) {
        HandleError(intentId, "Commit failed");
        return;
    }
    
    // Phase 6: Report
    TransitionTo(SpinePhase::REPORT);
    GenerateReport(intentId);
    
    intent.complete = true;
    intent.success = true;
    intent.completed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    stats_.completedIntents++;
    
    if (completionCallback_) completionCallback_(intentId, true);
    TransitionTo(SpinePhase::IDLE);
}

bool ExecutionSpine::ExecutePlan(uint64_t intentId) {
    stats_.totalValidations++;
    return true;
}

bool ExecutionSpine::ExecuteTools(uint64_t intentId) {
    stats_.totalToolCalls++;
    return true;
}

bool ExecutionSpine::ValidateResults(uint64_t intentId) {
    return true;
}

bool ExecutionSpine::CommitResults(uint64_t intentId) {
    stats_.totalCommits++;
    return true;
}

void ExecutionSpine::GenerateReport(uint64_t intentId) {
    auto& intent = intents_[intentId];
    SpineEvent reportEvent;
    reportEvent.id = intentId;
    reportEvent.phase = SpinePhase::REPORT;
    reportEvent.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    reportEvent.description = "Completed: " + intent.text;
    reportEvent.success = true;
    intent.events.push_back(reportEvent);
}

void ExecutionSpine::HandleError(uint64_t intentId, const std::string& error) {
    auto& intent = intents_[intentId];
    intent.complete = true;
    intent.success = false;
    stats_.failedIntents++;
    
    if (errorCallback_) errorCallback_(error);
    if (completionCallback_) completionCallback_(intentId, false);
    TransitionTo(SpinePhase::IDLE);
}

void ExecutionSpine::TransitionTo(SpinePhase phase) {
    currentPhase_ = phase;
    if (phaseCallback_) phaseCallback_(phase);
}

bool ExecutionSpine::TriggerRecovery(const std::string& reason) {
    inRecovery_ = true;
    TransitionTo(SpinePhase::RECOVERY);
    // Recovery logic
    inRecovery_ = false;
    return true;
}

ExecutionSpine::SpineStats ExecutionSpine::GetStats() const {
    return stats_;
}

void ExecutionSpine::ResetStats() {
    stats_ = SpineStats{};
}

} // namespace Sovereign
