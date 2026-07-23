// ============================================================
// RecoveryManager.cpp - Failure Recovery and Retry Logic
// ============================================================

#include "RecoveryManager.hpp"
#include "ExecutiveDirector.hpp"
#include <chrono>
#include <algorithm>
#include <math>

namespace RawrXD::Executive {

// ============================================================
// Lifecycle
// ============================================================
bool RecoveryManager::initialize(ExecutiveDirector* director) {
    director_ = director;
    return true;
}

void RecoveryManager::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    failures_.clear();
}

// ============================================================
// Failure Recording
// ============================================================
uint64_t RecoveryManager::recordFailure(const FailureRecord& failure) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t id = nextFailureId_.fetch_add(1);
    failures_[id] = failure;
    failures_[id].failureId = id;
    failures_[id].timestampMs = currentTimeMs();
    totalFailures_.fetch_add(1);
    
    return id;
}

FailureRecord RecoveryManager::getFailure(uint64_t failureId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = failures_.find(failureId);
    if (it != failures_.end()) {
        return it->second;
    }
    return FailureRecord{};
}

std::vector<FailureRecord> RecoveryManager::getRecentFailures(size_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<FailureRecord> result;
    for (auto it = failures_.rbegin(); it != failures_.rend() && result.size() < count; ++it) {
        result.push_back(it->second);
    }
    return result;
}

std::vector<FailureRecord> RecoveryManager::getFailuresForMission(uint64_t missionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<FailureRecord> result;
    for (const auto& [id, failure] : failures_) {
        if (failure.missionId == missionId) {
            result.push_back(failure);
        }
    }
    return result;
}

// ============================================================
// Recovery Actions
// ============================================================
std::vector<RecoveryAction> RecoveryManager::generateRecoveryOptions(uint64_t failureId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = failures_.find(failureId);
    if (it == failures_.end()) {
        return {};
    }
    
    std::vector<RecoveryAction> options;
    
    if (it->second.retryCount < maxRetries_) {
        options.push_back(RecoveryAction{
            RecoveryStrategy::RETRY_IMMEDIATE,
            "Retry immediately",
            nullptr,
            0.7f,
            1000.0
        });
        
        options.push_back(RecoveryAction{
            RecoveryStrategy::RETRY_WITH_BACKOFF,
            "Retry with exponential backoff",
            nullptr,
            0.6f,
            retryBackoffMs_ * std::pow(2.0, it->second.retryCount)
        });
    }
    
    options.push_back(RecoveryAction{
        RecoveryStrategy::REPLAN,
        "Generate alternative plan",
        nullptr,
        0.5f,
        5000.0
    });
    
    options.push_back(RecoveryAction{
        RecoveryStrategy::ESCALATE,
        "Escalate to human operator",
        nullptr,
        0.9f,
        30000.0
    });
    
    return options;
}

RecoveryAction RecoveryManager::selectBestRecovery(const std::vector<RecoveryAction>& options) {
    if (options.empty()) {
        return RecoveryAction{RecoveryStrategy::ABANDON, "No recovery options available", nullptr, 0.0f, 0.0};
    }
    
    const RecoveryAction* best = &options[0];
    for (const auto& option : options) {
        if (option.successProbability > best->successProbability) {
            best = &option;
        }
    }
    return *best;
}

bool RecoveryManager::attemptRecovery(uint64_t failureId, const RecoveryAction& action) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = failures_.find(failureId);
    if (it == failures_.end()) {
        return false;
    }
    
    it->second.recoveryAttempts.push_back(action.description);
    it->second.retryCount++;
    
    auto start = std::chrono::steady_clock::now();
    bool success = action.execute ? action.execute() : false;
    auto end = std::chrono::steady_clock::now();
    
    double recoveryTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    totalRecoveryTimeMs_ += recoveryTime;
    
    if (success) {
        it->second.isRecovered = true;
        it->second.recoveryMethod = action.description;
        recoveredFailures_.fetch_add(1);
        return true;
    }
    
    return false;
}

// ============================================================
// Configuration
// ============================================================
void RecoveryManager::enableAutomaticRecovery(bool enable) {
    automaticRecovery_ = enable;
}

bool RecoveryManager::isAutomaticRecoveryEnabled() const {
    return automaticRecovery_;
}

void RecoveryManager::setMaxRetries(int maxRetries) {
    maxRetries_ = maxRetries;
}

void RecoveryManager::setRetryBackoffMs(int initialBackoffMs) {
    retryBackoffMs_ = initialBackoffMs;
}

// ============================================================
// Analysis
// ============================================================
std::vector<uint64_t> RecoveryManager::identifyRecurringFailures() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::unordered_map<std::string, std::vector<uint64_t>> byDescription;
    for (const auto& [id, failure] : failures_) {
        byDescription[failure.description].push_back(id);
    }
    
    std::vector<uint64_t> recurring;
    for (const auto& [desc, ids] : byDescription) {
        if (ids.size() >= 3) {
            recurring.insert(recurring.end(), ids.begin(), ids.end());
        }
    }
    return recurring;
}

std::vector<uint64_t> RecoveryManager::identifySystemicIssues() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<uint64_t> systemic;
    for (const auto& [id, failure] : failures_) {
        if (failure.type == FailureType::SYSTEM_ERROR || failure.type == FailureType::RESOURCE_EXHAUSTED) {
            systemic.push_back(id);
        }
    }
    return systemic;
}

std::string RecoveryManager::rootCauseAnalysis(uint64_t failureId) {
    auto failure = getFailure(failureId);
    if (failure.failureId == 0) {
        return "Failure not found";
    }
    
    switch (failure.type) {
        case FailureType::AGENT_ERROR:
            return "Agent execution error: " + failure.description;
        case FailureType::TIMEOUT:
            return "Execution timeout: " + failure.description;
        case FailureType::RESOURCE_EXHAUSTED:
            return "Resource exhaustion: " + failure.description;
        case FailureType::DEPENDENCY_FAILED:
            return "Dependency failure: " + failure.description;
        case FailureType::PLAN_INVALID:
            return "Invalid plan: " + failure.description;
        case FailureType::UNEXPECTED_RESULT:
            return "Unexpected result: " + failure.description;
        case FailureType::SYSTEM_ERROR:
            return "System error: " + failure.description;
        default:
            return "Unknown failure: " + failure.description;
    }
}

std::vector<uint64_t> RecoveryManager::predictPotentialFailures() {
    std::vector<uint64_t> predicted;
    auto recurring = identifyRecurringFailures();
    auto systemic = identifySystemicIssues();
    
    predicted.insert(predicted.end(), recurring.begin(), recurring.end());
    predicted.insert(predicted.end(), systemic.begin(), systemic.end());
    
    std::sort(predicted.begin(), predicted.end());
    predicted.erase(std::unique(predicted.begin(), predicted.end()), predicted.end());
    
    return predicted;
}

void RecoveryManager::registerPreventionMeasure(const std::string& failurePattern, 
                                                 const std::string& preventionAction) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (failurePattern.empty() || preventionAction.empty()) {
        return;
    }
    
    // Store prevention measure - in production this would be used to proactively
    // prevent failures matching the pattern before they occur
    // For now, log it by associating with recent matching failures
    for (auto& [id, failure] : failures_) {
        if (failure.description.find(failurePattern) != std::string::npos && !failure.isRecovered) {
            failure.recoveryAttempts.push_back("PREVENTION: " + preventionAction);
        }
    }
}

// ============================================================
// Stats
// ============================================================
RecoveryManager::Stats RecoveryManager::getStats() const {
    size_t total = totalFailures_.load();
    size_t recovered = recoveredFailures_.load();
    
    float successRate = total > 0 ? static_cast<float>(recovered) / total : 0.0f;
    double avgTime = total > 0 ? totalRecoveryTimeMs_ / total : 0.0;
    
    return Stats{
        total,
        recovered,
        total - recovered,
        automaticRecoveries_.load(),
        successRate,
        avgTime
    };
}

// ============================================================
// Helpers
// ============================================================
uint64_t RecoveryManager::currentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

} // namespace RawrXD::Executive
