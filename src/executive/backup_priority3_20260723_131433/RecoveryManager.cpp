// ============================================================================
// RecoveryManager.cpp - Implementation
// ============================================================================

#include "RecoveryManager.hpp"
#include "ExecutiveDirector.hpp"
#include <algorithm>

namespace RawrXD {
namespace Executive {

struct RecoveryManager::Impl {
    ExecutiveDirector* director = nullptr;
    std::unordered_map<std::string, FailureRecord> failures;
    bool automaticRecovery = true;
    int maxRetries = 3;
    int retryBackoffMs = 1000;
    size_t totalFailures = 0;
    size_t recoveredFailures = 0;
    size_t unrecoveredFailures = 0;
    size_t automaticRecoveries = 0;
    double totalRecoveryTimeMs = 0.0;
};

RecoveryManager::RecoveryManager() : pImpl_(std::make_unique<Impl>()) {}
RecoveryManager::~RecoveryManager() = default;

bool RecoveryManager::Initialize(ExecutiveDirector* director) {
    pImpl_->director = director;
    return true;
}

void RecoveryManager::Shutdown() {}

std::string RecoveryManager::RecordFailure(const FailureRecord& failure) {
    pImpl_->failures[failure.failureId] = failure;
    pImpl_->totalFailures++;
    return failure.failureId;
}

FailureRecord RecoveryManager::GetFailure(const std::string& failureId) {
    auto it = pImpl_->failures.find(failureId);
    if (it != pImpl_->failures.end()) {
        return it->second;
    }
    return {};
}

std::vector<FailureRecord> RecoveryManager::GetRecentFailures(size_t count) {
    std::vector<FailureRecord> results;
    for (const auto& [id, failure] : pImpl_->failures) {
        results.push_back(failure);
    }
    // Sort by timestamp (most recent first)
    std::sort(results.begin(), results.end(), [](const FailureRecord& a, const FailureRecord& b) {
        return a.timestamp > b.timestamp;
    });
    if (results.size() > count) {
        results.resize(count);
    }
    return results;
}

std::vector<FailureRecord> RecoveryManager::GetFailuresForMission(const std::string& missionId) {
    std::vector<FailureRecord> results;
    for (const auto& [id, failure] : pImpl_->failures) {
        if (failure.missionId == missionId) {
            results.push_back(failure);
        }
    }
    return results;
}

std::vector<RecoveryAction> RecoveryManager::GenerateRecoveryOptions(const std::string& failureId) {
    return {}; // Stub
}

RecoveryAction RecoveryManager::SelectBestRecovery(const std::vector<RecoveryAction>& options) {
    if (!options.empty()) {
        return options[0];
    }
    return {};
}

bool RecoveryManager::AttemptRecovery(const std::string& failureId, const RecoveryAction& action) {
    auto start = std::chrono::steady_clock::now();
    
    bool success = action.execute ? action.execute() : false;
    
    auto end = std::chrono::steady_clock::now();
    double durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    pImpl_->totalRecoveryTimeMs += durationMs;
    
    auto it = pImpl_->failures.find(failureId);
    if (it != pImpl_->failures.end()) {
        it->second.recoveryAttempts.push_back(action.description);
        if (success) {
            it->second.isRecovered = true;
            it->second.recoveryMethod = action.description;
            pImpl_->recoveredFailures++;
        }
    }
    
    return success;
}

void RecoveryManager::EnableAutomaticRecovery(bool enable) {
    pImpl_->automaticRecovery = enable;
}

bool RecoveryManager::IsAutomaticRecoveryEnabled() const {
    return pImpl_->automaticRecovery;
}

void RecoveryManager::SetMaxRetries(int maxRetries) {
    pImpl_->maxRetries = maxRetries;
}

void RecoveryManager::SetRetryBackoffMs(int initialBackoffMs) {
    pImpl_->retryBackoffMs = initialBackoffMs;
}

std::vector<std::string> RecoveryManager::IdentifyRecurringFailures() { return {}; }
std::vector<std::string> RecoveryManager::IdentifySystemicIssues() { return {}; }
std::string RecoveryManager::RootCauseAnalysis(const std::string& failureId) { return ""; }
std::vector<std::string> RecoveryManager::PredictPotentialFailures() { return {}; }
void RecoveryManager::RegisterPreventionMeasure(const std::string& failurePattern, const std::string& preventionAction) {}

RecoveryManager::Stats RecoveryManager::GetStats() const {
    Stats s;
    s.totalFailures = pImpl_->totalFailures;
    s.recoveredFailures = pImpl_->recoveredFailures;
    s.unrecoveredFailures = pImpl_->totalFailures - pImpl_->recoveredFailures;
    s.automaticRecoveries = pImpl_->automaticRecoveries;
    s.recoverySuccessRate = pImpl_->totalFailures > 0 ?
        static_cast<float>(pImpl_->recoveredFailures) / pImpl_->totalFailures : 0.0f;
    s.averageRecoveryTimeMs = pImpl_->recoveredFailures > 0 ?
        pImpl_->totalRecoveryTimeMs / pImpl_->recoveredFailures : 0.0;
    return s;
}

} // namespace Executive
} // namespace RawrXD
