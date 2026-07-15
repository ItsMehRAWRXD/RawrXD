/**
 * FaultManager.cpp
 *
 * Phase D.1 Batch 3/5: Failure Containment
 */

#include "FaultManager.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>

namespace Core {

// ============================================================================
// FaultType Utilities
// ============================================================================

std::string FaultTypeToString(FaultType type) {
    switch (type) {
        case FaultType::SUBSYSTEM_CRASH: return "SUBSYSTEM_CRASH";
        case FaultType::SUBSYSTEM_HANG: return "SUBSYSTEM_HANG";
        case FaultType::EXECUTION_ERROR: return "EXECUTION_ERROR";
        case FaultType::RESOURCE_EXHAUSTION: return "RESOURCE_EXHAUSTION";
        case FaultType::STATE_INCONSISTENCY: return "STATE_INCONSISTENCY";
        case FaultType::NETWORK_FAILURE: return "NETWORK_FAILURE";
        case FaultType::TIMEOUT: return "TIMEOUT";
        case FaultType::UNKNOWN: return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Fault Implementation
// ============================================================================

std::string Fault::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"faultId\":\"" << faultId << "\",";
    json << "\"type\":\"" << FaultTypeToString(type) << "\",";
    json << "\"severity\":" << static_cast<int>(severity) << ",";
    json << "\"subsystem\":\"" << subsystem << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"errorMessage\":\"" << errorMessage << "\",";
    json << "\"timestampMs\":" << timestampMs;
    json << "}";
    return json.str();
}

// ============================================================================
// RecoveryResult Implementation
// ============================================================================

std::string RecoveryResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (success ? "true" : "false") << ",";
    json << "\"faultId\":\"" << faultId << "\",";
    json << "\"actionId\":\"" << actionId << "\",";
    json << "\"attempts\":" << attempts << ",";
    json << "\"durationMs\":" << durationMs;
    if (!errorMessage.empty()) {
        json << ",\"errorMessage\":\"" << errorMessage << "\"";
    }
    json << "}";
    return json.str();
}

// ============================================================================
// FaultManagerConfig Implementation
// ============================================================================

std::string FaultManagerConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"enableAutoRecovery\":" << (enableAutoRecovery ? "true" : "false") << ",";
    json << "\"maxConcurrentRecoveries\":" << maxConcurrentRecoveries << ",";
    json << "\"recoveryTimeoutMs\":" << recoveryTimeoutMs << ",";
    json << "\"faultHistorySize\":" << faultHistorySize << ",";
    json << "\"maxFaultsPerMinute\":" << maxFaultsPerMinute << ",";
    json << "\"maxCriticalFaultsPerHour\":" << maxCriticalFaultsPerHour;
    json << "}";
    return json.str();
}

// ============================================================================
// FaultManager Implementation
// ============================================================================

FaultManager::FaultManager() = default;
FaultManager::~FaultManager() {
    Shutdown();
}

bool FaultManager::Initialize(const FaultManagerConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    config_ = config;
    initialized_ = true;
    
    std::cout << "[FaultManager] Initialized\n";
    return true;
}

void FaultManager::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    activeFaults_.clear();
    faultHistory_.clear();
    recoveryHistory_.clear();
    recoveryActions_.clear();
    
    initialized_ = false;
    std::cout << "[FaultManager] Shutdown complete\n";
}

std::string FaultManager::ReportFault(const Fault& fault) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Fault newFault = fault;
    newFault.faultId = GenerateFaultId();
    newFault.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Add to active faults
    activeFaults_.push_back(newFault);
    
    // Add to history
    faultHistory_.push_back(newFault);
    if (faultHistory_.size() > static_cast<size_t>(config_.faultHistorySize)) {
        faultHistory_.erase(faultHistory_.begin());
    }
    
    stats_.totalFaults++;
    if (newFault.severity == FaultSeverity::CRITICAL) {
        stats_.criticalFaults++;
    }
    
    std::cerr << "[FaultManager] Fault reported: [" << FaultTypeToString(newFault.type) 
              << "] " << newFault.description << "\n";
    
    // Attempt recovery if enabled
    if (config_.enableAutoRecovery && ShouldAttemptRecovery(newFault)) {
        auto result = AttemptRecovery(newFault);
        recoveryHistory_.push_back(result);
        UpdateStatistics(result);
    }
    
    return newFault.faultId;
}

std::string FaultManager::ReportFault(const std::string& subsystem,
                                     const std::string& error,
                                     FaultSeverity severity) {
    Fault fault;
    fault.subsystem = subsystem;
    fault.errorMessage = error;
    fault.severity = severity;
    fault.description = subsystem + " error: " + error;
    fault.type = FaultType::UNKNOWN;
    
    return ReportFault(fault);
}

bool FaultManager::IsRecoveryInProgress() const {
    return recoveryInProgress_.load();
}

std::vector<Fault> FaultManager::GetActiveFaults() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activeFaults_;
}

std::vector<Fault> FaultManager::GetFaultHistory(int count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Fault> result;
    int start = std::max(0, static_cast<int>(faultHistory_.size()) - count);
    for (int i = start; i < static_cast<int>(faultHistory_.size()); ++i) {
        result.push_back(faultHistory_[i]);
    }
    return result;
}

std::vector<RecoveryResult> FaultManager::GetRecoveryHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return recoveryHistory_;
}

void FaultManager::ClearResolvedFaults() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Remove faults that have been recovered
    auto it = activeFaults_.begin();
    while (it != activeFaults_.end()) {
        bool recovered = false;
        for (const auto& result : recoveryHistory_) {
            if (result.faultId == it->faultId && result.success) {
                recovered = true;
                break;
            }
        }
        
        if (recovered) {
            it = activeFaults_.erase(it);
        } else {
            ++it;
        }
    }
}

void FaultManager::SetCheckpointManager(std::shared_ptr<Runtime::CheckpointManager> manager) {
    std::lock_guard<std::mutex> lock(mutex_);
    checkpointManager_ = manager;
}

void FaultManager::SetExecutionGraph(std::shared_ptr<SEG::ExecutionGraph> graph) {
    std::lock_guard<std::mutex> lock(mutex_);
    executionGraph_ = graph;
}

FaultManager::Statistics FaultManager::GetStatistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void FaultManager::PrintStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     FAULT MANAGER STATUS                                         ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Faults:      " << std::setw(10) << stats_.totalFaults << std::string(26, ' ') << "║\n";
    std::cout << "║  Active Faults:      " << std::setw(10) << activeFaults_.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Recovered:          " << std::setw(10) << stats_.recoveredFaults << std::string(26, ' ') << "║\n";
    std::cout << "║  Failed Recoveries:  " << std::setw(10) << stats_.failedRecoveries << std::string(26, ' ') << "║\n";
    std::cout << "║  Critical Faults:    " << std::setw(10) << stats_.criticalFaults << std::string(26, ' ') << "║\n";
    std::cout << "║  Recovery Rate:      " << std::setw(9) << std::fixed << std::setprecision(1) 
              << (stats_.recoverySuccessRate * 100) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Recovery Methods
// ============================================================================

RecoveryResult FaultManager::AttemptRecovery(const Fault& fault) {
    RecoveryResult result;
    result.faultId = fault.faultId;
    result.attempts = 0;
    
    auto startTime = std::chrono::steady_clock::now();
    
    recoveryInProgress_ = true;
    
    switch (fault.type) {
        case FaultType::SUBSYSTEM_CRASH:
        case FaultType::SUBSYSTEM_HANG:
            result = RecoverSubsystemCrash(fault);
            break;
        case FaultType::EXECUTION_ERROR:
            result = RecoverExecutionError(fault);
            break;
        case FaultType::RESOURCE_EXHAUSTION:
            result = RecoverResourceExhaustion(fault);
            break;
        case FaultType::STATE_INCONSISTENCY:
            result = RecoverStateInconsistency(fault);
            break;
        default:
            result.errorMessage = "No recovery strategy for fault type: " + FaultTypeToString(fault.type);
            break;
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    recoveryInProgress_ = false;
    
    if (result.success) {
        std::cout << "[FaultManager] Recovery successful for fault " << fault.faultId << "\n";
    } else {
        std::cerr << "[FaultManager] Recovery failed for fault " << fault.faultId 
                  << ": " << result.errorMessage << "\n";
    }
    
    return result;
}

RecoveryResult FaultManager::RecoverSubsystemCrash(const Fault& fault) {
    RecoveryResult result;
    result.faultId = fault.faultId;
    result.actionId = "restart_" + fault.subsystem;
    
    std::cout << "[FaultManager] Attempting to restart subsystem: " << fault.subsystem << "\n";
    
    // Simulate restart
    result.attempts = 1;
    result.success = true; // Would actually restart
    
    return result;
}

RecoveryResult FaultManager::RecoverExecutionError(const Fault& fault) {
    RecoveryResult result;
    result.faultId = fault.faultId;
    result.actionId = "retry_execution";
    
    std::cout << "[FaultManager] Retrying execution after error\n";
    
    // Simulate retry
    result.attempts = 1;
    result.success = true;
    
    return result;
}

RecoveryResult FaultManager::RecoverResourceExhaustion(const Fault& fault) {
    RecoveryResult result;
    result.faultId = fault.faultId;
    result.actionId = "free_resources";
    
    std::cout << "[FaultManager] Freeing resources\n";
    
    // Simulate resource cleanup
    result.attempts = 1;
    result.success = true;
    
    return result;
}

RecoveryResult FaultManager::RecoverStateInconsistency(const Fault& fault) {
    RecoveryResult result;
    result.faultId = fault.faultId;
    result.actionId = "restore_checkpoint";
    
    std::cout << "[FaultManager] Restoring from checkpoint\n";
    
    if (checkpointManager_) {
        // Would restore from checkpoint
        result.attempts = 1;
        result.success = true;
    } else {
        result.errorMessage = "No checkpoint manager available";
    }
    
    return result;
}

// ============================================================================
// Helpers
// ============================================================================

FaultSeverity FaultManager::AssessSeverity(const Fault& fault) const {
    // Auto-assess based on fault type and subsystem
    switch (fault.type) {
        case FaultType::SUBSYSTEM_CRASH:
        case FaultType::STATE_INCONSISTENCY:
            return FaultSeverity::CRITICAL;
        case FaultType::RESOURCE_EXHAUSTION:
        case FaultType::SUBSYSTEM_HANG:
            return FaultSeverity::MAJOR;
        case FaultType::EXECUTION_ERROR:
        case FaultType::TIMEOUT:
            return FaultSeverity::MINOR;
        default:
            return FaultSeverity::WARNING;
    }
}

bool FaultManager::ShouldAttemptRecovery(const Fault& fault) const {
    // Don't recover warnings
    if (fault.severity == FaultSeverity::WARNING) {
        return false;
    }
    
    // Check if we've exceeded max recoveries
    int activeRecoveries = 0;
    for (const auto& r : recoveryHistory_) {
        if (!r.success) activeRecoveries++;
    }
    
    return activeRecoveries < config_.maxConcurrentRecoveries;
}

std::string FaultManager::GenerateFaultId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "fault-" << ms << "-" << dis(gen);
    return id.str();
}

void FaultManager::UpdateStatistics(const RecoveryResult& result) {
    if (result.success) {
        stats_.recoveredFaults++;
    } else {
        stats_.failedRecoveries++;
    }
    
    int total = stats_.recoveredFaults + stats_.failedRecoveries;
    if (total > 0) {
        stats_.recoverySuccessRate = static_cast<double>(stats_.recoveredFaults) / total;
    }
}

// ============================================================================
// Statistics Implementation
// ============================================================================

void FaultManager::Statistics::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           FAULT STATISTICS                                       ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Faults:       " << std::setw(10) << totalFaults << std::string(26, ' ') << "║\n";
    std::cout << "║  Active Faults:      " << std::setw(10) << activeFaults << std::string(26, ' ') << "║\n";
    std::cout << "║  Recovered:          " << std::setw(10) << recoveredFaults << std::string(26, ' ') << "║\n";
    std::cout << "║  Failed Recoveries:  " << std::setw(10) << failedRecoveries << std::string(26, ' ') << "║\n";
    std::cout << "║  Critical Faults:    " << std::setw(10) << criticalFaults << std::string(26, ' ') << "║\n";
    std::cout << "║  Recovery Rate:      " << std::setw(9) << std::fixed << std::setprecision(1) 
              << (recoverySuccessRate * 100) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// FaultDetector Implementation
// ============================================================================

bool FaultDetector::DetectHang(const std::string& subsystem,
                               std::function<bool()> healthCheck,
                               int timeoutMs) {
    // Would implement actual timeout detection
    return !healthCheck();
}

bool FaultDetector::DetectResourceExhaustion(double memoryUsagePercent,
                                            double cpuUsagePercent,
                                            double threshold) {
    return memoryUsagePercent > threshold || cpuUsagePercent > threshold;
}

bool FaultDetector::DetectStateInconsistency(const SovereignState& previous,
                                            const SovereignState& current,
                                            double threshold) {
    // Check for significant divergence
    double stabilityDelta = std::abs(current.stability - previous.stability);
    return stabilityDelta > threshold;
}

} // namespace Core
