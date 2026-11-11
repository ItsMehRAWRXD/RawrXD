/**
 * SovereignState.cpp
 *
 * Phase D.1 Batch 2/5: State Consistency Layer
 */

#include "SovereignState.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Core {

// ============================================================================
// ExecutionMode Utilities
// ============================================================================

std::string ExecutionModeToString(ExecutionMode mode) {
    switch (mode) {
        case ExecutionMode::IDLE: return "IDLE";
        case ExecutionMode::MANUAL: return "MANUAL";
        case ExecutionMode::ASSISTED: return "ASSISTED";
        case ExecutionMode::AUTONOMOUS: return "AUTONOMOUS";
        case ExecutionMode::SELF_OPTIMIZING: return "SELF_OPTIMIZING";
        default: return "UNKNOWN";
    }
}

ExecutionMode StringToExecutionMode(const std::string& str) {
    if (str == "IDLE") return ExecutionMode::IDLE;
    if (str == "MANUAL") return ExecutionMode::MANUAL;
    if (str == "ASSISTED") return ExecutionMode::ASSISTED;
    if (str == "AUTONOMOUS") return ExecutionMode::AUTONOMOUS;
    if (str == "SELF_OPTIMIZING") return ExecutionMode::SELF_OPTIMIZING;
    return ExecutionMode::IDLE;
}

// ============================================================================
// RuntimeState Implementation
// ============================================================================

std::string RuntimeState::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"isRunning\":" << (isRunning ? "true" : "false") << ",";
    json << "\"isPaused\":" << (isPaused ? "true" : "false") << ",";
    json << "\"cycleCount\":" << cycleCount << ",";
    json << "\"uptimeMs\":" << uptimeMs << ",";
    json << "\"cpuUtilization\":" << cpuUtilization << ",";
    json << "\"memoryUsageMB\":" << memoryUsageMB << ",";
    json << "\"activeThreads\":" << activeThreads << ",";
    json << "\"lastCheckpointMs\":" << lastCheckpointMs;
    json << "}";
    return json.str();
}

// ============================================================================
// SEGState Implementation
// ============================================================================

std::string SEGState::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"nodeCount\":" << nodeCount << ",";
    json << "\"edgeCount\":" << edgeCount << ",";
    json << "\"activeExecutions\":" << activeExecutions << ",";
    json << "\"pendingExecutions\":" << pendingExecutions << ",";
    json << "\"averageExecutionTimeMs\":" << averageExecutionTimeMs << ",";
    json << "\"completedExecutions\":" << completedExecutions << ",";
    json << "\"failedExecutions\":" << failedExecutions;
    json << "}";
    return json.str();
}

// ============================================================================
// EngineState Implementation
// ============================================================================

std::string EngineState::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"isInitialized\":" << (isInitialized ? "true" : "false") << ",";
    json << "\"activeCycles\":" << activeCycles << ",";
    json << "\"tokensPerSecond\":" << tokensPerSecond << ",";
    json << "\"averageLatencyMs\":" << averageLatencyMs << ",";
    json << "\"totalTokensGenerated\":" << totalTokensGenerated << ",";
    json << "\"failedCycles\":" << failedCycles;
    json << "}";
    return json.str();
}

// ============================================================================
// SwarmState Implementation
// ============================================================================

std::string SwarmState::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"totalWorkers\":" << totalWorkers << ",";
    json << "\"activeWorkers\":" << activeWorkers << ",";
    json << "\"idleWorkers\":" << idleWorkers << ",";
    json << "\"failedWorkers\":" << failedWorkers << ",";
    json << "\"tasksCompleted\":" << tasksCompleted << ",";
    json << "\"tasksFailed\":" << tasksFailed << ",";
    json << "\"averageTaskTimeMs\":" << averageTaskTimeMs;
    json << "}";
    return json.str();
}

// ============================================================================
// EmergentState Implementation
// ============================================================================

std::string EmergentState::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"patternsDetected\":" << patternsDetected << ",";
    json << "\"rolesAssigned\":" << rolesAssigned << ",";
    json << "\"intentsActive\":" << intentsActive << ",";
    json << "\"correctionsApplied\":" << correctionsApplied << ",";
    json << "\"systemStability\":" << systemStability << ",";
    json << "\"convergenceScore\":" << convergenceScore;
    json << "}";
    return json.str();
}

// ============================================================================
// AutonomyState Implementation
// ============================================================================

std::string AutonomyState::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"mode\":\"" << ExecutionModeToString(mode) << "\",";
    json << "\"decisionsPending\":" << decisionsPending << ",";
    json << "\"decisionsExecuted\":" << decisionsExecuted << ",";
    json << "\"decisionsFailed\":" << decisionsFailed << ",";
    json << "\"averageDecisionConfidence\":" << averageDecisionConfidence << ",";
    json << "\"emergencyStopped\":" << (emergencyStopped ? "true" : "false");
    json << "}";
    return json.str();
}

// ============================================================================
// SovereignState Implementation
// ============================================================================

std::string SovereignState::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"phase\":\"" << phase << "\",";
    json << "\"timestampMs\":" << timestampMs << ",";
    json << "\"version\":\"" << version << "\",";
    json << "\"stability\":" << stability << ",";
    json << "\"convergence\":" << convergence << ",";
    json << "\"performance\":" << performance << ",";
    json << "\"activeNodes\":" << activeNodes << ",";
    json << "\"activeWorkers\":" << activeWorkers << ",";
    json << "\"mode\":\"" << ExecutionModeToString(mode) << "\",";
    json << "\"activeSubsystems\":" << activeSubsystems << ",";
    json << "\"healthySubsystems\":" << healthySubsystems << ",";
    json << "\"runtime\":" << runtime.ToJson() << ",";
    json << "\"seg\":" << seg.ToJson() << ",";
    json << "\"engine\":" << engine.ToJson() << ",";
    json << "\"swarm\":" << swarm.ToJson() << ",";
    json << "\"emergent\":" << emergent.ToJson() << ",";
    json << "\"autonomy\":" << autonomy.ToJson();
    
    if (!errors.empty()) {
        json << ",\"errors\":[";
        for (size_t i = 0; i < errors.size(); ++i) {
            if (i > 0) json << ",";
            json << "\"" << errors[i] << "\"";
        }
        json << "]";
    }
    
    json << "}";
    return json.str();
}

void SovereignState::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           SOVEREIGN STATE                                          ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Phase:        " << std::left << std::setw(48) << phase << " ║\n";
    std::cout << "║  Mode:          " << std::setw(48) << ExecutionModeToString(mode) << " ║\n";
    std::cout << "║  Timestamp:     " << std::setw(48) << std::to_string(timestampMs) << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Aggregated Metrics:                                               ║\n";
    std::cout << "║    Stability:   " << std::setw(9) << std::fixed << std::setprecision(1) << (stability * 100) << "%"
              << std::string(36, ' ') << "║\n";
    std::cout << "║    Convergence: " << std::setw(9) << std::setprecision(1) << (convergence * 100) << "%"
              << std::string(36, ' ') << "║\n";
    std::cout << "║    Performance: " << std::setw(9) << std::setprecision(1) << (performance * 100) << "%"
              << std::string(36, ' ') << "║\n";
    std::cout << "║    Active Nodes:   " << std::setw(10) << activeNodes
              << std::string(33, ' ') << "║\n";
    std::cout << "║    Active Workers: " << std::setw(10) << activeWorkers
              << std::string(33, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Subsystem Health: " << std::setw(10) << healthySubsystems << "/" << activeSubsystems
              << std::string(26, ' ') << "║\n";
    
    if (!errors.empty()) {
        std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Errors:                                                           ║\n";
        for (const auto& error : errors) {
            std::string truncated = error.length() > 58 ? error.substr(0, 55) + "..." : error;
            std::cout << "║    " << std::setw(58) << truncated << " ║\n";
        }
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

bool SovereignState::IsHealthy() const {
    return healthySubsystems == activeSubsystems && errors.empty();
}

double SovereignState::CalculateOverallHealth() const {
    if (activeSubsystems == 0) return 0.0;
    
    double health = static_cast<double>(healthySubsystems) / activeSubsystems;
    health *= stability;
    health *= convergence;
    
    // Penalize errors
    health *= std::max(0.0, 1.0 - (errors.size() * 0.1));
    
    return health;
}

void SovereignState::UpdateFromRuntime(const RuntimeState& state) {
    runtime = state;
    activeNodes = state.activeThreads;
}

void SovereignState::UpdateFromSEG(const SEGState& state) {
    seg = state;
    activeNodes = state.nodeCount;
}

void SovereignState::UpdateFromEngine(const EngineState& state) {
    engine = state;
    performance = state.tokensPerSecond / 100.0; // Normalize
}

void SovereignState::UpdateFromSwarm(const SwarmState& state) {
    swarm = state;
    activeWorkers = state.activeWorkers;
}

void SovereignState::UpdateFromEmergent(const EmergentState& state) {
    emergent = state;
    stability = state.systemStability;
    convergence = state.convergenceScore;
}

void SovereignState::UpdateFromAutonomy(const AutonomyState& state) {
    autonomy = state;
    mode = state.mode;
}

// ============================================================================
// SovereignStateManager Implementation
// ============================================================================

SovereignState SovereignStateManager::GetCurrentState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return currentState_;
}

void SovereignStateManager::UpdateRuntime(const RuntimeState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.UpdateFromRuntime(state);
    currentState_.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void SovereignStateManager::UpdateSEG(const SEGState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.UpdateFromSEG(state);
    currentState_.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void SovereignStateManager::UpdateEngine(const EngineState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.UpdateFromEngine(state);
    currentState_.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void SovereignStateManager::UpdateSwarm(const SwarmState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.UpdateFromSwarm(state);
    currentState_.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void SovereignStateManager::UpdateEmergent(const EmergentState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.UpdateFromEmergent(state);
    currentState_.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void SovereignStateManager::UpdateAutonomy(const AutonomyState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.UpdateFromAutonomy(state);
    currentState_.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void SovereignStateManager::SetPhase(const std::string& phase) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.phase = phase;
    
    // Archive current state
    history_.push_back(currentState_);
    if (history_.size() > MAX_HISTORY) {
        history_.erase(history_.begin());
    }
}

void SovereignStateManager::AddError(const std::string& subsystem, const std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.errors.push_back(subsystem + ": " + error);
}

void SovereignStateManager::ClearErrors() {
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.errors.clear();
}

std::vector<SovereignState> SovereignStateManager::GetHistory(int count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<SovereignState> result;
    int start = std::max(0, static_cast<int>(history_.size()) - count);
    for (int i = start; i < static_cast<int>(history_.size()); ++i) {
        result.push_back(history_[i]);
    }
    return result;
}

bool SovereignStateManager::DetectStateDrift(const SovereignState& previous, 
                                            const SovereignState& current) const {
    // Detect significant changes
    double stabilityDelta = std::abs(current.stability - previous.stability);
    double convergenceDelta = std::abs(current.convergence - previous.convergence);
    
    // Drift if stability drops significantly
    if (stabilityDelta > 0.2 && current.stability < previous.stability) {
        return true;
    }
    
    // Drift if convergence drops significantly
    if (convergenceDelta > 0.2 && current.convergence < previous.convergence) {
        return true;
    }
    
    // Drift if mode changed unexpectedly
    if (previous.mode != ExecutionMode::IDLE && 
        current.mode == ExecutionMode::IDLE) {
        return true;
    }
    
    return false;
}

} // namespace Core
