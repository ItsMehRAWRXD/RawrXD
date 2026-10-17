// AgenticLoopState Implementation
#include "agentic_loop_state.h"
#include <iostream>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace {

std::string nowIsoString() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string phaseToString(AgenticLoopState::ReasoningPhase phase) {
    switch (phase) {
        case AgenticLoopState::ReasoningPhase::Analysis: return "Analysis";
        case AgenticLoopState::ReasoningPhase::Planning: return "Planning";
        case AgenticLoopState::ReasoningPhase::Execution: return "Execution";
        case AgenticLoopState::ReasoningPhase::Verification: return "Verification";
        case AgenticLoopState::ReasoningPhase::Reflection: return "Reflection";
        case AgenticLoopState::ReasoningPhase::Adjustment: return "Adjustment";
    }
    return "Unknown";
}

std::string statusToString(AgenticLoopState::IterationStatus status) {
    switch (status) {
        case AgenticLoopState::IterationStatus::NotStarted: return "NotStarted";
        case AgenticLoopState::IterationStatus::InProgress: return "InProgress";
        case AgenticLoopState::IterationStatus::Completed: return "Completed";
        case AgenticLoopState::IterationStatus::Failed: return "Failed";
        case AgenticLoopState::IterationStatus::Recovering: return "Recovering";
        case AgenticLoopState::IterationStatus::MaxAttemptsReached: return "MaxAttemptsReached";
    }
    return "Unknown";
}

} // namespace

AgenticLoopState::AgenticLoopState()
    : m_currentPhase(ReasoningPhase::Analysis)
    , m_currentStatus(IterationStatus::NotStarted)
    , m_stateStartTime(std::chrono::system_clock::now())
    , m_lastUpdateTime(std::chrono::system_clock::now())
{
}

AgenticLoopState::~AgenticLoopState() {
}

// ===== ITERATION MANAGEMENT =====

void AgenticLoopState::startIteration(const std::string& goal) {
    Iteration iter;
    iter.iterationNumber = (int)m_iterations.size() + 1;
    iter.startTime = std::chrono::system_clock::now();
    iter.currentPhase = m_currentPhase;
    iter.status = IterationStatus::InProgress;
    iter.goalStatement = goal;
    iter.successScore = 0.0f;
    iter.errorCount = 0;

    m_iterations.push_back(iter);
    m_currentStatus = IterationStatus::InProgress;
    m_lastUpdateTime = std::chrono::system_clock::now();

    // Add to context window
    m_contextWindow.push_back(iter);
    if ((int)m_contextWindow.size() > m_contextWindowSize) {
        m_contextWindow.pop_front();
    }
}

void AgenticLoopState::endIteration(IterationStatus status, const std::string& result) {
    if (m_iterations.empty()) return;

    auto& iter = m_iterations.back();
    iter.endTime = std::chrono::system_clock::now();
    iter.status = status;
    iter.resultSummary = result;
    iter.successScore = (status == IterationStatus::Completed) ? 1.0f : 0.0f;

    m_currentStatus = status;
    m_lastUpdateTime = std::chrono::system_clock::now();
}

AgenticLoopState::Iteration* AgenticLoopState::getCurrentIteration() {
    if (m_iterations.empty()) return nullptr;
    return &m_iterations.back();
}

// ===== PHASE MANAGEMENT =====

void AgenticLoopState::setCurrentPhase(ReasoningPhase phase) {
    m_currentPhase = phase;
    m_lastUpdateTime = std::chrono::system_clock::now();
}

float AgenticLoopState::getPhaseProgress() const {
    return 1.0f; // Simplified
}

std::vector<std::string> AgenticLoopState::getAllPhaseTransitions() const {
    std::vector<std::string> transitions;
    for (const auto& iter : m_iterations) {
        transitions.push_back(phaseToString(iter.currentPhase));
    }
    return transitions;
}

// ===== DECISION TRACKING =====

void AgenticLoopState::recordDecision(
    const std::string& description,
    const json& reasoning,
    float confidence)
{
    Decision decision;
    decision.timestamp = std::chrono::system_clock::now();
    decision.phase = m_currentPhase;
    decision.description = description;
    decision.reasoning = reasoning;
    decision.confidence = confidence;
    decision.success = false;
    decision.retryCount = 0;

    if (!m_iterations.empty()) {
        m_iterations.back().decisions.push_back(decision);
    }
}

void AgenticLoopState::recordDecisionOutcome(
    int decisionIndex,
    const json& outcome,
    bool success)
{
    if (m_iterations.empty()) return;

    auto& decisions = m_iterations.back().decisions;
    if (decisionIndex >= 0 && decisionIndex < (int)decisions.size()) {
        decisions[decisionIndex].outcome = outcome;
        decisions[decisionIndex].success = success;
    }
}

std::vector<AgenticLoopState::Decision> AgenticLoopState::getDecisionHistory(int limit) const {
    std::vector<Decision> all;
    for (const auto& iter : m_iterations) {
        for (const auto& d : iter.decisions) {
            all.push_back(d);
        }
    }

    if (limit > 0 && (int)all.size() > limit) {
        all.resize(limit);
    }

    return all;
}

AgenticLoopState::Decision* AgenticLoopState::getCurrentDecision() {
    if (m_iterations.empty()) return nullptr;
    auto& decisions = m_iterations.back().decisions;
    if (decisions.empty()) return nullptr;
    return &decisions.back();
}

float AgenticLoopState::getAverageDecisionConfidence() const {
    float total = 0.0f;
    int count = 0;
    for (const auto& iter : m_iterations) {
        for (const auto& d : iter.decisions) {
            total += d.confidence;
            count++;
        }
    }
    return count > 0 ? total / count : 0.0f;
}

float AgenticLoopState::getDecisionSuccessRate() const {
    int total = 0;
    int successful = 0;
    for (const auto& iter : m_iterations) {
        for (const auto& d : iter.decisions) {
            total++;
            if (d.success) successful++;
        }
    }
    return total > 0 ? (float)successful / total : 0.0f;
}

// ===== ERROR TRACKING AND RECOVERY =====

void AgenticLoopState::recordError(
    const std::string& errorType,
    const std::string& message,
    const std::string& stackTrace)
{
    ErrorRecord record;
    record.timestamp = std::chrono::system_clock::now();
    record.errorType = errorType;
    record.errorMessage = message;
    record.stackTrace = stackTrace;
    record.phase = m_currentPhase;
    record.recoverySucceeded = false;
    record.recoveryAttempt = 0;

    m_errorHistory.push_back(record);

    if (!m_iterations.empty()) {
        m_iterations.back().errorCount++;
    }
}

void AgenticLoopState::recordErrorRecovery(
    int errorIndex,
    const std::string& strategy,
    bool succeeded)
{
    if (errorIndex < 0 || errorIndex >= (int)m_errorHistory.size()) return;

    m_errorHistory[errorIndex].recoveryStrategy = strategy;
    m_errorHistory[errorIndex].recoverySucceeded = succeeded;
}

const std::deque<AgenticLoopState::ErrorRecord>& AgenticLoopState::getErrorHistory(size_t limit) const {
    return m_errorHistory;
}

float AgenticLoopState::getErrorRate() const {
    if (m_iterations.empty()) return 0.0f;
    int totalErrors = 0;
    for (const auto& iter : m_iterations) {
        totalErrors += iter.errorCount;
    }
    return (float)totalErrors / (float)m_iterations.size();
}

std::string AgenticLoopState::generateErrorAnalysis() const {
    std::string analysis = "Error Analysis:\n";
    analysis += "Total errors: " + std::to_string(m_errorHistory.size()) + "\n";
    analysis += "Error rate: " + std::to_string(getErrorRate()) + "\n";
    return analysis;
}

// ===== STATE SNAPSHOTS (CHECKPOINTING) =====

json AgenticLoopState::takeSnapshot() {
    json snapshot;
    snapshot["current_phase"] = static_cast<int>(m_currentPhase);
    snapshot["current_status"] = static_cast<int>(m_currentStatus);
    snapshot["current_goal"] = m_currentGoal;
    snapshot["progress_current"] = m_progressCurrent;
    snapshot["progress_total"] = m_progressTotal;
    snapshot["timestamp"] = nowIsoString();

    m_lastSnapshot = snapshot;
    m_snapshotHistory.push_back(snapshot);

    return snapshot;
}

bool AgenticLoopState::restoreFromSnapshot(const json& snapshot) {
    m_lastSnapshot = snapshot;
    
    if (snapshot.contains("current_phase")) {
        m_currentPhase = static_cast<ReasoningPhase>(snapshot["current_phase"].get<int>());
    }
    if (snapshot.contains("current_goal")) {
        m_currentGoal = snapshot["current_goal"].get<std::string>();
    }
    if (snapshot.contains("progress_current")) {
        m_progressCurrent = snapshot["progress_current"].get<int>();
    }
    if (snapshot.contains("progress_total")) {
        m_progressTotal = snapshot["progress_total"].get<int>();
    }

    m_lastUpdateTime = std::chrono::system_clock::now();
    return true;
}

// ===== MEMORY AND CONTEXT WINDOW =====

void AgenticLoopState::addToMemory(const std::string& key, const json& value) {
    m_memory[key] = value;
}

json AgenticLoopState::getFromMemory(const std::string& key) {
    auto it = m_memory.find(key);
    if (it != m_memory.end()) {
        return it->second;
    }
    return json();
}

void AgenticLoopState::removeFromMemory(const std::string& key) {
    m_memory.erase(key);
}

json AgenticLoopState::getAllMemory() const {
    return m_memory;
}

void AgenticLoopState::clearMemoryExcept(const std::vector<std::string>& keysToKeep) {
    auto it = m_memory.begin();
    while (it != m_memory.end()) {
        bool keep = false;
        for (const auto& k : keysToKeep) {
            if (it->first == k) { keep = true; break; }
        }
        if (!keep) {
            it = m_memory.erase(it);
        } else {
            ++it;
        }
    }
}

void AgenticLoopState::setContextWindowSize(int size) {
    m_contextWindowSize = size;
}

json AgenticLoopState::getContextWindow() const {
    json window = json::array();
    for (const auto& iter : m_contextWindow) {
        json entry;
        entry["iteration"] = iter.iterationNumber;
        entry["goal"] = iter.goalStatement;
        entry["status"] = static_cast<int>(iter.status);
        entry["phase"] = static_cast<int>(iter.currentPhase);
        window.push_back(entry);
    }
    return window;
}

std::string AgenticLoopState::formatContextForModel() const {
    std::string context = "Context Window:\n";
    for (const auto& iter : m_contextWindow) {
        context += "- Iteration " + std::to_string(iter.iterationNumber) + ": " + iter.goalStatement + "\n";
    }
    return context;
}

// ===== GOAL AND PROGRESS TRACKING =====

void AgenticLoopState::updateProgress(int current, int total) {
    m_progressCurrent = current;
    m_progressTotal = total;
    m_lastUpdateTime = std::chrono::system_clock::now();
}

float AgenticLoopState::getProgressPercentage() const {
    if (m_progressTotal == 0) return 0.0f;
    return (float)m_progressCurrent / (float)m_progressTotal * 100.0f;
}

json AgenticLoopState::getProgressInfo() const {
    json info;
    info["current"] = m_progressCurrent;
    info["total"] = m_progressTotal;
    info["percentage"] = getProgressPercentage();
    return info;
}

// ===== CONSTRAINT MANAGEMENT =====

void AgenticLoopState::addConstraint(const std::string& key, const std::string& constraint) {
    m_constraints[key] = constraint;
}

void AgenticLoopState::removeConstraint(const std::string& key) {
    m_constraints.erase(key);
}

bool AgenticLoopState::validateAgainstConstraints(const json& action) const {
    // Simple validation - always pass for now
    return true;
}

// ===== STRATEGY TRACKING =====

void AgenticLoopState::recordAppliedStrategy(const std::string& strategy) {
    m_appliedStrategies.push_back(strategy);
    if (!m_iterations.empty()) {
        m_iterations.back().appliedStrategies.push_back(strategy);
    }
}

void AgenticLoopState::setSuggestedStrategies(const std::vector<std::string>& strategies) {
    m_suggestedStrategies = strategies;
}

// ===== OVERALL STATE METRICS =====

json AgenticLoopState::getMetrics() const {
    json metrics;
    metrics["total_iterations"] = (int)m_iterations.size();
    metrics["completed_iterations"] = getCompletedIterations();
    metrics["failed_iterations"] = getFailedIterations();
    metrics["overall_success_rate"] = getOverallSuccessRate();
    metrics["error_rate"] = getErrorRate();
    metrics["avg_decision_confidence"] = getAverageDecisionConfidence();
    metrics["decision_success_rate"] = getDecisionSuccessRate();
    return metrics;
}

int AgenticLoopState::getCompletedIterations() const {
    int count = 0;
    for (const auto& iter : m_iterations) {
        if (iter.status == IterationStatus::Completed) count++;
    }
    return count;
}

int AgenticLoopState::getFailedIterations() const {
    int count = 0;
    for (const auto& iter : m_iterations) {
        if (iter.status == IterationStatus::Failed) count++;
    }
    return count;
}

float AgenticLoopState::getOverallSuccessRate() const {
    if (m_iterations.empty()) return 0.0f;
    return (float)getCompletedIterations() / (float)m_iterations.size();
}

std::string AgenticLoopState::getStateAsSummary() const {
    std::string summary = "AgenticLoopState Summary:\n";
    summary += "- Current Phase: " + phaseToString(m_currentPhase) + "\n";
    summary += "- Current Status: " + statusToString(m_currentStatus) + "\n";
    summary += "- Total Iterations: " + std::to_string(m_iterations.size()) + "\n";
    summary += "- Completed: " + std::to_string(getCompletedIterations()) + "\n";
    summary += "- Failed: " + std::to_string(getFailedIterations()) + "\n";
    summary += "- Success Rate: " + std::to_string(getOverallSuccessRate()) + "\n";
    summary += "- Current Goal: " + m_currentGoal + "\n";
    return summary;
}

// ===== SERIALIZATION =====

std::string AgenticLoopState::serializeState() const {
    json state;
    state["current_phase"] = static_cast<int>(m_currentPhase);
    state["current_status"] = static_cast<int>(m_currentStatus);
    state["current_goal"] = m_currentGoal;
    state["progress_current"] = m_progressCurrent;
    state["progress_total"] = m_progressTotal;
    state["memory"] = m_memory;
    state["constraints"] = m_constraints;
    state["applied_strategies"] = m_appliedStrategies;
    state["suggested_strategies"] = m_suggestedStrategies;
    state["last_snapshot"] = m_lastSnapshot;
    return state.dump(2);
}

bool AgenticLoopState::deserializeState(const std::string& jsonStr) {
    try {
        json state = json::parse(jsonStr);
        m_currentPhase = static_cast<ReasoningPhase>(state.value("current_phase", 0));
        m_currentStatus = static_cast<IterationStatus>(state.value("current_status", 0));
        m_currentGoal = state.value("current_goal", "");
        m_progressCurrent = state.value("progress_current", 0);
        m_progressTotal = state.value("progress_total", 0);
        m_memory = state.value("memory", json::object());
        m_constraints = state.value("constraints", json::object());
        m_appliedStrategies = state.value("applied_strategies", std::vector<std::string>());
        m_suggestedStrategies = state.value("suggested_strategies", std::vector<std::string>());
        m_lastSnapshot = state.value("last_snapshot", json::object());
        return true;
    } catch (...) {
        return false;
    }
}

// ===== DEBUGGING =====

std::string AgenticLoopState::generateDebugReport() const {
    std::string report = "Debug Report:\n";
    report += getStateAsSummary();
    report += "\nMetrics:\n";
    report += getMetrics().dump(2);
    return report;
}
