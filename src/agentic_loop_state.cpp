// AgenticLoopState Implementation (Qt-free)
#include "agentic_loop_state.h"
<<<<<<< HEAD
=======


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <sstream>
#include <iomanip>

// ===== STATIC HELPERS =====

// Const overloads (actual implementation)
std::string AgenticLoopState::timePointToISO(const TimePoint& tp) const
{
    auto tt = std::chrono::system_clock::to_time_t(tp);
    struct tm tmBuf;
#ifdef _WIN32
    localtime_s(&tmBuf, &tt);
#else
    localtime_r(&tt, &tmBuf);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tmBuf);
    return std::string(buf);
}

std::string AgenticLoopState::timePointToHMS(const TimePoint& tp) const
{
    auto tt = std::chrono::system_clock::to_time_t(tp);
    struct tm tmBuf;
#ifdef _WIN32
    localtime_s(&tmBuf, &tt);
#else
    localtime_r(&tt, &tmBuf);
#endif
    char buf[16];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", &tmBuf);
    return std::string(buf);
}

AgenticLoopState::AgenticLoopState()
    : m_currentPhase(ReasoningPhase::Analysis)
    , m_currentStatus(IterationStatus::NotStarted)
<<<<<<< HEAD
    , m_stateStartTime(std::chrono::system_clock::now())
    , m_lastUpdateTime(std::chrono::system_clock::now())
    , m_constraints(nlohmann::json::object())
    , m_lastSnapshot(nlohmann::json::object())
{
    fprintf(stderr, "[AgenticLoopState] Initialized - Ready for iterative reasoning\n");
=======
    , m_stateStartTime(std::chrono::system_clock::time_point::currentDateTime())
    , m_lastUpdateTime(std::chrono::system_clock::time_point::currentDateTime())
{
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

AgenticLoopState::~AgenticLoopState()
{
<<<<<<< HEAD
    fprintf(stderr, "[AgenticLoopState] Destroyed - Cleaned up %zu iterations\n", m_iterations.size());
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ===== ITERATION MANAGEMENT =====

void AgenticLoopState::startIteration(const std::string& goal)
{
    Iteration iteration;
<<<<<<< HEAD
    iteration.iterationNumber = static_cast<int>(m_iterations.size()) + 1;
    iteration.startTime = std::chrono::system_clock::now();
=======
    iteration.iterationNumber = m_iterations.size() + 1;
    iteration.startTime = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    iteration.currentPhase = ReasoningPhase::Analysis;
    iteration.status = IterationStatus::InProgress;
    iteration.goalStatement = goal;
    iteration.contextSnapshot = getAllMemory();
    iteration.successScore = 0.0f;
    iteration.errorCount = 0;

    m_iterations.push_back(iteration);
    m_currentStatus = IterationStatus::InProgress;

    if (m_debugMode) {
<<<<<<< HEAD
        fprintf(stderr, "[AgenticLoopState] Started iteration %d - %s\n",
                iteration.iterationNumber, goal.c_str());
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

void AgenticLoopState::endIteration(IterationStatus status, const std::string& result)
{
    if (m_iterations.empty()) return;

    Iteration& iteration = m_iterations.back();
<<<<<<< HEAD
    iteration.endTime = std::chrono::system_clock::now();
=======
    iteration.endTime = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    iteration.status = status;
    iteration.resultSummary = result;

    // Update context window
    m_contextWindow.push_back(iteration);
    if (static_cast<int>(m_contextWindow.size()) > m_contextWindowSize) {
        m_contextWindow.pop_front();
    }

    m_currentStatus = status;
<<<<<<< HEAD
    m_lastUpdateTime = std::chrono::system_clock::now();

    if (m_debugMode) {
        fprintf(stderr, "[AgenticLoopState] Ended iteration %d - Status: %s\n",
                iteration.iterationNumber, statusToString(status).c_str());
=======
    m_lastUpdateTime = std::chrono::system_clock::time_point::currentDateTime();

    if (m_debugMode) {
                 << "- Status:" << statusToString(status);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

AgenticLoopState::Iteration* AgenticLoopState::getCurrentIteration()
{
    if (m_iterations.empty()) return nullptr;
    return &m_iterations.back();
}

// ===== PHASE MANAGEMENT =====

void AgenticLoopState::setCurrentPhase(ReasoningPhase phase)
{
    m_lastPhaseFinished = m_currentPhase;
    m_currentPhase = phase;
<<<<<<< HEAD
    m_lastPhaseStarted = phase;
    m_lastUpdateTime = std::chrono::system_clock::now();

    if (m_debugMode) {
        fprintf(stderr, "[AgenticLoopState] Phase transitioned to %s\n",
                phaseToString(phase).c_str());
=======
    m_lastUpdateTime = std::chrono::system_clock::time_point::currentDateTime();

    if (m_debugMode) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

float AgenticLoopState::getPhaseProgress() const
{
    if (m_iterations.empty()) return 0.0f;

    int completed = getCompletedIterations();
    float baseProgress = (completed * 100.0f) / m_iterations.size();

    auto curr = m_iterations.back();
    float phaseWeight = 0.0f;
    switch (curr.currentPhase) {
        case ReasoningPhase::Analysis:     phaseWeight = 0.1f;  break;
        case ReasoningPhase::Planning:     phaseWeight = 0.3f;  break;
        case ReasoningPhase::Execution:    phaseWeight = 0.6f;  break;
        case ReasoningPhase::Verification: phaseWeight = 0.8f;  break;
        case ReasoningPhase::Reflection:   phaseWeight = 0.9f;  break;
        case ReasoningPhase::Adjustment:   phaseWeight = 0.95f; break;
    }

    float iterationProgress = phaseWeight / m_iterations.size() * 100.0f;
    return std::min(99.9f, baseProgress + iterationProgress);
}

std::vector<std::string> AgenticLoopState::getAllPhaseTransitions() const
{
    std::vector<std::string> transitions;
    for (const auto& iteration : m_iterations) {
        transitions.push_back(phaseToString(iteration.currentPhase));
    }
    return transitions;
}

const AgenticLoopState::Iteration* AgenticLoopState::getLastStartedIteration() const
{
    if (m_iterations.empty()) return nullptr;
    return &m_iterations.back();
}

const AgenticLoopState::Iteration* AgenticLoopState::getLastCompletedIteration() const
{
    if (!m_contextWindow.empty())
        return &m_contextWindow.back();
    for (auto it = m_iterations.crbegin(); it != m_iterations.crend(); ++it) {
        if (it->status == IterationStatus::Completed || it->status == IterationStatus::Failed ||
            it->status == IterationStatus::MaxAttemptsReached)
            return &(*it);
    }
    return nullptr;
}

// ===== DECISION TRACKING =====

void AgenticLoopState::recordDecision(
    const std::string& description,
<<<<<<< HEAD
    const nlohmann::json& reasoning,
=======
    const void*& reasoning,
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    float confidence)
{
    if (m_iterations.empty()) return;

    Decision decision;
<<<<<<< HEAD
    decision.timestamp = std::chrono::system_clock::now();
=======
    decision.timestamp = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    decision.phase = m_currentPhase;
    decision.description = description;
    decision.reasoning = reasoning;
    decision.confidence = confidence;
    decision.success = false;
    decision.retryCount = 0;

    m_iterations.back().decisions.push_back(decision);

    if (m_debugMode) {
<<<<<<< HEAD
        fprintf(stderr, "[AgenticLoopState] Recorded decision: %s - Confidence: %.2f\n",
                description.c_str(), confidence);
=======
                 << "- Confidence:" << confidence;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

void AgenticLoopState::recordDecisionOutcome(
    int decisionIndex,
<<<<<<< HEAD
    const nlohmann::json& outcome,
=======
    const void*& outcome,
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    bool success)
{
    if (m_iterations.empty() ||
        decisionIndex >= static_cast<int>(m_iterations.back().decisions.size())) {
        return;
    }

    auto& decision = m_iterations.back().decisions[decisionIndex];
    decision.outcome = outcome;
    decision.success = success;

    if (m_debugMode) {
<<<<<<< HEAD
        fprintf(stderr, "[AgenticLoopState] Decision outcome recorded - Success: %s\n",
                success ? "true" : "false");
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

std::vector<AgenticLoopState::Decision> AgenticLoopState::getDecisionHistory(int limit) const
{
    std::vector<Decision> allDecisions;

    for (const auto& iteration : m_iterations) {
        for (const auto& decision : iteration.decisions) {
            allDecisions.push_back(decision);
        }
    }

    if (limit > 0 && static_cast<int>(allDecisions.size()) > limit) {
        allDecisions.erase(allDecisions.begin(),
                           allDecisions.end() - limit);
    }

    return allDecisions;
}

AgenticLoopState::Decision* AgenticLoopState::getCurrentDecision()
{
    if (m_iterations.empty() || m_iterations.back().decisions.empty()) {
        return nullptr;
    }
    return &m_iterations.back().decisions.back();
}

float AgenticLoopState::getAverageDecisionConfidence() const
{
    auto decisions = getDecisionHistory();
    if (decisions.empty()) return 0.0f;

    float total = 0.0f;
    for (const auto& decision : decisions) {
        total += decision.confidence;
    }

    return total / decisions.size();
}

float AgenticLoopState::getDecisionSuccessRate() const
{
    auto decisions = getDecisionHistory();
    if (decisions.empty()) return 0.0f;

    int successful = 0;
    for (const auto& decision : decisions) {
        if (decision.success) successful++;
    }

    return (successful * 100.0f) / decisions.size();
}

// ===== ERROR TRACKING =====

void AgenticLoopState::recordError(
    const std::string& errorType,
    const std::string& message,
    const std::string& stackTrace)
{
    ErrorRecord error;
<<<<<<< HEAD
    error.timestamp = std::chrono::system_clock::now();
=======
    error.timestamp = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    error.errorType = errorType;
    error.errorMessage = message;
    error.stackTrace = stackTrace;
    error.phase = m_currentPhase;
    error.recoveryAttempt = 0;
    error.recoverySucceeded = false;

    if (!m_iterations.empty()) {
        m_iterations.back().errorCount++;
    }

    m_errorHistory.push_back(error);

    // Keep error history bounded
    if (m_errorHistory.size() > 100) {
        m_errorHistory.pop_front();
    }

    if (m_debugMode) {
<<<<<<< HEAD
        fprintf(stderr, "[AgenticLoopState] Error recorded: %s - %s\n",
                errorType.c_str(), message.c_str());
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

void AgenticLoopState::recordErrorRecovery(
    int errorIndex,
    const std::string& strategy,
    bool succeeded)
{
    if (errorIndex >= static_cast<int>(m_errorHistory.size())) return;

    auto& error = m_errorHistory[errorIndex];
    error.recoveryStrategy = strategy;
    error.recoverySucceeded = succeeded;

    if (m_debugMode) {
<<<<<<< HEAD
        fprintf(stderr, "[AgenticLoopState] Error recovery recorded - Strategy: %s - Success: %s\n",
                strategy.c_str(), succeeded ? "true" : "false");
=======
                 << "- Success:" << succeeded;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

const std::deque<AgenticLoopState::ErrorRecord>& AgenticLoopState::getErrorHistory(size_t limit) const
{
    return m_errorHistory;
}

float AgenticLoopState::getErrorRate() const
{
    if (m_iterations.empty()) return 0.0f;

    int totalErrors = 0;
    for (const auto& iteration : m_iterations) {
        totalErrors += iteration.errorCount;
    }

    return (totalErrors * 100.0f) / m_iterations.size();
}

std::string AgenticLoopState::generateErrorAnalysis() const
{
<<<<<<< HEAD
    nlohmann::json analysis;
=======
    void* analysis;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    analysis["total_errors"] = getTotalErrorCount();
    analysis["error_rate"] = getErrorRate();

    // Group errors by type
    std::unordered_map<std::string, int> errorTypeCounts;
    for (const auto& error : m_errorHistory) {
        errorTypeCounts[error.errorType]++;
    }

<<<<<<< HEAD
    nlohmann::json errorTypes = nlohmann::json::object();
    for (const auto& pair : errorTypeCounts) {
        errorTypes[pair.first] = pair.second;
    }
    analysis["error_types"] = errorTypes;

    return analysis.dump();
=======
    void* errorTypes;
    for (const auto& pair : errorTypeCounts) {
        errorTypes[std::string::fromStdString(pair.first)] = pair.second;
    }
    analysis["error_types"] = errorTypes;

    return std::string::fromUtf8(void*(analysis).toJson());
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ===== SNAPSHOTS =====

<<<<<<< HEAD
nlohmann::json AgenticLoopState::takeSnapshot()
{
    nlohmann::json snapshot;
    snapshot["timestamp"] = timePointToISO(std::chrono::system_clock::now());
=======
void* AgenticLoopState::takeSnapshot()
{
    void* snapshot;
    snapshot["timestamp"] = std::chrono::system_clock::time_point::currentDateTime().toString(//ISODate);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    snapshot["phase"] = phaseToString(m_currentPhase);
    snapshot["status"] = statusToString(m_currentStatus);
    snapshot["iterations_completed"] = getCompletedIterations();
    snapshot["total_iterations"] = getTotalIterations();
    snapshot["progress"] = getProgressPercentage();
    snapshot["error_count"] = getTotalErrorCount();
    snapshot["average_confidence"] = getAverageDecisionConfidence();
    snapshot["decision_success_rate"] = getDecisionSuccessRate();

    m_lastSnapshot = snapshot;
    m_snapshotHistory.push_back(snapshot);

    return snapshot;
}

<<<<<<< HEAD
bool AgenticLoopState::restoreFromSnapshot(const nlohmann::json& snapshot)
=======
bool AgenticLoopState::restoreFromSnapshot(const void*& snapshot)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    // Restore limited state from snapshot
    if (snapshot.contains("phase") && snapshot["phase"].is_string()) {
        m_currentPhase = stringToPhase(snapshot["phase"].get<std::string>());
    }
    if (snapshot.contains("status") && snapshot["status"].is_string()) {
        m_currentStatus = stringToStatus(snapshot["status"].get<std::string>());
    }
    m_lastSnapshot = snapshot;

    if (m_debugMode) {
<<<<<<< HEAD
        fprintf(stderr, "[AgenticLoopState] Restored from snapshot\n");
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    return true;
}

// ===== MEMORY MANAGEMENT =====

<<<<<<< HEAD
void AgenticLoopState::addToMemory(const std::string& key, const nlohmann::json& value)
{
    m_memory[key] = value;
    m_lastUpdateTime = std::chrono::system_clock::now();
}

nlohmann::json AgenticLoopState::getFromMemory(const std::string& key)
=======
void AgenticLoopState::addToMemory(const std::string& key, const std::any& value)
{
    m_memory[key.toStdString()] = value;
    m_lastUpdateTime = std::chrono::system_clock::time_point::currentDateTime();
}

std::any AgenticLoopState::getFromMemory(const std::string& key)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    auto it = m_memory.find(key);
    if (it != m_memory.end()) {
        return it->second;
    }
<<<<<<< HEAD
    return nlohmann::json();
=======
    return std::any();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void AgenticLoopState::removeFromMemory(const std::string& key)
{
    m_memory.erase(key);
}

<<<<<<< HEAD
nlohmann::json AgenticLoopState::getAllMemory() const
{
    nlohmann::json obj = nlohmann::json::object();
    for (const auto& pair : m_memory) {
        obj[pair.first] = pair.second;
=======
void* AgenticLoopState::getAllMemory() const
{
    void* obj;
    for (const auto& pair : m_memory) {
        obj[std::string::fromStdString(pair.first)] = void*::fromVariant(pair.second);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    return obj;
}

void AgenticLoopState::clearMemoryExcept(const std::vector<std::string>& keysToKeep)
{
<<<<<<< HEAD
    std::unordered_map<std::string, nlohmann::json> newMemory;
=======
    std::unordered_map<std::string, std::any> newMemory;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    for (const auto& key : keysToKeep) {
        auto it = m_memory.find(key);
        if (it != m_memory.end()) {
            newMemory[it->first] = it->second;
        }
    }
    m_memory = newMemory;
}

void AgenticLoopState::setContextWindowSize(int size)
{
    m_contextWindowSize = size;
}

<<<<<<< HEAD
nlohmann::json AgenticLoopState::getContextWindow() const
{
    nlohmann::json array = nlohmann::json::array();
    for (const auto& iteration : m_contextWindow) {
        nlohmann::json obj;
=======
void* AgenticLoopState::getContextWindow() const
{
    void* array;
    for (const auto& iteration : m_contextWindow) {
        void* obj;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        obj["iteration"] = iteration.iterationNumber;
        obj["goal"] = iteration.goalStatement;
        obj["status"] = statusToString(iteration.status);
        array.push_back(obj);
    }
    return array;
}

std::string AgenticLoopState::formatContextForModel() const
{
    std::string context;
    context += "=== REASONING CONTEXT ===\n";
<<<<<<< HEAD
    context += "Current Goal: " + m_currentGoal + "\n";
    context += "Current Phase: " + phaseToString(m_currentPhase) + "\n";
    context += "Total Iterations: " + std::to_string(getTotalIterations()) + "\n";
    context += "Progress: " + std::to_string(static_cast<int>(getProgressPercentage())) + "%\n";
=======
    context += std::string("Current Goal: %1\n");
    context += std::string("Current Phase: %1\n"));
    context += std::string("Total Iterations: %1\n"));
    context += std::string("Progress: %1%\n")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    context += "\n=== RECENT DECISIONS ===\n";
    auto decisions = getDecisionHistory(5);
    for (const auto& decision : decisions) {
<<<<<<< HEAD
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f", decision.confidence);
        context += "- " + decision.description + " (Confidence: " + buf + ")\n";
=======
        context += std::string("- %1 (Confidence: %2)\n")
                  
                  ;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    return context;
}

// ===== GOAL AND PROGRESS =====

void AgenticLoopState::updateProgress(int current, int total)
{
    m_progressCurrent = current;
    m_progressTotal = total;
<<<<<<< HEAD
    m_lastUpdateTime = std::chrono::system_clock::now();
=======
    m_lastUpdateTime = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

float AgenticLoopState::getProgressPercentage() const
{
    if (m_progressTotal == 0) {
        return getPhaseProgress();
    }
    return (m_progressCurrent * 100.0f) / m_progressTotal;
}

<<<<<<< HEAD
nlohmann::json AgenticLoopState::getProgressInfo() const
{
    nlohmann::json info;
=======
void* AgenticLoopState::getProgressInfo() const
{
    void* info;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    info["current"] = m_progressCurrent;
    info["total"] = m_progressTotal;
    info["percentage"] = getProgressPercentage();
    info["phase"] = phaseToString(m_currentPhase);
    info["status"] = statusToString(m_currentStatus);
    return info;
}

// ===== CONSTRAINTS =====

void AgenticLoopState::addConstraint(const std::string& key, const std::string& constraint)
{
    m_constraints[key] = constraint;
}

void AgenticLoopState::removeConstraint(const std::string& key)
{
    // The current minimal json.hpp stub lacks erase().
    // Production implementation pending json.hpp upgrade or std::map migration.
    // m_constraints.erase(key);
    (void)key;
}

<<<<<<< HEAD
bool AgenticLoopState::validateAgainstConstraints(const nlohmann::json& action) const
{
    // Simple constraint validation — can be extended
    for (auto it = m_constraints.begin(); it != m_constraints.end(); ++it) {
        const std::string& constraintValue = it.value().get<std::string>();
=======
bool AgenticLoopState::validateAgainstConstraints(const void*& action) const
{
    // Simple constraint validation - can be extended
    for (auto it = m_constraints.constBegin(); it != m_constraints.constEnd(); ++it) {
        const std::string& constraintValue = it.value().toString();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        if (!action.contains(it.key()) && !constraintValue.empty()) {
            return false;
        }
    }
    return true;
}

// ===== STRATEGY TRACKING =====

void AgenticLoopState::recordAppliedStrategy(const std::string& strategy)
{
    m_appliedStrategies.push_back(strategy);
    if (!m_iterations.empty()) {
        m_iterations.back().appliedStrategies.push_back(strategy);
    }
}

void AgenticLoopState::setSuggestedStrategies(const std::vector<std::string>& strategies)
{
    m_suggestedStrategies = strategies;
}

// ===== METRICS =====

<<<<<<< HEAD
nlohmann::json AgenticLoopState::getMetrics() const
{
    nlohmann::json metrics;
=======
void* AgenticLoopState::getMetrics() const
{
    void* metrics;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    metrics["total_iterations"] = getTotalIterations();
    metrics["completed_iterations"] = getCompletedIterations();
    metrics["failed_iterations"] = getFailedIterations();
    metrics["success_rate"] = getOverallSuccessRate();
    metrics["phase_progress"] = getPhaseProgress();
    metrics["decision_success_rate"] = getDecisionSuccessRate();
    metrics["average_confidence"] = getAverageDecisionConfidence();
    metrics["error_rate"] = getErrorRate();
    metrics["total_errors"] = getTotalErrorCount();

    return metrics;
}

int AgenticLoopState::getCompletedIterations() const
{
    int count = 0;
    for (const auto& iteration : m_iterations) {
        if (iteration.status == IterationStatus::Completed) {
            count++;
        }
    }
    return count;
}

int AgenticLoopState::getFailedIterations() const
{
    int count = 0;
    for (const auto& iteration : m_iterations) {
        if (iteration.status == IterationStatus::Failed) {
            count++;
        }
    }
    return count;
}

float AgenticLoopState::getOverallSuccessRate() const
{
    if (m_iterations.empty()) return 0.0f;
    int completed = getCompletedIterations();
    return (completed * 100.0f) / m_iterations.size();
}

std::string AgenticLoopState::getStateAsSummary() const
{
    std::string summary;
<<<<<<< HEAD
    summary += "=== AGENTIC LOOP STATE ===\n";
    summary += "Current Phase: " + phaseToString(m_currentPhase) + "\n";
    summary += "Status: " + statusToString(m_currentStatus) + "\n";
    summary += "Iterations: " + std::to_string(getCompletedIterations()) + "/"
             + std::to_string(getTotalIterations()) + " completed\n";
    summary += "Success Rate: " + std::to_string(static_cast<int>(getOverallSuccessRate())) + "%\n";
    summary += "Errors: " + std::to_string(getTotalErrorCount()) + "\n";
=======
    summary += std::string("=== AGENTIC LOOP STATE ===\n");
    summary += std::string("Current Phase: %1\n"));
    summary += std::string("Status: %1\n"));
    summary += std::string("Iterations: %1/%2 completed\n")
              )
              );
    summary += std::string("Success Rate: %1%\n")));
    summary += std::string("Errors: %1\n"));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    return summary;
}

// ===== SERIALIZATION =====

std::string AgenticLoopState::serializeState() const
{
<<<<<<< HEAD
    nlohmann::json state = nlohmann::json::object();
=======
    void* state;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    state["phase"] = phaseToString(m_currentPhase);
    state["status"] = statusToString(m_currentStatus);
    state["goal"] = m_currentGoal;
    state["metrics"] = getMetrics();
    state["memory"] = getAllMemory();
    state["constraints"] = m_constraints;

<<<<<<< HEAD
    return state.dump();
=======
    return std::string::fromUtf8(void*(state).toJson());
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool AgenticLoopState::deserializeState(const std::string& jsonStr)
{
<<<<<<< HEAD
    try {
        nlohmann::json state = nlohmann::json::parse(jsonStr);
        if (!state.is_object()) return false;

        if (state.contains("phase") && state["phase"].is_string())
            m_currentPhase = stringToPhase(state["phase"].get<std::string>());
        if (state.contains("status") && state["status"].is_string())
            m_currentStatus = stringToStatus(state["status"].get<std::string>());
        if (state.contains("goal") && state["goal"].is_string())
            m_currentGoal = state["goal"].get<std::string>();
=======
    void* doc = void*::fromJson(jsonStr.toUtf8());
    if (!doc.isObject()) return false;

    void* state = doc.object();
    m_currentPhase = stringToPhase(state["phase"].toString());
    m_currentStatus = stringToStatus(state["status"].toString());
    m_currentGoal = state["goal"].toString();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

        return true;
    } catch (...) {
        return false;
    }
}

// ===== DEBUGGING =====

std::string AgenticLoopState::generateDebugReport() const
{
    std::string report;
    report += "=== AGENTIC LOOP STATE DEBUG REPORT ===\n\n";

    report += "ITERATIONS:\n";
    for (const auto& iteration : m_iterations) {
<<<<<<< HEAD
        report += "  " + std::to_string(iteration.iterationNumber) + ". "
                + iteration.goalStatement + " - "
                + statusToString(iteration.status) + "\n";
        report += "     Decisions: " + std::to_string(iteration.decisions.size())
                + ", Errors: " + std::to_string(iteration.errorCount) + "\n";
=======
        report += std::string("  %1. %2 - %3\n")


                  );
        report += std::string("     Decisions: %1, Errors: %2\n")
                  )
                  ;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    report += "\nERRORS:\n";
    for (const auto& error : m_errorHistory) {
<<<<<<< HEAD
        report += "  [" + timePointToHMS(error.timestamp) + "] "
                + error.errorType + " - "
                + error.errorMessage + "\n";
    }

    report += "\nMETRICS:\n";
    nlohmann::json metrics = getMetrics();
    for (auto it = metrics.begin(); it != metrics.end(); ++it) {
        report += "  " + it.key() + ": " + it.value().dump() + "\n";
=======
        report += std::string("  [%1] %2 - %3\n")
                  )
                  
                  ;
    }

    report += "\nMETRICS:\n";
    void* metrics = getMetrics();
    for (auto it = metrics.constBegin(); it != metrics.constEnd(); ++it) {
        report += std::string("  %1: %2\n")).toVariant().toString());
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    return report;
}

// ===== HELPER METHODS =====

std::string AgenticLoopState::phaseToString(ReasoningPhase phase) const
{
    switch (phase) {
        case ReasoningPhase::Analysis:     return "Analysis";
        case ReasoningPhase::Planning:     return "Planning";
        case ReasoningPhase::Execution:    return "Execution";
        case ReasoningPhase::Verification: return "Verification";
        case ReasoningPhase::Reflection:   return "Reflection";
        case ReasoningPhase::Adjustment:   return "Adjustment";
        default:                           return "Unknown";
    }
}

<<<<<<< HEAD
ReasoningPhase AgenticLoopState::stringToPhase(const std::string& str) const
=======
AgenticLoopState::ReasoningPhase AgenticLoopState::stringToPhase(const std::string& str) const
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    if (str == "Analysis")     return ReasoningPhase::Analysis;
    if (str == "Planning")     return ReasoningPhase::Planning;
    if (str == "Execution")    return ReasoningPhase::Execution;
    if (str == "Verification") return ReasoningPhase::Verification;
    if (str == "Reflection")   return ReasoningPhase::Reflection;
    if (str == "Adjustment")   return ReasoningPhase::Adjustment;
    return ReasoningPhase::Analysis;
}

std::string AgenticLoopState::statusToString(IterationStatus status) const
{
    switch (status) {
        case IterationStatus::NotStarted:         return "NotStarted";
        case IterationStatus::InProgress:         return "InProgress";
        case IterationStatus::Completed:          return "Completed";
        case IterationStatus::Failed:             return "Failed";
        case IterationStatus::Recovering:         return "Recovering";
        case IterationStatus::MaxAttemptsReached: return "MaxAttemptsReached";
        default:                                  return "Unknown";
    }
}

<<<<<<< HEAD
IterationStatus AgenticLoopState::stringToStatus(const std::string& str) const
=======
AgenticLoopState::IterationStatus AgenticLoopState::stringToStatus(const std::string& str) const
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    if (str == "NotStarted")         return IterationStatus::NotStarted;
    if (str == "InProgress")         return IterationStatus::InProgress;
    if (str == "Completed")          return IterationStatus::Completed;
    if (str == "Failed")             return IterationStatus::Failed;
    if (str == "Recovering")         return IterationStatus::Recovering;
    if (str == "MaxAttemptsReached") return IterationStatus::MaxAttemptsReached;
    return IterationStatus::NotStarted;
}


