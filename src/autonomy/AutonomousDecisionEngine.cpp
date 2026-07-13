/**
 * AutonomousDecisionEngine.cpp
 *
 * Phase C.3 Batch 1/5: Autonomous Decision Layer - Decision Engine Core
 */

#include "AutonomousDecisionEngine.hpp"
#include "DecisionMemory.hpp"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <random>
#include <chrono>

namespace Autonomy {

// ============================================================================
// DecisionTypes Implementation
// ============================================================================

std::string DecisionTypeToString(DecisionType type) {
    switch (type) {
        case DecisionType::OPTIMIZE_PATH: return "OPTIMIZE_PATH";
        case DecisionType::SPAWN_WORKERS: return "SPAWN_WORKERS";
        case DecisionType::MERGE_TASKS: return "MERGE_TASKS";
        case DecisionType::REBALANCE_RESOURCES: return "REBALANCE_RESOURCES";
        case DecisionType::RECOVER_STATE: return "RECOVER_STATE";
        case DecisionType::EXPLORE_ALTERNATIVE: return "EXPLORE_ALTERNATIVE";
        case DecisionType::FREEZE_UNSTABLE_COMPONENT: return "FREEZE_UNSTABLE_COMPONENT";
        case DecisionType::ADJUST_HARMONICS: return "ADJUST_HARMONICS";
        case DecisionType::SCALE_UP: return "SCALE_UP";
        case DecisionType::SCALE_DOWN: return "SCALE_DOWN";
        case DecisionType::PAUSE_EXECUTION: return "PAUSE_EXECUTION";
        case DecisionType::RESUME_EXECUTION: return "RESUME_EXECUTION";
        case DecisionType::TERMINATE_GRACEFULLY: return "TERMINATE_GRACEFULLY";
        case DecisionType::NONE: return "NONE";
        default: return "UNKNOWN";
    }
}

DecisionType StringToDecisionType(const std::string& str) {
    if (str == "OPTIMIZE_PATH") return DecisionType::OPTIMIZE_PATH;
    if (str == "SPAWN_WORKERS") return DecisionType::SPAWN_WORKERS;
    if (str == "MERGE_TASKS") return DecisionType::MERGE_TASKS;
    if (str == "REBALANCE_RESOURCES") return DecisionType::REBALANCE_RESOURCES;
    if (str == "RECOVER_STATE") return DecisionType::RECOVER_STATE;
    if (str == "EXPLORE_ALTERNATIVE") return DecisionType::EXPLORE_ALTERNATIVE;
    if (str == "FREEZE_UNSTABLE_COMPONENT") return DecisionType::FREEZE_UNSTABLE_COMPONENT;
    if (str == "ADJUST_HARMONICS") return DecisionType::ADJUST_HARMONICS;
    if (str == "SCALE_UP") return DecisionType::SCALE_UP;
    if (str == "SCALE_DOWN") return DecisionType::SCALE_DOWN;
    if (str == "PAUSE_EXECUTION") return DecisionType::PAUSE_EXECUTION;
    if (str == "RESUME_EXECUTION") return DecisionType::RESUME_EXECUTION;
    if (str == "TERMINATE_GRACEFULLY") return DecisionType::TERMINATE_GRACEFULLY;
    return DecisionType::NONE;
}

std::string DecisionPriorityToString(DecisionPriority priority) {
    switch (priority) {
        case DecisionPriority::CRITICAL: return "CRITICAL";
        case DecisionPriority::HIGH: return "HIGH";
        case DecisionPriority::MEDIUM: return "MEDIUM";
        case DecisionPriority::LOW: return "LOW";
        case DecisionPriority::DEFERRED: return "DEFERRED";
        default: return "UNKNOWN";
    }
}

std::string DecisionStatusToString(DecisionStatus status) {
    switch (status) {
        case DecisionStatus::PENDING: return "PENDING";
        case DecisionStatus::APPROVED: return "APPROVED";
        case DecisionStatus::REJECTED: return "REJECTED";
        case DecisionStatus::EXECUTING: return "EXECUTING";
        case DecisionStatus::COMPLETED: return "COMPLETED";
        case DecisionStatus::FAILED: return "FAILED";
        case DecisionStatus::ROLLED_BACK: return "ROLLED_BACK";
        default: return "UNKNOWN";
    }
}

std::string DecisionContext::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"systemStability\":" << systemStability << ",";
    json << "\"resourceUtilization\":" << resourceUtilization << ",";
    json << "\"performanceTrend\":" << performanceTrend << ",";
    json << "\"activeTasks\":" << activeTasks << ",";
    json << "\"pendingTasks\":" << pendingTasks << ",";
    json << "\"errorRate\":" << errorRate << ",";
    json << "\"timestampMs\":" << timestampMs;
    json << "}";
    return json.str();
}

std::string Action::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"actionId\":\"" << actionId << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"targetComponent\":\"" << targetComponent << "\",";
    json << "\"estimatedDurationMs\":" << estimatedDurationMs << ",";
    json << "\"rollbackProbability\":" << rollbackProbability;
    json << "}";
    return json.str();
}

std::string DecisionOutcome::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (success ? "true" : "false") << ",";
    json << "\"actualUtility\":" << actualUtility << ",";
    json << "\"executionTimeMs\":" << executionTimeMs << ",";
    json << "\"errorMessage\":\"" << errorMessage << "\",";
    json << "\"completedTimestampMs\":" << completedTimestampMs;
    json << "}";
    return json.str();
}

std::string Decision::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"decisionId\":\"" << decisionId << "\",";
    json << "\"type\":\"" << DecisionTypeToString(type) << "\",";
    json << "\"priority\":\"" << DecisionPriorityToString(priority) << "\",";
    json << "\"status\":\"" << DecisionStatusToString(status) << "\",";
    json << "\"confidence\":" << std::fixed << std::setprecision(4) << confidence << ",";
    json << "\"expectedUtility\":" << expectedUtility << ",";
    json << "\"riskScore\":" << riskScore << ",";
    json << "\"rationale\":\"" << rationale << "\",";
    json << "\"actions\":[";
    for (size_t i = 0; i < actions.size(); ++i) {
        if (i > 0) json << ",";
        json << actions[i].ToJson();
    }
    json << "],";
    json << "\"context\":" << context.ToJson() << ",";
    json << "\"createdTimestampMs\":" << createdTimestampMs;
    json << "}";
    return json.str();
}

std::string Decision::ToNaturalLanguage() const {
    std::ostringstream nl;
    nl << "Decision [" << DecisionTypeToString(type) << "]: ";
    nl << rationale << " ";
    nl << "(confidence: " << std::fixed << std::setprecision(1) << (confidence * 100) << "%, ";
    nl << "expected utility: " << expectedUtility << ", ";
    nl << "risk: " << (riskScore * 100) << "%)";
    return nl.str();
}

bool Decision::RequiresApproval() const {
    return priority == DecisionPriority::CRITICAL || 
           type == DecisionType::TERMINATE_GRACEFULLY ||
           type == DecisionType::FREEZE_UNSTABLE_COMPONENT;
}

bool Decision::CanExecute() const {
    return status == DecisionStatus::APPROVED || 
           (status == DecisionStatus::PENDING && !RequiresApproval());
}

std::string DecisionEngineConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"minConfidenceThreshold\":" << minConfidenceThreshold << ",";
    json << "\"maxRiskThreshold\":" << maxRiskThreshold << ",";
    json << "\"requireApprovalForCritical\":" << (requireApprovalForCritical ? "true" : "false") << ",";
    json << "\"maxPendingDecisions\":" << maxPendingDecisions << ",";
    json << "\"utilityThreshold\":" << utilityThreshold << ",";
    json << "\"decisionTimeoutMs\":" << decisionTimeoutMs;
    json << "}";
    return json.str();
}

void DecisionStatistics::RecordDecision(const Decision& decision) {
    totalDecisions++;
    decisionsByType[decision.type]++;
    
    switch (decision.status) {
        case DecisionStatus::APPROVED:
            approvedDecisions++;
            break;
        case DecisionStatus::REJECTED:
            rejectedDecisions++;
            break;
        case DecisionStatus::COMPLETED:
            completedDecisions++;
            break;
        case DecisionStatus::FAILED:
            failedDecisions++;
            break;
        case DecisionStatus::ROLLED_BACK:
            rolledBackDecisions++;
            break;
        default:
            break;
    }
    
    // Update averages
    double n = static_cast<double>(totalDecisions);
    averageConfidence = (averageConfidence * (n - 1) + decision.confidence) / n;
    averageRisk = (averageRisk * (n - 1) + decision.riskScore) / n;
    
    if (decision.outcome.has_value()) {
        averageUtility = (averageUtility * (completedDecisions - 1) + decision.outcome->actualUtility) / completedDecisions;
    }
    
    int completed = completedDecisions + failedDecisions;
    if (completed > 0) {
        successRate = static_cast<double>(completedDecisions) / completed;
    }
}

std::string DecisionStatistics::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"totalDecisions\":" << totalDecisions << ",";
    json << "\"approvedDecisions\":" << approvedDecisions << ",";
    json << "\"rejectedDecisions\":" << rejectedDecisions << ",";
    json << "\"completedDecisions\":" << completedDecisions << ",";
    json << "\"failedDecisions\":" << failedDecisions << ",";
    json << "\"rolledBackDecisions\":" << rolledBackDecisions << ",";
    json << "\"averageConfidence\":" << averageConfidence << ",";
    json << "\"averageUtility\":" << averageUtility << ",";
    json << "\"averageRisk\":" << averageRisk << ",";
    json << "\"successRate\":" << successRate;
    json << "}";
    return json.str();
}

void DecisionStatistics::PrintSummary() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           DECISION STATISTICS                                    ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Decisions:      " << std::setw(10) << totalDecisions << std::string(26, ' ') << "║\n";
    std::cout << "║  Approved:             " << std::setw(10) << approvedDecisions << std::string(26, ' ') << "║\n";
    std::cout << "║  Rejected:            " << std::setw(10) << rejectedDecisions << std::string(26, ' ') << "║\n";
    std::cout << "║  Completed:           " << std::setw(10) << completedDecisions << std::string(26, ' ') << "║\n";
    std::cout << "║  Failed:              " << std::setw(10) << failedDecisions << std::string(26, ' ') << "║\n";
    std::cout << "║  Rolled Back:         " << std::setw(10) << rolledBackDecisions << std::string(26, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Average Confidence:   " << std::setw(9) << std::fixed << std::setprecision(1) << (averageConfidence * 100) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "║  Average Utility:     " << std::setw(10) << std::setprecision(3) << averageUtility << std::string(26, ' ') << "║\n";
    std::cout << "║  Average Risk:        " << std::setw(9) << std::setprecision(1) << (averageRisk * 100) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "║  Success Rate:        " << std::setw(9) << std::setprecision(1) << (successRate * 100) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// AutonomousDecisionEngine Implementation
// ============================================================================

AutonomousDecisionEngine::AutonomousDecisionEngine() = default;
AutonomousDecisionEngine::~AutonomousDecisionEngine() = default;

AutonomousDecisionEngine::AutonomousDecisionEngine(AutonomousDecisionEngine&&) noexcept = default;
AutonomousDecisionEngine& AutonomousDecisionEngine::operator=(AutonomousDecisionEngine&&) noexcept = default;

bool AutonomousDecisionEngine::Initialize(const DecisionEngineConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    config_ = config;
    memory_ = std::make_unique<DecisionMemory>();
    governance_ = std::make_unique<DecisionGovernance>();
    
    // Add default constraints
    governance_->AddConstraint({
        "min_confidence",
        [this](const Decision& d) { return d.confidence >= config_.minConfidenceThreshold; },
        "Decision confidence below threshold"
    });
    
    governance_->AddConstraint({
        "max_risk",
        [this](const Decision& d) { return d.riskScore <= config_.maxRiskThreshold; },
        "Decision risk exceeds threshold"
    });
    
    governance_->AddConstraint({
        "min_utility",
        [this](const Decision& d) { return d.expectedUtility >= config_.utilityThreshold; },
        "Decision utility below threshold"
    });
    
    initialized_ = true;
    std::cout << "[AutonomousDecisionEngine] Initialized\n";
    return true;
}

void AutonomousDecisionEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Clear all state
    decisions_.clear();
    while (!pendingQueue_.empty()) pendingQueue_.pop();
    recentDecisionIds_.clear();
    
    memory_.reset();
    governance_.reset();
    
    initialized_ = false;
    std::cout << "[AutonomousDecisionEngine] Shutdown complete\n";
}

void AutonomousDecisionEngine::FeedPatterns(const std::vector<Emergent::Pattern>& patterns) {
    std::lock_guard<std::mutex> lock(mutex_);
    recentPatterns_ = patterns;
}

void AutonomousDecisionEngine::FeedTelemetry(const Telemetry::TelemetrySnapshot& snapshot) {
    std::lock_guard<std::mutex> lock(mutex_);
    latestTelemetry_ = snapshot;
}

void AutonomousDecisionEngine::FeedSwarmState(const Swarm::SwarmState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    latestSwarmState_ = state;
}

void AutonomousDecisionEngine::FeedIntents(const std::vector<Emergent::Intent>& intents) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeIntents_ = intents;
}

std::vector<Decision> AutonomousDecisionEngine::GenerateDecisions() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_ || emergencyStopped_) {
        return {};
    }
    
    std::vector<Decision> newDecisions;
    
    // Generate decisions from different categories
    auto optimizationDecisions = GenerateOptimizationDecisions();
    auto scalingDecisions = GenerateScalingDecisions();
    auto recoveryDecisions = GenerateRecoveryDecisions();
    auto explorationDecisions = GenerateExplorationDecisions();
    
    // Combine all decisions
    newDecisions.insert(newDecisions.end(), optimizationDecisions.begin(), optimizationDecisions.end());
    newDecisions.insert(newDecisions.end(), scalingDecisions.begin(), scalingDecisions.end());
    newDecisions.insert(newDecisions.end(), recoveryDecisions.begin(), recoveryDecisions.end());
    newDecisions.insert(newDecisions.end(), explorationDecisions.begin(), explorationDecisions.end());
    
    // Filter and store valid decisions
    std::vector<Decision> validDecisions;
    for (auto& decision : newDecisions) {
        std::string violation;
        if (governance_->ValidateDecision(decision, violation)) {
            decision.decisionId = GenerateDecisionId();
            decision.createdTimestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            
            decisions_[decision.decisionId] = decision;
            pendingQueue_.push(decision.decisionId);
            recentDecisionIds_.push_back(decision.decisionId);
            
            // Keep only recent history
            if (recentDecisionIds_.size() > 100) {
                recentDecisionIds_.erase(recentDecisionIds_.begin());
            }
            
            validDecisions.push_back(decision);
            
            if (callback_) {
                callback_(decision);
            }
        }
    }
    
    return validDecisions;
}

std::vector<Decision> AutonomousDecisionEngine::GenerateOptimizationDecisions() {
    std::vector<Decision> decisions;
    
    // Check for optimization opportunities
    if (latestTelemetry_ && latestTelemetry_->cpuUtilization > 0.8) {
        Action action;
        action.actionId = "opt-1";
        action.description = "Optimize execution path for high CPU";
        action.targetComponent = "execution_engine";
        action.estimatedDurationMs = 100.0;
        action.rollbackProbability = 0.1;
        
        decisions.push_back(CreateDecision(
            DecisionType::OPTIMIZE_PATH,
            "High CPU utilization detected, optimizing execution path",
            {action}
        ));
    }
    
    return decisions;
}

std::vector<Decision> AutonomousDecisionEngine::GenerateScalingDecisions() {
    std::vector<Decision> decisions;
    
    if (latestSwarmState_ && latestSwarmState_->pendingTasks > 50) {
        Action action;
        action.actionId = "scale-1";
        action.description = "Scale up worker pool";
        action.targetComponent = "swarm_coordinator";
        action.parameters["worker_count"] = "5";
        action.estimatedDurationMs = 500.0;
        action.rollbackProbability = 0.05;
        
        decisions.push_back(CreateDecision(
            DecisionType::SPAWN_WORKERS,
            "High pending task count, scaling up workers",
            {action}
        ));
    }
    
    return decisions;
}

std::vector<Decision> AutonomousDecisionEngine::GenerateRecoveryDecisions() {
    std::vector<Decision> decisions;
    
    // Check for instability patterns
    for (const auto& pattern : recentPatterns_) {
        if (pattern.type == Emergent::PatternType::ANOMALY && pattern.strength > 0.8) {
            Action action;
            action.actionId = "rec-1";
            action.description = "Freeze unstable component";
            action.targetComponent = pattern.source;
            action.estimatedDurationMs = 50.0;
            action.rollbackProbability = 0.2;
            
            decisions.push_back(CreateDecision(
                DecisionType::FREEZE_UNSTABLE_COMPONENT,
                "High anomaly detected in " + pattern.source + ", freezing component",
                {action}
            ));
            break;
        }
    }
    
    return decisions;
}

std::vector<Decision> AutonomousDecisionEngine::GenerateExplorationDecisions() {
    std::vector<Decision> decisions;
    
    // Occasionally explore alternatives
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    
    if (dis(gen) < 0.1) { // 10% chance
        Action action;
        action.actionId = "exp-1";
        action.description = "Explore alternative execution strategy";
        action.targetComponent = "scheduler";
        action.estimatedDurationMs = 200.0;
        action.rollbackProbability = 0.3;
        
        decisions.push_back(CreateDecision(
            DecisionType::EXPLORE_ALTERNATIVE,
            "Exploring alternative execution strategy for optimization",
            {action}
        ));
    }
    
    return decisions;
}

Decision AutonomousDecisionEngine::CreateDecision(DecisionType type, 
                                                   const std::string& rationale,
                                                   const std::vector<Action>& actions) {
    Decision decision;
    decision.type = type;
    decision.rationale = rationale;
    decision.actions = actions;
    decision.context = BuildContext();
    decision.confidence = CalculateConfidence(type, decision.context);
    decision.expectedUtility = CalculateExpectedUtility(type, decision.context);
    decision.riskScore = CalculateRisk(type, decision.context);
    
    // Set priority based on type and context
    if (type == DecisionType::FREEZE_UNSTABLE_COMPONENT || 
        type == DecisionType::RECOVER_STATE) {
        decision.priority = DecisionPriority::CRITICAL;
    } else if (decision.riskScore > 0.7) {
        decision.priority = DecisionPriority::HIGH;
    } else if (decision.expectedUtility > 0.5) {
        decision.priority = DecisionPriority::MEDIUM;
    } else {
        decision.priority = DecisionPriority::LOW;
    }
    
    return decision;
}

DecisionContext AutonomousDecisionEngine::BuildContext() const {
    DecisionContext context;
    context.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    if (latestTelemetry_) {
        context.systemStability = 1.0 - latestTelemetry_->errorRate;
        context.resourceUtilization = latestTelemetry_->cpuUtilization;
        context.errorRate = latestTelemetry_->errorRate;
        context.metrics["memory_usage"] = latestTelemetry_->memoryUsageMB;
        context.metrics["task_throughput"] = latestTelemetry_->tasksPerSecond;
    }
    
    if (latestSwarmState_) {
        context.activeTasks = latestSwarmState_->activeTasks;
        context.pendingTasks = latestSwarmState_->pendingTasks;
    }
    
    return context;
}

double AutonomousDecisionEngine::CalculateConfidence(DecisionType type, const DecisionContext& context) const {
    double baseConfidence = 0.7;
    
    // Adjust based on system stability
    baseConfidence *= context.systemStability;
    
    // Adjust based on data availability
    if (!latestTelemetry_.has_value()) baseConfidence *= 0.8;
    if (!latestSwarmState_.has_value()) baseConfidence *= 0.9;
    
    // Type-specific adjustments
    switch (type) {
        case DecisionType::OPTIMIZE_PATH:
            baseConfidence *= (context.resourceUtilization > 0.7) ? 1.1 : 0.9;
            break;
        case DecisionType::FREEZE_UNSTABLE_COMPONENT:
            baseConfidence *= (context.errorRate > 0.1) ? 1.2 : 0.8;
            break;
        default:
            break;
    }
    
    return std::min(1.0, std::max(0.0, baseConfidence));
}

double AutonomousDecisionEngine::CalculateExpectedUtility(DecisionType type, const DecisionContext& context) const {
    double baseUtility = 0.3;
    
    switch (type) {
        case DecisionType::OPTIMIZE_PATH:
            baseUtility = 0.5 * context.resourceUtilization;
            break;
        case DecisionType::SPAWN_WORKERS:
            baseUtility = context.pendingTasks > 50 ? 0.7 : 0.2;
            break;
        case DecisionType::FREEZE_UNSTABLE_COMPONENT:
            baseUtility = context.errorRate > 0.1 ? 0.9 : 0.1;
            break;
        case DecisionType::RECOVER_STATE:
            baseUtility = context.systemStability < 0.5 ? 0.8 : 0.1;
            break;
        default:
            baseUtility = 0.3;
    }
    
    return std::min(1.0, std::max(0.0, baseUtility));
}

double AutonomousDecisionEngine::CalculateRisk(DecisionType type, const DecisionContext& context) const {
    double baseRisk = 0.2;
    
    switch (type) {
        case DecisionType::TERMINATE_GRACEFULLY:
            baseRisk = 0.9;
            break;
        case DecisionType::FREEZE_UNSTABLE_COMPONENT:
            baseRisk = 0.4;
            break;
        case DecisionType::RECOVER_STATE:
            baseRisk = 0.5;
            break;
        case DecisionType::EXPLORE_ALTERNATIVE:
            baseRisk = 0.3;
            break;
        default:
            baseRisk = 0.2;
    }
    
    // Increase risk if system is unstable
    baseRisk += (1.0 - context.systemStability) * 0.3;
    
    return std::min(1.0, std::max(0.0, baseRisk));
}

std::string AutonomousDecisionEngine::GenerateDecisionId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "dec-" << ms << "-" << dis(gen);
    return id.str();
}

// Additional method implementations would continue here...
// (ApproveDecision, RejectDecision, ExecuteDecision, etc.)

void AutonomousDecisionEngine::SetAutonomousMode(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    autonomousMode_ = enabled;
    std::cout << "[AutonomousDecisionEngine] Autonomous mode: " << (enabled ? "ENABLED" : "DISABLED") << "\n";
}

bool AutonomousDecisionEngine::IsAutonomousMode() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return autonomousMode_;
}

void AutonomousDecisionEngine::EmergencyStop() {
    std::lock_guard<std::mutex> lock(mutex_);
    emergencyStopped_ = true;
    std::cout << "[AutonomousDecisionEngine] EMERGENCY STOP ACTIVATED\n";
}

void AutonomousDecisionEngine::ResumeAutonomy() {
    std::lock_guard<std::mutex> lock(mutex_);
    emergencyStopped_ = false;
    std::cout << "[AutonomousDecisionEngine] Autonomy resumed\n";
}

bool AutonomousDecisionEngine::IsEmergencyStopped() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return emergencyStopped_;
}

void AutonomousDecisionEngine::PrintStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     AUTONOMOUS DECISION ENGINE STATUS                            ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Initialized:        " << std::setw(10) << (initialized_ ? "YES" : "NO") << std::string(26, ' ') << "║\n";
    std::cout << "║  Autonomous Mode:    " << std::setw(10) << (autonomousMode_ ? "ENABLED" : "DISABLED") << std::string(26, ' ') << "║\n";
    std::cout << "║  Emergency Stop:     " << std::setw(10) << (emergencyStopped_ ? "ACTIVE" : "INACTIVE") << std::string(26, ' ') << "║\n";
    std::cout << "║  Pending Decisions:  " << std::setw(10) << pendingQueue_.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Total Decisions:    " << std::setw(10) << decisions_.size() << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// DecisionGovernance Implementation
// ============================================================================

void DecisionGovernance::AddConstraint(const Constraint& constraint) {
    constraints_.push_back(constraint);
}

bool DecisionGovernance::ValidateDecision(const Decision& decision, std::string& violation) const {
    for (const auto& constraint : constraints_) {
        if (!constraint.check(decision)) {
            violation = constraint.violationMessage;
            return false;
        }
    }
    return true;
}

// ============================================================================
// CLI Implementation
// ============================================================================

void AutonomousDecisionEngineCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     AUTONOMOUS DECISION ENGINE - Phase C.3                       ║\n";
    std::cout << "║     Closed Autonomous Control Loop                               ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void AutonomousDecisionEngineCLI::PrintUsage() {
    std::cout << "Usage: autonomy-decision-engine [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --min-confidence X   Minimum confidence threshold (0-1)\n";
    std::cout << "  --max-risk X         Maximum risk threshold (0-1)\n";
    std::cout << "  --autonomous         Enable autonomous mode\n";
    std::cout << "  --help               Show this help\n\n";
}

DecisionEngineConfig AutonomousDecisionEngineCLI::ParseArgs(int argc, char* argv[]) {
    DecisionEngineConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--min-confidence" && i + 1 < argc) {
            config.minConfidenceThreshold = std::stod(argv[++i]);
        } else if (arg == "--max-risk" && i + 1 < argc) {
            config.maxRiskThreshold = std::stod(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int AutonomousDecisionEngineCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    DecisionEngineConfig config = ParseArgs(argc, argv);
    
    // Create and initialize engine
    AutonomousDecisionEngine engine;
    if (!engine.Initialize(config)) {
        std::cerr << "Failed to initialize decision engine\n";
        return 1;
    }
    
    // Check for autonomous mode
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--autonomous") {
            engine.SetAutonomousMode(true);
        }
    }
    
    // Simulate some patterns and telemetry
    std::cout << "[Demo] Simulating system state...\n";
    
    // Generate decisions
    std::cout << "[Demo] Generating decisions...\n";
    auto decisions = engine.GenerateDecisions();
    
    std::cout << "\nGenerated " << decisions.size() << " decisions:\n";
    for (const auto& decision : decisions) {
        std::cout << "  - " << decision.ToNaturalLanguage() << "\n";
    }
    
    // Print status
    engine.PrintStatus();
    
    return 0;
}

} // namespace Autonomy
