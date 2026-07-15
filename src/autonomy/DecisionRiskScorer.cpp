/**
 * DecisionRiskScorer.cpp
 *
 * Phase C.4 Batch 4/5: Safety-Gated Decision Engine
 */

#include "DecisionRiskScorer.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace Autonomy {

// ============================================================================
// RiskLevel Conversions
// ============================================================================

std::string RiskLevelToString(RiskLevel level) {
    switch (level) {
        case RiskLevel::SAFE: return "SAFE";
        case RiskLevel::CAUTION: return "CAUTION";
        case RiskLevel::UNSAFE: return "UNSAFE";
        case RiskLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

RiskLevel ClassifyRisk(double score) {
    if (score < 0.2) return RiskLevel::SAFE;
    if (score < 0.5) return RiskLevel::CAUTION;
    if (score < 0.8) return RiskLevel::UNSAFE;
    return RiskLevel::CRITICAL;
}

// ============================================================================
// RiskWeights Implementation
// ============================================================================

double RiskWeights::CalculateWeightedScore(const std::map<std::string, double>& factors) const {
    double score = 0.0;
    
    auto it = factors.find("stateInstability");
    if (it != factors.end()) score += it->second * stateInstability;
    
    it = factors.find("resourcePressure");
    if (it != factors.end()) score += it->second * resourcePressure;
    
    it = factors.find("failureHistory");
    if (it != factors.end()) score += it->second * failureHistory;
    
    it = factors.find("mutationRisk");
    if (it != factors.end()) score += it->second * mutationRisk;
    
    it = factors.find("intentRisk");
    if (it != factors.end()) score += it->second * intentRisk;
    
    it = factors.find("oscillationSeverity");
    if (it != factors.end()) score += it->second * oscillationSeverity;
    
    return std::min(1.0, std::max(0.0, score));
}

std::string RiskWeights::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"stateInstability\":" << stateInstability << ",";
    json << "\"resourcePressure\":" << resourcePressure << ",";
    json << "\"failureHistory\":" << failureHistory << ",";
    json << "\"mutationRisk\":" << mutationRisk << ",";
    json << "\"intentRisk\":" << intentRisk << ",";
    json << "\"oscillationSeverity\":" << oscillationSeverity;
    json << "}";
    return json.str();
}

// ============================================================================
// RiskFactors Implementation
// ============================================================================

double RiskFactors::CalculateTotalScore(const RiskWeights& weights) const {
    return weights.CalculateWeightedScore(ToMap());
}

std::map<std::string, double> RiskFactors::ToMap() const {
    std::map<std::string, double> map;
    map["stateInstability"] = stateInstability;
    map["resourcePressure"] = resourcePressure;
    map["failureHistory"] = failureHistory;
    map["mutationRisk"] = mutationRisk;
    map["intentRisk"] = intentRisk;
    map["oscillationSeverity"] = oscillationSeverity;
    return map;
}

std::string RiskFactors::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"stateInstability\":" << stateInstability << ",";
    json << "\"resourcePressure\":" << resourcePressure << ",";
    json << "\"failureHistory\":" << failureHistory << ",";
    json << "\"mutationRisk\":" << mutationRisk << ",";
    json << "\"intentRisk\":" << intentRisk << ",";
    json << "\"oscillationSeverity\":" << oscillationSeverity;
    json << "}";
    return json.str();
}

// ============================================================================
// DecisionAssessment Implementation
// ============================================================================

std::string DecisionAssessment::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"decisionId\":\"" << decisionId << "\",";
    json << "\"decisionType\":\"" << decisionType << "\",";
    json << "\"confidence\":" << confidence << ",";
    json << "\"expectedReward\":" << expectedReward << ",";
    json << "\"estimatedRisk\":" << estimatedRisk << ",";
    json << "\"stabilityImpact\":" << stabilityImpact << ",";
    json << "\"rollbackProbability\":" << rollbackProbability << ",";
    json << "\"riskLevel\":\"" << RiskLevelToString(riskLevel) << "\",";
    json << "\"approved\":" << (approved ? "true" : "false") << ",";
    json << "\"reason\":\"" << reason << "\",";
    json << "\"riskFactors\":" << riskFactors.ToJson() << ",";
    json << "\"assessedAtMs\":" << assessedAtMs;
    json << "}";
    return json.str();
}

void DecisionAssessment::Print() const {
    const char* color = "\033[0m";
    if (riskLevel == RiskLevel::CRITICAL) color = "\033[31m";
    else if (riskLevel == RiskLevel::UNSAFE) color = "\033[33m";
    else if (riskLevel == RiskLevel::CAUTION) color = "\033[35m";
    else color = "\033[32m";
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  DECISION ASSESSMENT                                             ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Decision: " << std::left << std::setw(47) << decisionId << " ║\n";
    std::cout << "║  Type:     " << std::setw(48) << decisionType << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << color;
    std::cout << "║  Status:   " << std::setw(48) << (approved ? "APPROVED" : "REJECTED") << " ║\n";
    std::cout << "║  Risk:     " << std::setw(48) << RiskLevelToString(riskLevel) << " ║\n";
    std::cout << "║  Score:    " << std::setw(45) << std::fixed << std::setprecision(3) << estimatedRisk << " ║\n";
    std::cout << "\033[0m";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Metrics                                                           ║\n";
    std::cout << "║  Confidence:        " << std::setw(38) << std::setprecision(2) << confidence << " ║\n";
    std::cout << "║  Expected Reward:  " << std::setw(38) << expectedReward << " ║\n";
    std::cout << "║  Stability Impact:  " << std::setw(38) << stabilityImpact << " ║\n";
    std::cout << "║  Rollback Prob:    " << std::setw(38) << rollbackProbability << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Risk Factors                                                      ║\n";
    std::cout << "║  State Instability:  " << std::setw(36) << riskFactors.stateInstability << " ║\n";
    std::cout << "║  Resource Pressure: " << std::setw(36) << riskFactors.resourcePressure << " ║\n";
    std::cout << "║  Failure History:   " << std::setw(36) << riskFactors.failureHistory << " ║\n";
    std::cout << "║  Mutation Risk:     " << std::setw(36) << riskFactors.mutationRisk << " ║\n";
    std::cout << "║  Intent Risk:        " << std::setw(36) << riskFactors.intentRisk << " ║\n";
    std::cout << "║  Oscillation:        " << std::setw(36) << riskFactors.oscillationSeverity << " ║\n";
    if (!reason.empty()) {
        std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Reason: " << std::setw(55) << reason << " ║\n";
    }
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

bool DecisionAssessment::CanProceed() const {
    return approved && riskLevel <= RiskLevel::CAUTION;
}

std::string DecisionAssessment::GetRecommendation() const {
    if (riskLevel == RiskLevel::SAFE) {
        return "Proceed with confidence";
    } else if (riskLevel == RiskLevel::CAUTION) {
        return "Proceed with monitoring";
    } else if (riskLevel == RiskLevel::UNSAFE) {
        return "Requires additional validation";
    } else {
        return "Blocked - unsafe to proceed";
    }
}

// ============================================================================
// DecisionHistory Implementation
// ============================================================================

DecisionHistory::DecisionHistory() = default;
DecisionHistory::~DecisionHistory() = default;

bool DecisionHistory::Initialize(size_t maxHistorySize) {
    maxHistorySize_ = maxHistorySize;
    return true;
}

void DecisionHistory::RecordDecision(const HistoricalDecision& record) {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    history_.push_back(record);
    
    // Prune if needed
    while (history_.size() > maxHistorySize_) {
        history_.erase(history_.begin());
    }
}

double DecisionHistory::GetSuccessRate(const std::string& decisionType) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    int total = 0;
    int successful = 0;
    
    for (const auto& record : history_) {
        if (record.decisionType == decisionType) {
            total++;
            if (record.wasSuccessful) successful++;
        }
    }
    
    if (total == 0) return 1.0;  // No history = assume safe
    return static_cast<double>(successful) / total;
}

double DecisionHistory::GetAverageRisk(const std::string& decisionType) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    double totalRisk = 0.0;
    int count = 0;
    
    for (const auto& record : history_) {
        if (record.decisionType == decisionType) {
            totalRisk += record.riskScore;
            count++;
        }
    }
    
    if (count == 0) return 0.0;
    return totalRisk / count;
}

std::vector<HistoricalDecision> DecisionHistory::GetRecentFailures(int limit) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    std::vector<HistoricalDecision> failures;
    int count = 0;
    
    for (auto it = history_.rbegin(); it != history_.rend() && count < limit; ++it) {
        if (!it->wasSuccessful) {
            failures.push_back(*it);
            count++;
        }
    }
    
    return failures;
}

bool DecisionHistory::HasFailurePattern(const std::string& decisionType) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    int recentFailures = 0;
    int recentTotal = 0;
    
    // Check last 10 decisions of this type
    for (auto it = history_.rbegin(); it != history_.rend() && recentTotal < 10; ++it) {
        if (it->decisionType == decisionType) {
            recentTotal++;
            if (!it->wasSuccessful) recentFailures++;
        }
    }
    
    // Pattern if more than 50% recent failures
    return recentTotal > 0 && (static_cast<double>(recentFailures) / recentTotal) > 0.5;
}

void DecisionHistory::Clear() {
    std::lock_guard<std::mutex> lock(historyMutex_);
    history_.clear();
}

DecisionHistory::HistoryStats DecisionHistory::GetStats() const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    HistoryStats stats;
    stats.totalDecisions = history_.size();
    
    for (const auto& record : history_) {
        if (record.wasApproved) stats.approvedDecisions++;
        else stats.rejectedDecisions++;
        
        if (record.wasSuccessful) stats.successfulDecisions++;
        else stats.failedDecisions++;
    }
    
    if (stats.totalDecisions > 0) {
        stats.overallSuccessRate = static_cast<double>(stats.successfulDecisions) / stats.totalDecisions;
    }
    
    return stats;
}

// ============================================================================
// DecisionRiskScorer Implementation
// ============================================================================

DecisionRiskScorer::DecisionRiskScorer() = default;
DecisionRiskScorer::~DecisionRiskScorer() = default;

bool DecisionRiskScorer::Initialize(const RiskWeights& weights,
                                     StabilityEnvelope* envelope,
                                     OscillationManager* oscillationManager,
                                     DecisionHistory* history) {
    weights_ = weights;
    envelope_ = envelope;
    oscillationManager_ = oscillationManager;
    history_ = history;
    initialized_ = true;
    
    std::cout << "[DecisionRiskScorer] Initialized\n";
    std::cout << "  State instability weight: " << weights.stateInstability << "\n";
    std::cout << "  Resource pressure weight: " << weights.resourcePressure << "\n";
    std::cout << "  Failure history weight: " << weights.failureHistory << "\n";
    
    return true;
}

DecisionAssessment DecisionRiskScorer::AssessDecision(const Decision& decision) {
    DecisionAssessment assessment;
    assessment.decisionId = decision.decisionId;
    assessment.decisionType = DecisionTypeToString(decision.type);
    assessment.confidence = decision.confidence;
    assessment.weights = weights_;
    assessment.assessedAtMs = GetCurrentTimeMs();
    
    // Calculate risk factors
    assessment.riskFactors = CalculateRiskFactors(assessment.decisionType);
    assessment.estimatedRisk = assessment.riskFactors.CalculateTotalScore(weights_);
    assessment.riskLevel = GetRiskLevel(assessment.estimatedRisk);
    
    // Calculate expected reward (based on confidence and historical success)
    double historicalSuccess = 1.0;
    if (history_) {
        historicalSuccess = history_->GetSuccessRate(assessment.decisionType);
    }
    assessment.expectedReward = decision.confidence * historicalSuccess;
    
    // Calculate stability impact
    if (envelope_) {
        auto status = envelope_->GetStatus();
        assessment.stabilityImpact = status.overallStability - 0.5;  // Center around 0
    }
    
    // Calculate rollback probability
    assessment.rollbackProbability = assessment.estimatedRisk * (1.0 - decision.confidence);
    
    // Determine approval
    assessment.approved = (assessment.riskLevel <= RiskLevel::CAUTION) &&
                          (decision.confidence >= 0.5);
    
    if (!assessment.approved) {
        if (assessment.riskLevel > RiskLevel::CAUTION) {
            assessment.reason = "Risk level too high: " + RiskLevelToString(assessment.riskLevel);
        } else {
            assessment.reason = "Confidence below threshold";
        }
    }
    
    return assessment;
}

DecisionAssessment DecisionRiskScorer::AssessIntent(const Intent& intent) {
    DecisionAssessment assessment;
    assessment.decisionId = intent.intentId;
    assessment.decisionType = IntentTypeToString(intent.type);
    assessment.confidence = intent.confidence;
    assessment.weights = weights_;
    assessment.assessedAtMs = GetCurrentTimeMs();
    
    // Calculate risk factors
    assessment.riskFactors = CalculateRiskFactors("intent_" + assessment.decisionType);
    assessment.riskFactors.intentRisk = CalculateIntentRisk(intent);
    assessment.estimatedRisk = assessment.riskFactors.CalculateTotalScore(weights_);
    assessment.riskLevel = GetRiskLevel(assessment.estimatedRisk);
    
    // Expected reward
    assessment.expectedReward = intent.confidence;
    
    // Determine approval
    assessment.approved = (assessment.riskLevel <= RiskLevel::CAUTION) &&
                          (intent.confidence >= 0.6);
    
    if (!assessment.approved) {
        assessment.reason = "Intent risk too high or confidence too low";
    }
    
    return assessment;
}

DecisionAssessment DecisionRiskScorer::AssessMutation(const std::string& mutationType,
                                                       const std::map<std::string, std::string>& parameters) {
    DecisionAssessment assessment;
    assessment.decisionId = "mut_" + std::to_string(GetCurrentTimeMs());
    assessment.decisionType = mutationType;
    assessment.confidence = 0.8;  // Default confidence for mutations
    assessment.weights = weights_;
    assessment.assessedAtMs = GetCurrentTimeMs();
    
    // Calculate risk factors
    assessment.riskFactors = CalculateRiskFactors("mutation_" + mutationType);
    assessment.riskFactors.mutationRisk = CalculateMutationRisk(mutationType);
    assessment.estimatedRisk = assessment.riskFactors.CalculateTotalScore(weights_);
    assessment.riskLevel = GetRiskLevel(assessment.estimatedRisk);
    
    // Check stability requirements
    if (envelope_) {
        auto status = envelope_->GetStatus();
        if (status.overallStability < 0.6) {
            assessment.riskFactors.stateInstability = 0.8;
            assessment.estimatedRisk = assessment.riskFactors.CalculateTotalScore(weights_);
            assessment.riskLevel = GetRiskLevel(assessment.estimatedRisk);
        }
    }
    
    // Determine approval
    assessment.approved = (assessment.riskLevel <= RiskLevel::UNSAFE);
    
    if (!assessment.approved) {
        assessment.reason = "Mutation risk too high for current system state";
    }
    
    return assessment;
}

RiskFactors DecisionRiskScorer::CalculateRiskFactors(const std::string& actionType) {
    RiskFactors factors;
    
    factors.stateInstability = CalculateStateInstability();
    factors.resourcePressure = CalculateResourcePressure();
    factors.failureHistory = CalculateFailureHistory(actionType);
    factors.mutationRisk = 0.0;  // Calculated separately if needed
    factors.intentRisk = 0.0;    // Calculated separately if needed
    factors.oscillationSeverity = CalculateOscillationSeverity();
    
    return factors;
}

void DecisionRiskScorer::UpdateWeights(const RiskWeights& weights) {
    weights_ = weights;
}

RiskWeights DecisionRiskScorer::GetWeights() const {
    return weights_;
}

RiskLevel DecisionRiskScorer::GetRiskLevel(double score) {
    return ClassifyRisk(score);
}

void DecisionRiskScorer::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  DECISION RISK SCORER                                            ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Risk Weights                                                      ║\n";
    std::cout << "║  State Instability:  " << std::setw(36) << weights_.stateInstability << " ║\n";
    std::cout << "║  Resource Pressure: " << std::setw(36) << weights_.resourcePressure << " ║\n";
    std::cout << "║  Failure History:   " << std::setw(36) << weights_.failureHistory << " ║\n";
    std::cout << "║  Mutation Risk:     " << std::setw(36) << weights_.mutationRisk << " ║\n";
    std::cout << "║  Intent Risk:        " << std::setw(36) << weights_.intentRisk << " ║\n";
    std::cout << "║  Oscillation:        " << std::setw(36) << weights_.oscillationSeverity << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Factor Calculators
// ============================================================================

double DecisionRiskScorer::CalculateStateInstability() {
    if (!envelope_) return 0.0;
    
    auto status = envelope_->GetStatus();
    // Higher instability = lower stability
    return 1.0 - status.overallStability;
}

double DecisionRiskScorer::CalculateResourcePressure() {
    if (!envelope_) return 0.0;
    
    auto status = envelope_->GetStatus();
    return status.resourceUtilization;
}

double DecisionRiskScorer::CalculateFailureHistory(const std::string& decisionType) {
    if (!history_) return 0.0;
    
    double successRate = history_->GetSuccessRate(decisionType);
    // Convert success rate to failure risk
    return 1.0 - successRate;
}

double DecisionRiskScorer::CalculateMutationRisk(const std::string& mutationType) {
    // Base risk by mutation type
    if (mutationType.find("destructive") != std::string::npos) return 0.9;
    if (mutationType.find("irreversible") != std::string::npos) return 0.8;
    if (mutationType.find("major") != std::string::npos) return 0.6;
    if (mutationType.find("minor") != std::string::npos) return 0.3;
    return 0.5;  // Default
}

double DecisionRiskScorer::CalculateIntentRisk(const Intent& intent) {
    // Higher risk for certain intent types
    switch (intent.type) {
        case IntentType::EMERGENCY:
            return 0.9;
        case IntentType::MODIFY:
            return 0.5;
        case IntentType::EXECUTE:
            return 0.4;
        case IntentType::INSPECT:
        case IntentType::QUERY:
            return 0.1;
        default:
            return 0.3;
    }
}

double DecisionRiskScorer::CalculateOscillationSeverity() {
    if (!oscillationManager_) return 0.0;
    
    // Get stability score (1.0 = stable, 0.0 = unstable)
    double stability = oscillationManager_->GetStabilityScore();
    return 1.0 - stability;
}

int64_t DecisionRiskScorer::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ============================================================================
// SafetyGate Implementation
// ============================================================================

SafetyGate::SafetyGate() = default;
SafetyGate::~SafetyGate() = default;

bool SafetyGate::Initialize(SafetyProfileRegistry* profileRegistry,
                             DecisionRiskScorer* riskScorer,
                             SafetyConstraintChecker* constraintChecker) {
    profileRegistry_ = profileRegistry;
    riskScorer_ = riskScorer;
    constraintChecker_ = constraintChecker;
    initialized_ = true;
    
    std::cout << "[SafetyGate] Initialized\n";
    
    return true;
}

DecisionAssessment SafetyGate::Evaluate(const Decision& decision) {
    if (!enabled_) {
        DecisionAssessment assessment;
        assessment.decisionId = decision.decisionId;
        assessment.decisionType = DecisionTypeToString(decision.type);
        assessment.approved = true;
        assessment.reason = "Safety gate disabled";
        return assessment;
    }
    
    // Get risk assessment
    DecisionAssessment assessment = riskScorer_->AssessDecision(decision);
    
    // Check safety profile
    std::string subsystem = "decision";
    auto profileOpt = profileRegistry_->GetProfile(subsystem);
    if (profileOpt.has_value()) {
        auto profile = profileOpt.value();
        
        // Check minimum confidence
        if (decision.confidence < profile.minDecisionConfidence) {
            assessment.approved = false;
            assessment.reason = "Confidence below profile minimum";
        }
        
        // Check action safety
        auto actionSafety = profile.CheckAction(assessment.decisionType);
        if (actionSafety == ActionSafety::FORBIDDEN) {
            assessment.approved = false;
            assessment.reason = "Decision type forbidden by safety profile";
        }
    }
    
    // Check constraints
    std::vector<SafetyViolation> violations;
    if (!constraintChecker_->CheckAction(subsystem, assessment.decisionType, violations)) {
        if (!violations.empty()) {
            assessment.approved = false;
            assessment.reason = violations[0].description;
        }
    }
    
    RecordAssessment(assessment);
    return assessment;
}

DecisionAssessment SafetyGate::Evaluate(const Intent& intent) {
    if (!enabled_) {
        DecisionAssessment assessment;
        assessment.decisionId = intent.intentId;
        assessment.decisionType = IntentTypeToString(intent.type);
        assessment.approved = true;
        assessment.reason = "Safety gate disabled";
        return assessment;
    }
    
    DecisionAssessment assessment = riskScorer_->AssessIntent(intent);
    
    // Check safety profile
    std::string subsystem = "intent";
    auto profileOpt = profileRegistry_->GetProfile(subsystem);
    if (profileOpt.has_value()) {
        auto profile = profileOpt.value();
        
        // Check max intents
        // (Would need intent manager to check actual count)
    }
    
    RecordAssessment(assessment);
    return assessment;
}

DecisionAssessment SafetyGate::EvaluateMutation(const std::string& mutationType,
                                                  const std::map<std::string, std::string>& parameters) {
    if (!enabled_) {
        DecisionAssessment assessment;
        assessment.decisionId = "mut_" + std::to_string(GetCurrentTimeMs());
        assessment.decisionType = mutationType;
        assessment.approved = true;
        assessment.reason = "Safety gate disabled";
        return assessment;
    }
    
    DecisionAssessment assessment = riskScorer_->AssessMutation(mutationType, parameters);
    
    // Check safety profile
    std::string subsystem = "mutation";
    auto profileOpt = profileRegistry_->GetProfile(subsystem);
    if (profileOpt.has_value()) {
        auto profile = profileOpt.value();
        
        // Check action safety
        auto actionSafety = profile.CheckAction(mutationType);
        if (actionSafety == ActionSafety::FORBIDDEN) {
            assessment.approved = false;
            assessment.reason = "Mutation type forbidden by safety profile";
        }
        
        // Check stability requirements
        if (envelope_) {
            auto status = envelope_->GetStatus();
            if (status.overallStability < profile.minStabilityForMutation) {
                assessment.approved = false;
                assessment.reason = "Stability below mutation threshold";
            }
        }
    }
    
    RecordAssessment(assessment);
    return assessment;
}

bool SafetyGate::IsSafe(const std::string& subsystem, const std::string& action) {
    if (!enabled_) return true;
    
    auto profileOpt = profileRegistry_->GetProfile(subsystem);
    if (!profileOpt.has_value()) return true;
    
    auto safety = profileOpt.value().CheckAction(action);
    return safety == ActionSafety::ALLOWED || safety == ActionSafety::RESTRICTED;
}

std::optional<DecisionAssessment> SafetyGate::GetLastAssessment() const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    if (assessmentHistory_.empty()) {
        return std::nullopt;
    }
    
    return assessmentHistory_.back();
}

std::vector<DecisionAssessment> SafetyGate::GetAssessmentHistory(int limit) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    std::vector<DecisionAssessment> recent;
    int count = 0;
    
    for (auto it = assessmentHistory_.rbegin(); it != assessmentHistory_.rend() && count < limit; ++it, ++count) {
        recent.push_back(*it);
    }
    
    return recent;
}

void SafetyGate::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  SAFETY GATE                                                     ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Status: " << std::setw(50) << (enabled_ ? "ENABLED" : "DISABLED") << " ║\n";
    std::cout << "║  Assessments: " << std::setw(46) << assessmentHistory_.size() << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

void SafetyGate::RecordAssessment(const DecisionAssessment& assessment) {
    std::lock_guard<std::mutex> lock(historyMutex_);
    assessmentHistory_.push_back(assessment);
    
    // Keep only last 1000 assessments
    while (assessmentHistory_.size() > 1000) {
        assessmentHistory_.erase(assessmentHistory_.begin());
    }
}

// ============================================================================
// CLI Implementation
// ============================================================================

void SafetyGateCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     SAFETY GATE - Phase C.4 Batch 4/5                             ║\n";
    std::cout << "║     Decision Risk Validation                                       ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void SafetyGateCLI::PrintUsage() {
    std::cout << "Usage: safety-gate [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --interactive        Start interactive mode\n";
    std::cout << "  --test <type>       Test specific decision type\n";
    std::cout << "  --profiles           List safety profiles\n";
    std::cout << "  --help               Show this help\n\n";
}

void SafetyGateCLI::InteractiveMode(SafetyGate& gate) {
    std::cout << "\nInteractive Safety Gate\n";
    std::cout << "Commands: status, test <type>, profiles, enable, disable, quit\n\n";
    
    std::string command;
    while (true) {
        std::cout << "safety> ";
        std::getline(std::cin, command);
        
        if (command == "quit" || command == "exit") {
            break;
        }
        
        if (command == "status") {
            gate.PrintStatus();
        } else if (command.substr(0, 4) == "test") {
            std::string type = command.substr(5);
            SimulateDecision(gate, type);
        } else if (command == "profiles") {
            auto profiles = gate.GetProfileRegistry()->ListProfiles();
            std::cout << "\nSafety Profiles:\n";
            for (const auto& name : profiles) {
                std::cout << "  - " << name << "\n";
            }
        } else if (command == "enable") {
            gate.SetEnabled(true);
            std::cout << "Safety gate enabled\n";
        } else if (command == "disable") {
            gate.SetEnabled(false);
            std::cout << "Safety gate disabled\n";
        } else if (!command.empty()) {
            std::cout << "Unknown command: " << command << "\n";
        }
    }
}

void SafetyGateCLI::SimulateDecision(SafetyGate& gate, const std::string& decisionType) {
    Decision decision;
    decision.decisionId = "test_" + std::to_string(GetCurrentTimeMs());
    decision.type = DecisionType::OPTIMIZE;
    decision.confidence = 0.8;
    
    auto assessment = gate.Evaluate(decision);
    assessment.Print();
}

int SafetyGateCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    // Initialize components
    SafetyProfileRegistry profileRegistry;
    profileRegistry.Initialize();
    
    RiskWeights weights;
    DecisionRiskScorer riskScorer;
    riskScorer.Initialize(weights, nullptr, nullptr, nullptr);
    
    SafetyConstraintChecker constraintChecker;
    constraintChecker.Initialize(&profileRegistry);
    
    SafetyGate gate;
    if (!gate.Initialize(&profileRegistry, &riskScorer, &constraintChecker)) {
        std::cerr << "Failed to initialize safety gate\n";
        return 1;
    }
    
    if (argc > 1 && std::string(argv[1]) == "--interactive") {
        InteractiveMode(gate);
        return 0;
    }
    
    if (argc > 1 && std::string(argv[1]) == "--profiles") {
        auto profiles = profileRegistry.ListProfiles();
        std::cout << "\nSafety Profiles:\n";
        for (const auto& name : profiles) {
            std::cout << "  - " << name << "\n";
        }
        return 0;
    }
    
    // Default: show status
    gate.PrintStatus();
    profileRegistry.PrintStatus();
    
    return 0;
}

} // namespace Autonomy
