/**
 * DecisionRiskScorer.hpp
 *
 * Phase C.4 Batch 4/5: Safety-Gated Decision Engine
 *
 * Calculates risk scores for decisions based on multiple factors.
 * Risk scoring formula combines state instability, resource pressure,
 * historical failures, mutation risk, intent risk, and oscillation severity.
 */

#pragma once

#include "DecisionTypes.hpp"
#include "SafetyProfile.hpp"
#include "StabilityEnvelope.hpp"
#include "OscillationDampener.hpp"
#include "../core/SovereignState.hpp"

#include <cstring>
#include <vector>
#include <map>
#include <memory>

namespace Autonomy {

/**
 * Risk classification
 */
enum class RiskLevel {
    SAFE,       // 0.0-0.2: Safe to proceed
    CAUTION,    // 0.2-0.5: Proceed with caution
    UNSAFE,     // 0.5-0.8: Requires additional validation
    CRITICAL    // 0.8-1.0: Blocked
};

std::string RiskLevelToString(RiskLevel level);
RiskLevel ClassifyRisk(double score);

/**
 * Risk factor weights
 */
struct RiskWeights {
    double stateInstability{0.25};      // Weight for state instability
    double resourcePressure{0.20};       // Weight for resource pressure
    double failureHistory{0.15};       // Weight for historical failures
    double mutationRisk{0.15};           // Weight for mutation risk
    double intentRisk{0.15};            // Weight for intent risk
    double oscillationSeverity{0.10};   // Weight for oscillation severity
    
    double CalculateWeightedScore(const std::map<std::string, double>& factors) const;
    std::string ToJson() const;
};

/**
 * Risk factor scores
 */
struct RiskFactors {
    double stateInstability{0.0};       // State instability score (0-1)
    double resourcePressure{0.0};        // Resource pressure score (0-1)
    double failureHistory{0.0};        // Historical failure score (0-1)
    double mutationRisk{0.0};            // Mutation risk score (0-1)
    double intentRisk{0.0};             // Intent risk score (0-1)
    double oscillationSeverity{0.0};     // Oscillation severity (0-1)
    
    double CalculateTotalScore(const RiskWeights& weights) const;
    std::map<std::string, double> ToMap() const;
    std::string ToJson() const;
};

/**
 * Decision assessment
 */
struct DecisionAssessment {
    std::string decisionId;
    std::string decisionType;
    
    // Scores
    double confidence{0.0};              // Decision confidence (0-1)
    double expectedReward{0.0};          // Expected reward (0-1)
    double estimatedRisk{0.0};         // Overall risk score (0-1)
    double stabilityImpact{0.0};         // Impact on stability (-1 to 1)
    double rollbackProbability{0.0};     // Probability rollback needed (0-1)
    
    // Risk breakdown
    RiskFactors riskFactors;
    RiskWeights weights;
    
    // Assessment
    RiskLevel riskLevel{RiskLevel::SAFE};
    bool approved{false};
    std::string reason;
    std::vector<std::string> warnings;
    std::vector<std::string> blockers;
    
    int64_t assessedAtMs{0};
    
    std::string ToJson() const;
    void Print() const;
    
    // Check if assessment allows proceeding
    bool CanProceed() const;
    
    // Get recommendation
    std::string GetRecommendation() const;
};

/**
 * Historical decision record
 */
struct HistoricalDecision {
    std::string decisionId;
    std::string decisionType;
    double riskScore{0.0};
    bool wasApproved{false};
    bool wasSuccessful{false};
    int64_t timestampMs{0};
    std::string failureReason;
};

/**
 * Historical performance tracker
 */
class DecisionHistory {
public:
    DecisionHistory();
    ~DecisionHistory();

    /**
     * Initialize history
     */
    bool Initialize(size_t maxHistorySize = 1000);

    /**
     * Record decision outcome
     */
    void RecordDecision(const HistoricalDecision& record);

    /**
     * Get success rate for decision type
     */
    double GetSuccessRate(const std::string& decisionType) const;

    /**
     * Get average risk for decision type
     */
    double GetAverageRisk(const std::string& decisionType) const;

    /**
     * Get recent failures
     */
    std::vector<HistoricalDecision> GetRecentFailures(int limit = 10) const;

    /**
     * Check if decision type has pattern of failures
     */
    bool HasFailurePattern(const std::string& decisionType) const;

    /**
     * Clear history
     */
    void Clear();

    /**
     * Get statistics
     */
    struct HistoryStats {
        size_t totalDecisions{0};
        size_t approvedDecisions{0};
        size_t rejectedDecisions{0};
        size_t successfulDecisions{0};
        size_t failedDecisions{0};
        double overallSuccessRate{0.0};
    };
    HistoryStats GetStats() const;

private:
    std::vector<HistoricalDecision> history_;
    mutable std::mutex historyMutex_;
    size_t maxHistorySize_{1000};
};

/**
 * Decision Risk Scorer
 *
 * Calculates comprehensive risk scores for decisions.
 */
class DecisionRiskScorer {
public:
    DecisionRiskScorer();
    ~DecisionRiskScorer();

    // Disable copy
    DecisionRiskScorer(const DecisionRiskScorer&) = delete;
    DecisionRiskScorer& operator=(const DecisionRiskScorer&) = delete;

    /**
     * Initialize scorer
     */
    bool Initialize(const RiskWeights& weights,
                     StabilityEnvelope* envelope,
                     OscillationManager* oscillationManager,
                     DecisionHistory* history);

    /**
     * Assess decision risk
     */
    DecisionAssessment AssessDecision(const Decision& decision);

    /**
     * Assess intent risk
     */
    DecisionAssessment AssessIntent(const Intent& intent);

    /**
     * Assess mutation risk
     */
    DecisionAssessment AssessMutation(const std::string& mutationType,
                                     const std::map<std::string, std::string>& parameters);

    /**
     * Calculate risk factors
     */
    RiskFactors CalculateRiskFactors(const std::string& actionType);

    /**
     * Update risk weights
     */
    void UpdateWeights(const RiskWeights& weights);

    /**
     * Get current weights
     */
    RiskWeights GetWeights() const;

    /**
     * Get risk level for score
     */
    static RiskLevel GetRiskLevel(double score);

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    RiskWeights weights_;
    StabilityEnvelope* envelope_{nullptr};
    OscillationManager* oscillationManager_{nullptr};
    DecisionHistory* history_{nullptr};
    bool initialized_{false};
    
    // Factor calculators
    double CalculateStateInstability();
    double CalculateResourcePressure();
    double CalculateFailureHistory(const std::string& decisionType);
    double CalculateMutationRisk(const std::string& mutationType);
    double CalculateIntentRisk(const Intent& intent);
    double CalculateOscillationSeverity();
    
    // Helpers
    int64_t GetCurrentTimeMs() const;
};

/**
 * Safety Gate
 *
 * Main entry point for safety validation.
 * Combines risk scoring, profile checking, and constraint validation.
 */
class SafetyGate {
public:
    SafetyGate();
    ~SafetyGate();

    // Disable copy
    SafetyGate(const SafetyGate&) = delete;
    SafetyGate& operator=(const SafetyGate&) = delete;

    /**
     * Initialize safety gate
     */
    bool Initialize(SafetyProfileRegistry* profileRegistry,
                   DecisionRiskScorer* riskScorer,
                   SafetyConstraintChecker* constraintChecker);

    /**
     * Evaluate decision
     */
    DecisionAssessment Evaluate(const Decision& decision);

    /**
     * Evaluate intent
     */
    DecisionAssessment Evaluate(const Intent& intent);

    /**
     * Evaluate mutation
     */
    DecisionAssessment EvaluateMutation(const std::string& mutationType,
                                       const std::map<std::string, std::string>& parameters);

    /**
     * Quick safety check
     */
    bool IsSafe(const std::string& subsystem, const std::string& action);

    /**
     * Get last assessment
     */
    std::optional<DecisionAssessment> GetLastAssessment() const;

    /**
     * Get assessment history
     */
    std::vector<DecisionAssessment> GetAssessmentHistory(int limit = 10) const;

    /**
     * Enable/disable gate
     */
    void SetEnabled(bool enabled) { enabled_ = enabled; }
    bool IsEnabled() const { return enabled_; }

    /**
     * Print status
     */
    void PrintStatus() const;

    // Component access
    SafetyProfileRegistry* GetProfileRegistry() { return profileRegistry_; }
    DecisionRiskScorer* GetRiskScorer() { return riskScorer_; }
    SafetyConstraintChecker* GetConstraintChecker() { return constraintChecker_; }

private:
    SafetyProfileRegistry* profileRegistry_{nullptr};
    DecisionRiskScorer* riskScorer_{nullptr};
    SafetyConstraintChecker* constraintChecker_{nullptr};
    bool initialized_{false};
    bool enabled_{true};
    
    // Assessment history
    std::vector<DecisionAssessment> assessmentHistory_;
    mutable std::mutex historyMutex_;
    
    void RecordAssessment(const DecisionAssessment& assessment);
};

/**
 * CLI for testing safety gate
 */
class SafetyGateCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static void InteractiveMode(SafetyGate& gate);
    static void SimulateDecision(SafetyGate& gate, const std::string& decisionType);
};

} // namespace Autonomy
