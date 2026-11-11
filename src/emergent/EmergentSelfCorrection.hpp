#pragma once

/**
 * EmergentSelfCorrection.hpp
 *
 * Phase C.2 Batch 4/5: Emergent Self-Correction
 *
 * The runtime detects instability, adjusts topology,
 * modifies scheduling, and rebalances harmonics.
 */

#include <vector>
#include <map>
#include <memory>
#include <string>
#include <functional>

namespace Emergent {

/**
 * Correction types the system can apply
 */
enum class CorrectionType {
    TOPOLOGY_ADJUSTMENT,    // Modify execution graph topology
    SCHEDULING_MODIFICATION, // Change task scheduling
    HARMONIC_REBALANCE,     // Rebalance harmonic weights
    RESOURCE_REALLOCATION,  // Move resources between components
    PATTERN_SUPPRESSION,    // Suppress problematic patterns
    PATTERN_AMPLIFICATION   // Amplify beneficial patterns
};

/**
 * Detected instability
 */
struct Instability {
    std::string instabilityId;
    std::string description;
    double severity;        // 0-1
    std::string source;     // Component where detected
    std::map<std::string, double> metrics;
    int64_t detectedAtMs;
    bool isResolved;
};

/**
 * Correction action taken
 */
struct CorrectionAction {
    std::string actionId;
    CorrectionType type;
    std::string name;
    std::string description;
    
    // Target
    std::string targetComponent;
    std::map<std::string, double> parameterAdjustments;
    
    // Effectiveness
    double expectedImprovement;
    double actualImprovement;  // Updated after application
    bool wasEffective;
    
    // Temporal
    int64_t appliedAtMs;
    int64_t evaluatedAtMs;
    
    std::string ToJson() const;
};

/**
 * System health snapshot
 */
struct HealthSnapshot {
    int64_t timestampMs;
    double overallHealth;   // 0-1
    
    // Component healths
    std::map<std::string, double> componentHealths;
    
    // Stability metrics
    double convergenceStability;
    double performanceStability;
    double resourceStability;
    
    // Active issues
    std::vector<std::string> activeInstabilities;
    int activeCorrectionCount;
};

/**
 * Self-correction configuration
 */
struct SelfCorrectionConfig {
    // Detection thresholds
    double instabilityThreshold = 0.3;  // Below this is unstable
    double correctionThreshold = 0.5;   // Apply correction below this
    
    // Correction limits
    int maxConcurrentCorrections = 3;
    int64_t minCorrectionIntervalMs = 5000;  // 5 seconds
    double maxAdjustmentMagnitude = 0.3;     // Max parameter change
    
    // Evaluation
    int64_t evaluationWindowMs = 30000;    // 30 seconds to evaluate
    double effectivenessThreshold = 0.7;   // Correction must achieve this
    
    // Learning
    bool enableLearning = true;
    double learningRate = 0.1;
};

/**
 * Self-correction result
 */
struct SelfCorrectionResult {
    std::vector<Instability> detectedInstabilities;
    std::vector<CorrectionAction> appliedCorrections;
    HealthSnapshot healthBefore;
    HealthSnapshot healthAfter;
    
    int64_t correctionDurationMs;
    double overallImprovement;
    
    std::string ToJson() const;
    void PrintSummary() const;
};

/**
 * Correction strategy
 */
struct CorrectionStrategy {
    CorrectionType type;
    std::string targetComponent;
    std::map<std::string, double> parameterAdjustments;
    double expectedImprovement;
    int priority;
};

/**
 * Emergent Self-Correction
 *
 * Detects and corrects system instabilities
 */
class EmergentSelfCorrection {
public:
    EmergentSelfCorrection();
    ~EmergentSelfCorrection();
    
    // Initialize
    bool Initialize(const SelfCorrectionConfig& config = SelfCorrectionConfig{});
    
    // Update with current health
    void UpdateHealth(const HealthSnapshot& snapshot);
    
    // Run self-correction cycle
    SelfCorrectionResult Correct();
    
    // Specific correction functions
    std::vector<Instability> DetectInstabilities(const HealthSnapshot& snapshot);
    std::vector<CorrectionStrategy> PlanCorrections(const std::vector<Instability>& instabilities);
    CorrectionAction ApplyCorrection(const CorrectionStrategy& strategy);
    bool EvaluateCorrection(CorrectionAction& action, const HealthSnapshot& before, const HealthSnapshot& after);
    
    // Get current state
    const std::vector<Instability>& GetActiveInstabilities() const { return activeInstabilities_; }
    const std::vector<CorrectionAction>& GetCorrectionHistory() const { return correctionHistory_; }
    
    // Manual correction
    void ForceCorrection(CorrectionType type, const std::string& target);
    void RevertCorrection(const std::string& actionId);
    
    // Export/Import
    bool SaveCorrectionHistory(const std::string& path) const;
    bool LoadCorrectionHistory(const std::string& path);
    
private:
    SelfCorrectionConfig config_;
    std::vector<HealthSnapshot> healthHistory_;
    std::vector<Instability> activeInstabilities_;
    std::vector<CorrectionAction> correctionHistory_;
    int64_t lastCorrectionTime_;
    
    // Learning data
    std::map<CorrectionType, double> strategySuccessRates_;
    std::map<std::string, std::map<std::string, double>> effectiveAdjustments_;
    
    // Helper methods
    double CalculateInstabilitySeverity(const HealthSnapshot& snapshot, const std::string& component);
    CorrectionStrategy SelectBestStrategy(const std::vector<CorrectionStrategy>& strategies);
    bool CanApplyCorrection() const;
    void LearnFromCorrection(const CorrectionAction& action);
    std::string GenerateInstabilityId() const;
    std::string GenerateActionId() const;
};

/**
 * Self-correction CLI
 */
class EmergentSelfCorrectionCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintBanner();
    static void PrintUsage();
    static SelfCorrectionConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Emergent
