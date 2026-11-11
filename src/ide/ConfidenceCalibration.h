/*===========================================================================
 * ConfidenceCalibration.h
 * RawrXD IDE - Runtime Confidence Calibration with Historical Accuracy
 * 
 * The runtime owns the confidence score, not the model.
 * Historical success +8% to base confidence.
 *===========================================================================*/

#ifndef CONFIDENCE_CALIBRATION_H
#define CONFIDENCE_CALIBRATION_H

#include "PatchFingerprint.h"
#include "RepairMemory.h"
#include <vector>
#include <map>
#include <memory>

namespace RawrXD {

/*===========================================================================
 * CONFIDENCE FACTORS
 *===========================================================================*/

enum class ConfidenceFactor {
    ModelPrediction,        // Base confidence from LLM
    HistoricalAccuracy,     // Track record for this crash type
    PatchSimilarity,        // Similarity to past successful patches
    ValidationStage,        // How far through validation pipeline
    ContextQuality,         // Quality of debug context
    CodeComplexity,         // Complexity of code being modified
    TestCoverage,           // Coverage of affected code
    RegressionRisk,         // Risk of introducing regressions
    UserFeedback,           // Historical user ratings
    SystemStability         // Current system stability metrics
};

struct ConfidenceFactorWeight {
    ConfidenceFactor factor;
    float weight;
    float minValue;
    float maxValue;
    std::string description;
};

/*===========================================================================
 * CALIBRATED CONFIDENCE
 *===========================================================================*/

struct CalibratedConfidence {
    float rawModelConfidence;           // What the model reported (0.0-1.0)
    float calibratedConfidence;         // Runtime-adjusted confidence (0.0-1.0)
    
    // Factor breakdown
    float historicalAccuracyBonus;      // +8% for proven patterns
    float similarityBonus;              // Based on patch similarity
    float validationStageBonus;       // Increases as validation progresses
    float contextQualityScore;          // Quality of debug info
    float complexityPenalty;            // Higher complexity = lower confidence
    float coverageBonus;                // Test coverage of affected code
    float regressionRiskPenalty;        // Estimated regression risk
    float userFeedbackAdjustment;       // Historical user ratings
    float stabilityAdjustment;          // Current system stability
    
    // Metadata
    std::string calibrationReason;        // Why confidence was adjusted
    std::vector<std::string> appliedFactors;
    std::vector<std::string> warnings;
    
    uint64_t calibrationTimestamp;
    uint64_t calibrationVersion;
    
    CalibratedConfidence()
        : rawModelConfidence(0.0f)
        , calibratedConfidence(0.0f)
        , historicalAccuracyBonus(0.0f)
        , similarityBonus(0.0f)
        , validationStageBonus(0.0f)
        , contextQualityScore(0.0f)
        , complexityPenalty(0.0f)
        , coverageBonus(0.0f)
        , regressionRiskPenalty(0.0f)
        , userFeedbackAdjustment(0.0f)
        , stabilityAdjustment(0.0f)
        , calibrationTimestamp(0)
        , calibrationVersion(0) {}
    
    // Threshold checks
    bool IsAutoApplyEligible() const { return calibratedConfidence >= 0.85f; }
    bool IsManualReviewRequired() const { return calibratedConfidence >= 0.60f && calibratedConfidence < 0.85f; }
    bool IsRejectRecommended() const { return calibratedConfidence < 0.60f; }
    
    std::string GetRecommendation() const;
    std::string ToJson() const;
};

/*===========================================================================
 * HISTORICAL ACCURACY TRACKER
 *===========================================================================*/

struct CrashTypeAccuracy {
    std::string crashType;              // e.g., "NullPointer", "AccessViolation"
    std::string crashSubtype;           // e.g., "Dereference", "ArrayIndex"
    
    uint32_t totalAttempts;
    uint32_t successfulFixes;
    uint32_t failedFixes;
    uint32_t falsePositives;            // Passed validation, failed later
    
    float accuracyRate;                 // successful / total
    float precisionRate;                // true positives / (true + false positives)
    float recallRate;                   // successful / (successful + missed)
    
    // Time-based trends
    float accuracyTrend7d;              // Trend over last 7 days
    float accuracyTrend30d;             // Trend over last 30 days
    
    // Model-specific accuracy
    std::map<std::string, float> accuracyByModel;
    
    CrashTypeAccuracy()
        : totalAttempts(0)
        , successfulFixes(0)
        , failedFixes(0)
        , falsePositives(0)
        , accuracyRate(0.0f)
        , precisionRate(0.0f)
        , recallRate(0.0f)
        , accuracyTrend7d(0.0f)
        , accuracyTrend30d(0.0f) {}
};

struct PatchTypeAccuracy {
    std::string patchType;              // e.g., "NullCheck", "BoundsCheck", "TypeCast"
    
    uint32_t applications;
    uint32_t successes;
    uint32_t failures;
    
    float successRate;
    float avgTimeToValidate;
    float avgRegressionRisk;
    
    // Context-specific success rates
    std::map<std::string, float> successRateByContext;
    
    PatchTypeAccuracy()
        : applications(0)
        , successes(0)
        , failures(0)
        , successRate(0.0f)
        , avgTimeToValidate(0.0f)
        , avgRegressionRisk(0.0f) {}
};

class HistoricalAccuracyTracker {
public:
    HistoricalAccuracyTracker(RepairMemory* memory);
    
    void RecordOutcome(const std::string& crashType, const std::string& patchType, 
                       bool success, bool wasFalsePositive);
    
    CrashTypeAccuracy GetCrashTypeAccuracy(const std::string& crashType);
    PatchTypeAccuracy GetPatchTypeAccuracy(const std::string& patchType);
    
    float GetAccuracyBonus(const std::string& crashType, const std::string& patchType);
    float CalculateHistoricalSuccessRate(const std::string& crashSignature);
    
    // Trend analysis
    bool IsImproving(const std::string& crashType);
    bool IsDegrading(const std::string& crashType);
    std::vector<std::string> GetUnderperformingCrashTypes(float threshold = 0.5f);
    
    // Calibration recommendations
    std::string GetCalibrationRecommendation(const std::string& crashType);

private:
    RepairMemory* m_memory;
    std::map<std::string, CrashTypeAccuracy> m_crashTypeStats;
    std::map<std::string, PatchTypeAccuracy> m_patchTypeStats;
    
    void UpdateCrashTypeStats(const std::string& crashType, bool success);
    void UpdatePatchTypeStats(const std::string& patchType, bool success);
};

/*===========================================================================
 * CONFIDENCE CALIBRATOR
 *===========================================================================*/

class ConfidenceCalibrator {
public:
    ConfidenceCalibrator(HistoricalAccuracyTracker* tracker, RepairMemory* memory);
    
    // Main calibration entry point
    CalibratedConfidence Calibrate(
        float modelConfidence,
        const PatchFingerprint& patch,
        const std::string& crashSignature,
        const std::string& crashType,
        const std::string& context
    );
    
    // Stage-based calibration (confidence increases as validation progresses)
    CalibratedConfidence CalibrateForStage(
        const CalibratedConfidence& current,
        ValidationStage stage,
        const ValidationResult& result
    );
    
    // Factor-specific calculations
    float CalculateHistoricalFactor(const std::string& crashType, const std::string& patchType);
    float CalculateSimilarityFactor(const PatchFingerprint& patch, const std::string& crashSignature);
    float CalculateContextFactor(const std::string& context);
    float CalculateComplexityFactor(const PatchFingerprint& patch);
    float CalculateCoverageFactor(const std::string& filePath, uint32_t lineNumber);
    float CalculateRegressionRisk(const PatchFingerprint& patch);
    
    // Configuration
    void SetHistoricalWeight(float weight) { m_historicalWeight = weight; }
    void SetSimilarityWeight(float weight) { m_similarityWeight = weight; }
    void SetMinimumConfidence(float min) { m_minimumConfidence = min; }
    void SetMaximumConfidence(float max) { m_maximumConfidence = max; }
    void SetHistoricalBonus(float bonus) { m_historicalBonus = bonus; }
    
    // Default weights
    static constexpr float DEFAULT_HISTORICAL_WEIGHT = 0.25f;
    static constexpr float DEFAULT_SIMILARITY_WEIGHT = 0.20f;
    static constexpr float DEFAULT_CONTEXT_WEIGHT = 0.15f;
    static constexpr float DEFAULT_COMPLEXITY_WEIGHT = 0.10f;
    static constexpr float DEFAULT_COVERAGE_WEIGHT = 0.10f;
    static constexpr float DEFAULT_REGRESSION_WEIGHT = 0.10f;
    static constexpr float DEFAULT_USER_FEEDBACK_WEIGHT = 0.05f;
    static constexpr float DEFAULT_STABILITY_WEIGHT = 0.05f;
    
    // Historical accuracy bonus (as specified: +8%)
    static constexpr float DEFAULT_HISTORICAL_BONUS = 0.08f;

private:
    HistoricalAccuracyTracker* m_tracker;
    RepairMemory* m_memory;
    
    float m_historicalWeight = DEFAULT_HISTORICAL_WEIGHT;
    float m_similarityWeight = DEFAULT_SIMILARITY_WEIGHT;
    float m_contextWeight = DEFAULT_CONTEXT_WEIGHT;
    float m_complexityWeight = DEFAULT_COMPLEXITY_WEIGHT;
    float m_coverageWeight = DEFAULT_COVERAGE_WEIGHT;
    float m_regressionWeight = DEFAULT_REGRESSION_WEIGHT;
    float m_userFeedbackWeight = DEFAULT_USER_FEEDBACK_WEIGHT;
    float m_stabilityWeight = DEFAULT_STABILITY_WEIGHT;
    
    float m_historicalBonus = DEFAULT_HISTORICAL_BONUS;
    float m_minimumConfidence = 0.0f;
    float m_maximumConfidence = 1.0f;
    
    uint64_t m_calibrationVersion = 1;
    
    float ClampConfidence(float value);
    std::string GenerateCalibrationReason(const CalibratedConfidence& cc);
};

/*===========================================================================
 * CONFIDENCE THRESHOLDS
 *===========================================================================*/

struct ConfidenceThresholds {
    float autoApplyThreshold = 0.85f;       // Apply without user interaction
    float notifyThreshold = 0.70f;          // Notify user but don't block
    float suggestThreshold = 0.60f;         // Suggest but require approval
    float rejectThreshold = 0.40f;          // Reject, try alternative
    float abortThreshold = 0.20f;           // Abort, escalate to human
    
    // Dynamic thresholds based on system state
    float stabilityMultiplier = 1.0f;       // Adjust based on system stability
    float urgencyMultiplier = 1.0f;         // Adjust based on crash severity
    
    float GetEffectiveThreshold(float base) const {
        return base * stabilityMultiplier * urgencyMultiplier;
    }
};

class ConfidenceThresholdManager {
public:
    ConfidenceThresholdManager();
    
    // Threshold queries
    bool ShouldAutoApply(float confidence) const;
    bool ShouldNotify(float confidence) const;
    bool ShouldSuggest(float confidence) const;
    bool ShouldReject(float confidence) const;
    bool ShouldAbort(float confidence) const;
    
    // Dynamic adjustment
    void AdjustForStability(float stabilityScore);
    void AdjustForUrgency(CrashSeverity severity);
    void AdjustForTimeOfDay(int hour);  // Lower thresholds during off-hours
    void ResetToDefaults();
    
    // Custom thresholds per crash type
    void SetThresholdsForCrashType(const std::string& crashType, const ConfidenceThresholds& thresholds);
    ConfidenceThresholds GetThresholdsForCrashType(const std::string& crashType) const;

private:
    ConfidenceThresholds m_defaultThresholds;
    std::map<std::string, ConfidenceThresholds> m_customThresholds;
};

/*===========================================================================
 * CONFIDENCE REPORTING
 *===========================================================================*/

struct ConfidenceReport {
    uint64_t reportId;
    uint64_t timestamp;
    
    // Summary
    uint32_t totalCalibrations;
    uint32_t autoApplied;
    uint32_t manuallyApproved;
    uint32_t rejected;
    uint32_t aborted;
    
    // Accuracy metrics
    float calibrationAccuracy;          // How often calibrated confidence was correct
    float modelAccuracy;                  // How often raw model confidence was correct
    float calibrationImprovement;       // calibrationAccuracy - modelAccuracy
    
    // Factor effectiveness
    std::map<ConfidenceFactor, float> factorEffectiveness;
    
    // Recommendations
    std::vector<std::string> calibrationRecommendations;
};

class ConfidenceReporter {
public:
    ConfidenceReporter(ConfidenceCalibrator* calibrator);
    
    void RecordCalibration(const CalibratedConfidence& cc, bool actualSuccess);
    void RecordDecision(uint64_t patchId, const std::string& decision);
    
    ConfidenceReport GenerateReport(uint64_t sinceTimestamp = 0);
    void ExportReport(const std::string& path);
    
    // Analysis
    std::vector<std::string> GetOverconfidentPatterns();
    std::vector<std::string> GetUnderconfidentPatterns();
    std::map<ConfidenceFactor, float> GetFactorWeightsRecommendation();

private:
    ConfidenceCalibrator* m_calibrator;
    std::vector<CalibratedConfidence> m_calibrationHistory;
    std::map<uint64_t, std::string> m_decisions;
};

/*===========================================================================
 * CONFIDENCE CALIBRATION UI
 *===========================================================================*/

namespace ConfidenceCalibrationUI {
    std::string FormatCalibratedConfidence(const CalibratedConfidence& cc);
    std::string FormatConfidenceFactors(const CalibratedConfidence& cc);
    std::string GenerateConfidenceGauge(float confidence);
    std::string GenerateFactorBreakdownChart(const CalibratedConfidence& cc);
    std::string GenerateHtmlReport(const ConfidenceReport& report);
}

} // namespace RawrXD

#endif // CONFIDENCE_CALIBRATION_H
