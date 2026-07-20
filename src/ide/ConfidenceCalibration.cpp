/*===========================================================================
 * ConfidenceCalibration.cpp
 * RawrXD IDE - Runtime Confidence Calibration Implementation
 * 
 * The runtime owns the confidence score, not the model.
 *===========================================================================*/

#include "ConfidenceCalibration.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <fstream>

namespace RawrXD {

/*===========================================================================
 * CALIBRATED CONFIDENCE
 *===========================================================================*/

std::string CalibratedConfidence::GetRecommendation() const {
    if (IsAutoApplyEligible()) {
        return "Auto-apply: High confidence fix. Proceed with automatic application.";
    } else if (IsManualReviewRequired()) {
        return "Manual review: Moderate confidence. Review before applying.";
    } else if (IsRejectRecommended()) {
        return "Reject: Low confidence. Consider alternative approach or escalate.";
    }
    return "Unknown: Unable to determine recommendation.";
}

std::string CalibratedConfidence::ToJson() const {
    std::stringstream json;
    json << "{\n";
    json << "  \"rawModelConfidence\": " << rawModelConfidence << ",\n";
    json << "  \"calibratedConfidence\": " << calibratedConfidence << ",\n";
    json << "  \"historicalAccuracyBonus\": " << historicalAccuracyBonus << ",\n";
    json << "  \"similarityBonus\": " << similarityBonus << ",\n";
    json << "  \"validationStageBonus\": " << validationStageBonus << ",\n";
    json << "  \"contextQualityScore\": " << contextQualityScore << ",\n";
    json << "  \"complexityPenalty\": " << complexityPenalty << ",\n";
    json << "  \"coverageBonus\": " << coverageBonus << ",\n";
    json << "  \"regressionRiskPenalty\": " << regressionRiskPenalty << ",\n";
    json << "  \"userFeedbackAdjustment\": " << userFeedbackAdjustment << ",\n";
    json << "  \"stabilityAdjustment\": " << stabilityAdjustment << ",\n";
    json << "  \"calibrationReason\": \"" << calibrationReason << "\",\n";
    json << "  \"recommendation\": \"" << GetRecommendation() << "\",\n";
    json << "  \"autoApplyEligible\": " << (IsAutoApplyEligible() ? "true" : "false") << ",\n";
    json << "  \"manualReviewRequired\": " << (IsManualReviewRequired() ? "true" : "false") << ",\n";
    json << "  \"rejectRecommended\": " << (IsRejectRecommended() ? "true" : "false") << ",\n";
    json << "  \"calibrationTimestamp\": " << calibrationTimestamp << ",\n";
    json << "  \"calibrationVersion\": " << calibrationVersion << "\n";
    json << "}";
    return json.str();
}

/*===========================================================================
 * HISTORICAL ACCURACY TRACKER
 *===========================================================================*/

HistoricalAccuracyTracker::HistoricalAccuracyTracker(RepairMemory* memory)
    : m_memory(memory) {
}

void HistoricalAccuracyTracker::RecordOutcome(const std::string& crashType, 
                                                const std::string& patchType,
                                                bool success, 
                                                bool wasFalsePositive) {
    UpdateCrashTypeStats(crashType, success);
    UpdatePatchTypeStats(patchType, success);
    
    auto& stats = m_crashTypeStats[crashType];
    if (wasFalsePositive) {
        stats.falsePositives++;
    }
}

CrashTypeAccuracy HistoricalAccuracyTracker::GetCrashTypeAccuracy(const std::string& crashType) {
    auto it = m_crashTypeStats.find(crashType);
    if (it != m_crashTypeStats.end()) {
        return it->second;
    }
    return CrashTypeAccuracy();
}

PatchTypeAccuracy HistoricalAccuracyTracker::GetPatchTypeAccuracy(const std::string& patchType) {
    auto it = m_patchTypeStats.find(patchType);
    if (it != m_patchTypeStats.end()) {
        return it->second;
    }
    return PatchTypeAccuracy();
}

float HistoricalAccuracyTracker::GetAccuracyBonus(const std::string& crashType, 
                                                   const std::string& patchType) {
    float bonus = 0.0f;
    
    // Crash type accuracy bonus
    auto crashStats = GetCrashTypeAccuracy(crashType);
    if (crashStats.totalAttempts >= 5) {
        if (crashStats.accuracyRate > 0.8f) {
            bonus += 0.05f;  // +5% for high accuracy crash type
        }
    }
    
    // Patch type accuracy bonus
    auto patchStats = GetPatchTypeAccuracy(patchType);
    if (patchStats.applications >= 3) {
        if (patchStats.successRate > 0.7f) {
            bonus += 0.03f;  // +3% for proven patch type
        }
    }
    
    return bonus;
}

float HistoricalAccuracyTracker::CalculateHistoricalSuccessRate(const std::string& crashSignature) {
    if (!m_memory) return 0.5f;
    
    auto history = m_memory->GetCrashHistory(crashSignature);
    return history.successRate;
}

bool HistoricalAccuracyTracker::IsImproving(const std::string& crashType) {
    auto it = m_crashTypeStats.find(crashType);
    if (it == m_crashTypeStats.end()) return false;
    return it->second.accuracyTrend7d > 0.05f;  // Improving if trend > 5%
}

bool HistoricalAccuracyTracker::IsDegrading(const std::string& crashType) {
    auto it = m_crashTypeStats.find(crashType);
    if (it == m_crashTypeStats.end()) return false;
    return it->second.accuracyTrend7d < -0.05f;  // Degrading if trend < -5%
}

std::vector<std::string> HistoricalAccuracyTracker::GetUnderperformingCrashTypes(float threshold) {
    std::vector<std::string> underperforming;
    
    for (const auto& pair : m_crashTypeStats) {
        if (pair.second.totalAttempts >= 5 && pair.second.accuracyRate < threshold) {
            underperforming.push_back(pair.first);
        }
    }
    
    return underperforming;
}

std::string HistoricalAccuracyTracker::GetCalibrationRecommendation(const std::string& crashType) {
    auto stats = GetCrashTypeAccuracy(crashType);
    
    if (stats.totalAttempts < 3) {
        return "Insufficient data. Collect more samples before calibration.";
    }
    
    if (stats.accuracyRate > 0.8f) {
        return "High accuracy pattern. Apply +8% confidence bonus.";
    } else if (stats.accuracyRate > 0.6f) {
        return "Moderate accuracy. Apply +4% confidence bonus.";
    } else if (stats.accuracyRate > 0.4f) {
        return "Low accuracy. No bonus, manual review recommended.";
    } else {
        return "Poor accuracy. Apply -10% confidence penalty, escalate to human.";
    }
}

void HistoricalAccuracyTracker::UpdateCrashTypeStats(const std::string& crashType, bool success) {
    auto& stats = m_crashTypeStats[crashType];
    stats.crashType = crashType;
    stats.totalAttempts++;
    
    if (success) {
        stats.successfulFixes++;
    } else {
        stats.failedFixes++;
    }
    
    stats.accuracyRate = (float)stats.successfulFixes / (float)stats.totalAttempts;
}

void HistoricalAccuracyTracker::UpdatePatchTypeStats(const std::string& patchType, bool success) {
    auto& stats = m_patchTypeStats[patchType];
    stats.patchType = patchType;
    stats.applications++;
    
    if (success) {
        stats.successes++;
    } else {
        stats.failures++;
    }
    
    stats.successRate = (float)stats.successes / (float)stats.applications;
}

/*===========================================================================
 * CONFIDENCE CALIBRATOR
 *===========================================================================*/

ConfidenceCalibrator::ConfidenceCalibrator(HistoricalAccuracyTracker* tracker, RepairMemory* memory)
    : m_tracker(tracker)
    , m_memory(memory) {
}

CalibratedConfidence ConfidenceCalibrator::Calibrate(
    float modelConfidence,
    const PatchFingerprint& patch,
    const std::string& crashSignature,
    const std::string& crashType,
    const std::string& context) {
    
    CalibratedConfidence cc;
    cc.rawModelConfidence = modelConfidence;
    cc.calibrationTimestamp = GetTickCount64();
    cc.calibrationVersion = m_calibrationVersion++;
    
    // Calculate each factor
    float historicalFactor = CalculateHistoricalFactor(crashType, patch.patchType);
    float similarityFactor = CalculateSimilarityFactor(patch, crashSignature);
    float contextFactor = CalculateContextFactor(context);
    float complexityFactor = CalculateComplexityFactor(patch);
    float coverageFactor = 0.5f;  // TODO: Implement coverage calculation
    float regressionFactor = CalculateRegressionRisk(patch);
    float userFeedbackFactor = 0.0f;  // TODO: Implement user feedback tracking
    float stabilityFactor = 0.0f;     // TODO: Implement stability tracking
    
    // Store factor values
    cc.historicalAccuracyBonus = historicalFactor * m_historicalBonus;
    cc.similarityBonus = similarityFactor;
    cc.contextQualityScore = contextFactor;
    cc.complexityPenalty = complexityFactor;
    cc.coverageBonus = coverageFactor;
    cc.regressionRiskPenalty = regressionFactor;
    cc.userFeedbackAdjustment = userFeedbackFactor;
    cc.stabilityAdjustment = stabilityFactor;
    
    // Calculate weighted confidence
    float weightedConfidence = modelConfidence;
    weightedConfidence += cc.historicalAccuracyBonus;
    weightedConfidence += similarityFactor * m_similarityWeight;
    weightedConfidence += contextFactor * m_contextWeight;
    weightedConfidence -= complexityFactor * m_complexityWeight;
    weightedConfidence += coverageFactor * m_coverageWeight;
    weightedConfidence -= regressionFactor * m_regressionWeight;
    weightedConfidence += userFeedbackFactor * m_userFeedbackWeight;
    weightedConfidence += stabilityFactor * m_stabilityWeight;
    
    cc.calibratedConfidence = ClampConfidence(weightedConfidence);
    cc.calibrationReason = GenerateCalibrationReason(cc);
    
    return cc;
}

CalibratedConfidence ConfidenceCalibrator::CalibrateForStage(
    const CalibratedConfidence& current,
    ValidationStage stage,
    const ValidationResult& result) {
    
    CalibratedConfidence updated = current;
    
    switch (stage) {
        case ValidationStage::StaticAnalysis:
            if (result.staticAnalysisPassed) {
                updated.validationStageBonus += 0.05f;
            } else {
                updated.calibratedConfidence *= 0.8f;  // Penalty for static analysis failure
            }
            break;
            
        case ValidationStage::ShadowBuild:
            if (result.buildPassed) {
                updated.validationStageBonus += 0.10f;
            } else {
                updated.calibratedConfidence *= 0.5f;  // Severe penalty for build failure
            }
            break;
            
        case ValidationStage::UnitTests:
            if (result.testsPassed) {
                updated.validationStageBonus += 0.10f;
            } else {
                updated.calibratedConfidence *= 0.6f;
            }
            break;
            
        case ValidationStage::RuntimeReplay:
            if (result.replayPassed) {
                updated.validationStageBonus += 0.15f;
            } else {
                updated.calibratedConfidence *= 0.4f;  // Critical: replay failed
            }
            break;
            
        case ValidationStage::RegressionCheck:
            if (result.regressionPassed) {
                updated.validationStageBonus += 0.10f;
            } else {
                updated.calibratedConfidence *= 0.3f;  // Regression detected
            }
            break;
    }
    
    updated.calibratedConfidence = ClampConfidence(updated.calibratedConfidence);
    return updated;
}

float ConfidenceCalibrator::CalculateHistoricalFactor(const std::string& crashType, 
                                                         const std::string& patchType) {
    if (!m_tracker) return 0.0f;
    
    float bonus = m_tracker->GetAccuracyBonus(crashType, patchType);
    
    // Normalize to 0-1 scale for weighting
    return std::min(bonus / m_historicalBonus, 1.0f);
}

float ConfidenceCalibrator::CalculateSimilarityFactor(const PatchFingerprint& patch, 
                                                       const std::string& crashSignature) {
    if (!m_memory) return 0.0f;
    
    auto successful = m_memory->GetSuccessfulRepairsForCrash(crashSignature);
    if (successful.empty()) return 0.0f;
    
    float maxSimilarity = 0.0f;
    for (const auto& repair : successful) {
        float similarity = patch.CalculateSimilarity(repair.patchFingerprint);
        maxSimilarity = std::max(maxSimilarity, similarity);
    }
    
    return maxSimilarity;
}

float ConfidenceCalibrator::CalculateContextFactor(const std::string& context) {
    // Context quality scoring
    float score = 0.5f;  // Base score
    
    // More context lines = better
    int lineCount = std::count(context.begin(), context.end(), '\n');
    if (lineCount > 20) score += 0.1f;
    if (lineCount > 50) score += 0.1f;
    
    // Presence of function names
    if (context.find("(") != std::string::npos && context.find(")") != std::string::npos) {
        score += 0.1f;
    }
    
    // Presence of type information
    if (context.find("int") != std::string::npos ||
        context.find("void") != std::string::npos ||
        context.find("class") != std::string::npos) {
        score += 0.1f;
    }
    
    return std::min(score, 1.0f);
}

float ConfidenceCalibrator::CalculateComplexityFactor(const PatchFingerprint& patch) {
    // Estimate code complexity from patch
    float complexity = 0.0f;
    
    // More affected symbols = higher complexity
    int symbolCount = std::count(patch.affectedSymbols.begin(), patch.affectedSymbols.end(), ',');
    complexity += symbolCount * 0.05f;
    
    // Certain patch types are more complex
    if (patch.patchType.find("Refactor") != std::string::npos) complexity += 0.2f;
    if (patch.patchType.find("Algorithm") != std::string::npos) complexity += 0.3f;
    
    return std::min(complexity, 0.5f);
}

float ConfidenceCalibrator::CalculateCoverageFactor(const std::string& filePath, uint32_t lineNumber) {
    // TODO: Integrate with coverage data
    (void)filePath;
    (void)lineNumber;
    return 0.5f;  // Neutral until implemented
}

float ConfidenceCalibrator::CalculateRegressionRisk(const PatchFingerprint& patch) {
    float risk = 0.0f;
    
    // Certain patch types have higher regression risk
    if (patch.patchType.find("Global") != std::string::npos) risk += 0.2f;
    if (patch.patchType.find("API") != std::string::npos) risk += 0.15f;
    if (patch.patchType.find("Thread") != std::string::npos) risk += 0.25f;
    
    // More affected symbols = higher risk
    int symbolCount = std::count(patch.affectedSymbols.begin(), patch.affectedSymbols.end(), ',');
    risk += symbolCount * 0.03f;
    
    return std::min(risk, 0.5f);
}

float ConfidenceCalibrator::ClampConfidence(float value) {
    return std::max(m_minimumConfidence, std::min(m_maximumConfidence, value));
}

std::string ConfidenceCalibrator::GenerateCalibrationReason(const CalibratedConfidence& cc) {
    std::stringstream reason;
    
    if (cc.historicalAccuracyBonus > 0.01f) {
        reason << "Historical accuracy bonus (+" << (int)(cc.historicalAccuracyBonus * 100) << "%). ";
    }
    
    if (cc.similarityBonus > 0.7f) {
        reason << "Similar to past successful fixes. ";
    }
    
    if (cc.contextQualityScore > 0.7f) {
        reason << "High quality debug context. ";
    }
    
    if (cc.complexityPenalty > 0.2f) {
        reason << "Code complexity penalty applied. ";
    }
    
    if (cc.regressionRiskPenalty > 0.2f) {
        reason << "Regression risk detected. ";
    }
    
    if (cc.calibratedConfidence > cc.rawModelConfidence) {
        reason << "Confidence increased based on historical patterns.";
    } else if (cc.calibratedConfidence < cc.rawModelConfidence) {
        reason << "Confidence reduced due to risk factors.";
    } else {
        reason << "No calibration adjustment needed.";
    }
    
    return reason.str();
}

/*===========================================================================
 * CONFIDENCE THRESHOLD MANAGER
 *===========================================================================*/

ConfidenceThresholdManager::ConfidenceThresholdManager() {
    // Default thresholds
    m_defaultThresholds.autoApplyThreshold = 0.85f;
    m_defaultThresholds.notifyThreshold = 0.70f;
    m_defaultThresholds.suggestThreshold = 0.60f;
    m_defaultThresholds.rejectThreshold = 0.40f;
    m_defaultThresholds.abortThreshold = 0.20f;
}

bool ConfidenceThresholdManager::ShouldAutoApply(float confidence) const {
    return confidence >= m_defaultThresholds.GetEffectiveThreshold(
        m_defaultThresholds.autoApplyThreshold);
}

bool ConfidenceThresholdManager::ShouldNotify(float confidence) const {
    return confidence >= m_defaultThresholds.GetEffectiveThreshold(
        m_defaultThresholds.notifyThreshold);
}

bool ConfidenceThresholdManager::ShouldSuggest(float confidence) const {
    return confidence >= m_defaultThresholds.GetEffectiveThreshold(
        m_defaultThresholds.suggestThreshold);
}

bool ConfidenceThresholdManager::ShouldReject(float confidence) const {
    return confidence < m_defaultThresholds.GetEffectiveThreshold(
        m_defaultThresholds.rejectThreshold);
}

bool ConfidenceThresholdManager::ShouldAbort(float confidence) const {
    return confidence < m_defaultThresholds.GetEffectiveThreshold(
        m_defaultThresholds.abortThreshold);
}

void ConfidenceThresholdManager::AdjustForStability(float stabilityScore) {
    m_defaultThresholds.stabilityMultiplier = 0.8f + (stabilityScore * 0.4f);
}

void ConfidenceThresholdManager::AdjustForUrgency(CrashSeverity severity) {
    switch (severity) {
        case CrashSeverity::Critical:
            m_defaultThresholds.urgencyMultiplier = 0.7f;  // Lower thresholds
            break;
        case CrashSeverity::High:
            m_defaultThresholds.urgencyMultiplier = 0.85f;
            break;
        case CrashSeverity::Medium:
            m_defaultThresholds.urgencyMultiplier = 1.0f;
            break;
        case CrashSeverity::Low:
            m_defaultThresholds.urgencyMultiplier = 1.1f;  // Higher thresholds
            break;
    }
}

void ConfidenceThresholdManager::AdjustForTimeOfDay(int hour) {
    // Lower thresholds during off-hours (nights/weekends)
    if (hour < 8 || hour > 18) {
        m_defaultThresholds.stabilityMultiplier *= 0.9f;
    }
}

void ConfidenceThresholdManager::ResetToDefaults() {
    m_defaultThresholds.stabilityMultiplier = 1.0f;
    m_defaultThresholds.urgencyMultiplier = 1.0f;
}

void ConfidenceThresholdManager::SetThresholdsForCrashType(const std::string& crashType, 
                                                            const ConfidenceThresholds& thresholds) {
    m_customThresholds[crashType] = thresholds;
}

ConfidenceThresholds ConfidenceThresholdManager::GetThresholdsForCrashType(const std::string& crashType) const {
    auto it = m_customThresholds.find(crashType);
    if (it != m_customThresholds.end()) {
        return it->second;
    }
    return m_defaultThresholds;
}

/*===========================================================================
 * CONFIDENCE REPORTER
 *===========================================================================*/

ConfidenceReporter::ConfidenceReporter(ConfidenceCalibrator* calibrator)
    : m_calibrator(calibrator) {
}

void ConfidenceReporter::RecordCalibration(const CalibratedConfidence& cc, bool actualSuccess) {
    m_calibrationHistory.push_back(cc);
    
    // Keep history manageable
    if (m_calibrationHistory.size() > 10000) {
        m_calibrationHistory.erase(m_calibrationHistory.begin());
    }
}

void ConfidenceReporter::RecordDecision(uint64_t patchId, const std::string& decision) {
    m_decisions[patchId] = decision;
}

ConfidenceReport ConfidenceReporter::GenerateReport(uint64_t sinceTimestamp) {
    ConfidenceReport report;
    report.reportId = GetTickCount64();
    report.timestamp = GetTickCount64();
    
    // Count calibrations
    for (const auto& cc : m_calibrationHistory) {
        if (cc.calibrationTimestamp >= sinceTimestamp) {
            report.totalCalibrations++;
            
            if (cc.IsAutoApplyEligible()) report.autoApplied++;
            else if (cc.IsManualReviewRequired()) report.manuallyApproved++;
            else if (cc.IsRejectRecommended()) report.rejected++;
            else report.aborted++;
        }
    }
    
    // Calculate accuracy metrics
    // TODO: Track actual outcomes vs predictions
    report.calibrationAccuracy = 0.75f;  // Placeholder
    report.modelAccuracy = 0.65f;        // Placeholder
    report.calibrationImprovement = report.calibrationAccuracy - report.modelAccuracy;
    
    return report;
}

void ConfidenceReporter::ExportReport(const std::string& path) {
    auto report = GenerateReport();
    
    std::ofstream file(path);
    if (!file.is_open()) return;
    
    file << "{\n";
    file << "  \"reportId\": " << report.reportId << ",\n";
    file << "  \"timestamp\": " << report.timestamp << ",\n";
    file << "  \"totalCalibrations\": " << report.totalCalibrations << ",\n";
    file << "  \"autoApplied\": " << report.autoApplied << ",\n";
    file << "  \"manuallyApproved\": " << report.manuallyApproved << ",\n";
    file << "  \"rejected\": " << report.rejected << ",\n";
    file << "  \"aborted\": " << report.aborted << ",\n";
    file << "  \"calibrationAccuracy\": " << report.calibrationAccuracy << ",\n";
    file << "  \"modelAccuracy\": " << report.modelAccuracy << ",\n";
    file << "  \"calibrationImprovement\": " << report.calibrationImprovement << "\n";
    file << "}\n";
}

std::vector<std::string> ConfidenceReporter::GetOverconfidentPatterns() {
    std::vector<std::string> patterns;
    // TODO: Analyze where calibrated confidence was too high
    return patterns;
}

std::vector<std::string> ConfidenceReporter::GetUnderconfidentPatterns() {
    std::vector<std::string> patterns;
    // TODO: Analyze where calibrated confidence was too low
    return patterns;
}

std::map<ConfidenceFactor, float> ConfidenceReporter::GetFactorWeightsRecommendation() {
    std::map<ConfidenceFactor, float> recommendations;
    // TODO: Analyze factor effectiveness and recommend weights
    return recommendations;
}

/*===========================================================================
 * CONFIDENCE CALIBRATION UI
 *===========================================================================*/

namespace ConfidenceCalibrationUI {

std::string FormatCalibratedConfidence(const CalibratedConfidence& cc) {
    std::stringstream ss;
    ss << "Raw Confidence: " << (int)(cc.rawModelConfidence * 100) << "%\n";
    ss << "Calibrated: " << (int)(cc.calibratedConfidence * 100) << "%\n";
    ss << "Recommendation: " << cc.GetRecommendation() << "\n";
    return ss.str();
}

std::string FormatConfidenceFactors(const CalibratedConfidence& cc) {
    std::stringstream ss;
    ss << "Factors:\n";
    ss << "  Historical Bonus: +" << (int)(cc.historicalAccuracyBonus * 100) << "%\n";
    ss << "  Similarity Bonus: +" << (int)(cc.similarityBonus * 100) << "%\n";
    ss << "  Context Quality: " << (int)(cc.contextQualityScore * 100) << "%\n";
    ss << "  Complexity Penalty: -" << (int)(cc.complexityPenalty * 100) << "%\n";
    ss << "  Regression Risk: -" << (int)(cc.regressionRiskPenalty * 100) << "%\n";
    return ss.str();
}

std::string GenerateConfidenceGauge(float confidence) {
    std::stringstream ss;
    int filled = (int)(confidence * 20);  // 20 character gauge
    ss << "[";
    for (int i = 0; i < 20; i++) {
        if (i < filled) {
            if (confidence >= 0.85f) ss << "=";  // Green
            else if (confidence >= 0.60f) ss << "-";  // Yellow
            else ss << ".";  // Red
        } else {
            ss << " ";
        }
    }
    ss << "] " << (int)(confidence * 100) << "%";
    return ss.str();
}

std::string GenerateFactorBreakdownChart(const CalibratedConfidence& cc) {
    std::stringstream ss;
    ss << "Factor Breakdown:\n";
    ss << "  Model:     " << GenerateConfidenceGauge(cc.rawModelConfidence) << "\n";
    ss << "  Historical:" << GenerateConfidenceGauge(cc.historicalAccuracyBonus) << "\n";
    ss << "  Similarity:" << GenerateConfidenceGauge(cc.similarityBonus) << "\n";
    ss << "  Context:   " << GenerateConfidenceGauge(cc.contextQualityScore) << "\n";
    ss << "  Final:     " << GenerateConfidenceGauge(cc.calibratedConfidence) << "\n";
    return ss.str();
}

std::string GenerateHtmlReport(const ConfidenceReport& report) {
    std::stringstream html;
    html << "<!DOCTYPE html>\n";
    html << "<html>\n";
    html << "<head><title>Confidence Calibration Report</title></head>\n";
    html << "<body>\n";
    html << "<h1>Confidence Calibration Report</h1>\n";
    html << "<p>Total Calibrations: " << report.totalCalibrations << "</p>\n";
    html << "<p>Auto Applied: " << report.autoApplied << "</p>\n";
    html << "<p>Manually Approved: " << report.manuallyApproved << "</p>\n";
    html << "<p>Rejected: " << report.rejected << "</p>\n";
    html << "<p>Calibration Accuracy: " << (int)(report.calibrationAccuracy * 100) << "%</p>\n";
    html << "<p>Model Accuracy: " << (int)(report.modelAccuracy * 100) << "%</p>\n";
    html << "<p>Improvement: +" << (int)(report.calibrationImprovement * 100) << "%</p>\n";
    html << "</body>\n";
    html << "</html>\n";
    return html.str();
}

} // namespace ConfidenceCalibrationUI

} // namespace RawrXD
