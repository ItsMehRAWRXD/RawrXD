#pragma once

#include "hotpatch_intervention.hpp"
#include <vector>
#include <map>

namespace rawrxd {
namespace benchmarks {

/**
 * Phase E.1 Batch 4/5: Statistical Analysis
 * 
 * Computes rigorous statistical comparisons between baseline and hotpatched
 * performance using the confidence interval framework.
 */

// Statistical test result
struct StatisticalTestResult {
    std::string test_name;
    double test_statistic;
    double p_value;
    bool significant;
    double effect_size;
    std::string interpretation;
};

// Comprehensive comparison between baseline and hotpatched
struct HotpatchComparison {
    // Model info
    std::string model_name;
    std::string patch_type;
    int sample_size_baseline;
    int sample_size_hotpatched;
    
    // Prompt TPS comparison
    double baseline_prompt_tps_mean;
    double hotpatched_prompt_tps_mean;
    double prompt_tps_delta;
    double prompt_tps_delta_percent;
    ConfidenceInterval prompt_tps_baseline_ci;
    ConfidenceInterval prompt_tps_hotpatched_ci;
    double prompt_tps_effect_size;
    bool prompt_tps_significant;
    StatisticalTestResult prompt_tps_test;
    
    // Generation TPS comparison
    double baseline_generation_tps_mean;
    double hotpatched_generation_tps_mean;
    double generation_tps_delta;
    double generation_tps_delta_percent;
    ConfidenceInterval generation_tps_baseline_ci;
    ConfidenceInterval generation_tps_hotpatched_ci;
    double generation_tps_effect_size;
    bool generation_tps_significant;
    StatisticalTestResult generation_tps_test;
    
    // Latency comparison
    double baseline_latency_mean;
    double hotpatched_latency_mean;
    double latency_delta;
    double latency_delta_percent;
    ConfidenceInterval latency_baseline_ci;
    ConfidenceInterval latency_hotpatched_ci;
    double latency_effect_size;
    bool latency_significant;
    StatisticalTestResult latency_test;
    
    // Overall verdict
    std::string overall_verdict;  // "SIGNIFICANT_IMPROVEMENT", "NO_CHANGE", "REGRESSION"
    double overall_improvement_percent;
    int significant_metrics_count;
    int total_metrics_count;
    double average_effect_size;
    
    // Significance markers
    std::string significance_marker;  // "***", "**", "*", "ns"
};

// Aggregated results across multiple models/patches
struct AggregatedAnalysis {
    std::vector<HotpatchComparison> comparisons;
    
    // Summary statistics
    double mean_improvement_percent;
    double median_improvement_percent;
    double min_improvement_percent;
    double max_improvement_percent;
    
    // Significance breakdown
    int highly_significant_count;  // p < 0.001
    int very_significant_count;    // p < 0.01
    int significant_count;       // p < 0.05
    int not_significant_count;
    
    // Effect size distribution
    double mean_effect_size;
    int large_effect_count;   // d > 0.8
    int medium_effect_count;  // 0.5 < d < 0.8
    int small_effect_count;   // 0.2 < d < 0.5
    int negligible_effect_count; // d < 0.2
    
    // Model-specific breakdown
    std::map<std::string, double> improvement_by_model;
    std::map<std::string, double> improvement_by_patch_type;
};

// Statistical analysis engine
class StatisticalAnalysisEngine {
public:
    StatisticalAnalysisEngine();
    
    // Main analysis routine
    HotpatchComparison AnalyzeComparison(
        const BaselineMeasurement& baseline,
        const HotpatchInterventionResult& hotpatched);
    
    // Aggregate analysis
    AggregatedAnalysis AnalyzeAggregated(
        const std::vector<HotpatchComparison>& comparisons);
    
    // Individual statistical tests
    StatisticalTestResult WelchTTest(
        const StatisticalMetrics& baseline,
        const StatisticalMetrics& hotpatched);
    
    StatisticalTestResult MannWhitneyUTest(
        const std::vector<double>& baseline_samples,
        const std::vector<double>& hotpatched_samples);
    
    StatisticalTestResult PairedTTest(
        const std::vector<double>& baseline_samples,
        const std::vector<double>& hotpatched_samples);
    
    // Effect size calculations
    double CohensD(const StatisticalMetrics& baseline,
                   const StatisticalMetrics& hotpatched);
    
    double HedgeSG(const StatisticalMetrics& baseline,
                   const StatisticalMetrics& hotpatched);
    
    double GlassDelta(const StatisticalMetrics& baseline,
                      const StatisticalMetrics& hotpatched);
    
    // Confidence intervals
    ConfidenceInterval MeanCI(const StatisticalMetrics& stats,
                               double confidence = 0.95);
    
    ConfidenceInterval MedianCIBootstrap(
        const std::vector<double>& samples,
        double confidence = 0.95,
        int iterations = 1000);
    
    ConfidenceInterval DifferenceCI(
        const StatisticalMetrics& baseline,
        const StatisticalMetrics& hotpatched,
        double confidence = 0.95);
    
    // Power analysis
    struct PowerAnalysisResult {
        double observed_power;
        double required_sample_size;
        double min_detectable_effect;
        bool adequately_powered;
    };
    
    PowerAnalysisResult CalculatePower(
        const StatisticalMetrics& baseline,
        double expected_effect_size,
        double alpha = 0.05,
        double target_power = 0.80);
    
    // Multiple comparisons correction
    std::vector<double> BonferroniCorrection(
        std::vector<double> p_values,
        double alpha = 0.05);
    
    std::vector<double> BenjaminiHochbergCorrection(
        std::vector<double> p_values,
        double fdr = 0.05);
    
    // Export
    std::string ExportComparisonToJson(const HotpatchComparison& comparison);
    std::string ExportComparisonToMarkdown(const HotpatchComparison& comparison);
    std::string ExportAggregatedToJson(const AggregatedAnalysis& analysis);
    std::string ExportAggregatedToMarkdown(const AggregatedAnalysis& analysis);

private:
    // Internal helpers
    double CalculatePValue(double test_statistic, int df);
    double CalculateTStatistic(const StatisticalMetrics& baseline,
                               const StatisticalMetrics& hotpatched);
    double CalculateDegreesOfFreedom(const StatisticalMetrics& baseline,
                                     const StatisticalMetrics& hotpatched);
    std::string InterpretEffectSize(double d);
    std::string InterpretPValue(double p);
};

// Significance level utilities
struct SignificanceLevel {
    static std::string GetMarker(double p_value) {
        if (p_value < 0.001) return "***";
        if (p_value < 0.01) return "**";
        if (p_value < 0.05) return "*";
        return "ns";
    }
    
    static std::string GetDescription(double p_value) {
        if (p_value < 0.001) return "highly significant (p < 0.001)";
        if (p_value < 0.01) return "very significant (p < 0.01)";
        if (p_value < 0.05) return "significant (p < 0.05)";
        return "not significant (p >= 0.05)";
    }
};

// Factory
std::unique_ptr<StatisticalAnalysisEngine> CreateStatisticalAnalysisEngine();

// Quick analysis function
HotpatchComparison QuickAnalyze(
    const BaselineMeasurement& baseline,
    const HotpatchInterventionResult& hotpatched);

} // namespace benchmarks
} // namespace rawrxd
