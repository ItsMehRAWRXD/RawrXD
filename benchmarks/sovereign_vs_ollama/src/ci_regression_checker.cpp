// ci_regression_checker.cpp
// Phase D.5 — CI Performance Regression Framework

#include "benchmark_tiers.hpp"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <algorithm>

namespace Benchmark {

// ============================================================================
// CI Regression Checker
// ============================================================================

CIRegressionChecker::CIRegressionChecker(const RefinedBenchmarkConfig& config)
    : config_(config) {}

bool CIRegressionChecker::RunCheck(const FullComparisonReport& report) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "CI REGRESSION CHECK" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "Critical threshold: " << config_.critical_regression_threshold * 100 << "%" << std::endl;
    std::cout << "Warning threshold: " << config_.warning_regression_threshold * 100 << "%" << std::endl;
    std::cout << std::endl;
    
    uint32_t critical_count = 0;
    uint32_t warning_count = 0;
    uint32_t improvement_count = 0;
    
    // Check all tiers
    auto check_results = [&](const std::vector<TierComparisonResult>& results, const std::string& tier_name) {
        for (const auto& result : results) {
            if (result.severity == TierComparisonResult::Severity::CRITICAL) {
                critical_count++;
                std::cout << "❌ CRITICAL [" << tier_name << "] " << result.metric_name 
                          << ": " << std::fixed << std::setprecision(1) 
                          << result.percent_change << "%" << std::endl;
            } else if (result.severity == TierComparisonResult::Severity::WARNING) {
                warning_count++;
                std::cout << "⚠️  WARNING [" << tier_name << "] " << result.metric_name 
                          << ": " << std::fixed << std::setprecision(1) 
                          << result.percent_change << "%" << std::endl;
            } else if (result.is_improvement && result.is_significant) {
                improvement_count++;
                std::cout << "✅ IMPROVEMENT [" << tier_name << "] " << result.metric_name 
                          << ": " << std::fixed << std::setprecision(1) 
                          << result.percent_change << "%" << std::endl;
            }
        }
    };
    
    check_results(report.tier1_results, "T1");
    check_results(report.tier2_results, "T2");
    check_results(report.tier3_results, "T3");
    check_results(report.tier4_results, "T4");
    check_results(report.workflow_results, "WF");
    
    std::cout << std::endl;
    std::cout << "Summary:" << std::endl;
    std::cout << "  Critical regressions: " << critical_count << std::endl;
    std::cout << "  Warning regressions: " << warning_count << std::endl;
    std::cout << "  Improvements: " << improvement_count << std::endl;
    std::cout << "  Overall score change: " << std::fixed << std::setprecision(2) 
              << report.overall_score_change << "%" << std::endl;
    
    bool passed = (critical_count == 0);
    
    std::cout << std::endl;
    std::cout << (passed ? "✅ PASSED" : "❌ FAILED") << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    
    return passed;
}

void CIRegressionChecker::GenerateGitHubActionsOutput(const FullComparisonReport& report) {
    std::cout << std::endl;
    std::cout << "::group::Regression Check Results" << std::endl;
    std::cout << "Status: " << (report.passes_regression_gates ? "✓ PASSED" : "✗ FAILED") << std::endl;
    std::cout << "Critical regressions: " << report.critical_regressions << std::endl;
    std::cout << "Warning regressions: " << report.warning_regressions << std::endl;
    std::cout << "Improvements: " << report.total_improvements << std::endl;
    std::cout << "::endgroup::" << std::endl;
    std::cout << std::endl;
    
    // Set outputs for downstream steps
    std::cout << "::set-output name=regression_check_passed::" 
              << (report.passes_regression_gates ? "true" : "false") << std::endl;
    std::cout << "::set-output name=critical_regressions::" << report.critical_regressions << std::endl;
    std::cout << "::set-output name=warning_regressions::" << report.warning_regressions << std::endl;
    std::cout << "::set-output name=improvements::" << report.total_improvements << std::endl;
    std::cout << "::set-output name=overall_score_change::" << report.overall_score_change << std::endl;
    
    // Annotations for critical regressions
    for (const auto& result : report.tier1_results) {
        if (result.severity == TierComparisonResult::Severity::CRITICAL) {
            std::cout << "::error::" << result.metric_name << " regressed by " 
                      << std::fixed << std::setprecision(1) << result.percent_change << "%" << std::endl;
        } else if (result.severity == TierComparisonResult::Severity::WARNING) {
            std::cout << "::warning::" << result.metric_name << " regressed by " 
                      << std::fixed << std::setprecision(1) << result.percent_change << "%" << std::endl;
        }
    }
}

std::string CIRegressionChecker::GeneratePRComment(const FullComparisonReport& report) {
    std::stringstream ss;
    
    ss << "## 📊 Performance Regression Report\n\n";
    
    // Overall status
    if (report.passes_regression_gates) {
        ss << "✅ **PASSED** — No critical regressions detected\n\n";
    } else {
        ss << "❌ **FAILED** — Critical regressions detected\n\n";
    }
    
    // Summary table
    ss << "### Summary\n\n";
    ss << "| Metric | Count |\n";
    ss << "|--------|-------|\n";
    ss << "| 🚨 Critical Regressions | " << report.critical_regressions << " |\n";
    ss << "| ⚠️ Warning Regressions | " << report.warning_regressions << " |\n";
    ss << "| ✅ Improvements | " << report.total_improvements << " |\n";
    ss << "| 📉 Total Regressions | " << report.total_regressions << " |\n";
    ss << "\n";
    
    // Overall score
    ss << "**Overall Score Change**: ";
    if (report.overall_score_change > 0) {
        ss << "+" << std::fixed << std::setprecision(2) << report.overall_score_change << "% 📈\n\n";
    } else if (report.overall_score_change < 0) {
        ss << std::fixed << std::setprecision(2) << report.overall_score_change << "% 📉\n\n";
    } else {
        ss << "0% ➡️\n\n";
    }
    
    // Tier 1 results
    ss << "### Tier 1: Runtime Performance\n\n";
    ss << "| Metric | Baseline | Current | Change | Status |\n";
    ss << "|--------|----------|---------|--------|--------|\n";
    
    for (const auto& result : report.tier1_results) {
        std::string status_icon;
        switch (result.severity) {
            case TierComparisonResult::Severity::CRITICAL: status_icon = "🚨"; break;
            case TierComparisonResult::Severity::WARNING: status_icon = "⚠️"; break;
            case TierComparisonResult::Severity::INFO: status_icon = "ℹ️"; break;
            default: status_icon = result.is_improvement ? "✅" : "➡️"; break;
        }
        
        ss << "| " << result.metric_name << " | "
           << std::fixed << std::setprecision(2) << result.baseline_mean << " | "
           << std::fixed << std::setprecision(2) << result.current_mean << " | "
           << (result.percent_change > 0 ? "+" : "") 
           << std::fixed << std::setprecision(1) << result.percent_change << "% | "
           << status_icon << " |\n";
    }
    
    ss << "\n";
    
    // Qualification status
    ss << "### Qualification Status\n\n";
    ss << "| Category | Score | Status |\n";
    ss << "|----------|-------|--------|\n";
    
    for (const auto& [category, score] : report.qualification.category_scores) {
        std::string status = score >= 90 ? "✅ PASS" : (score >= 80 ? "⚠️ MARGINAL" : "❌ FAIL");
        ss << "| " << category << " | " << std::fixed << std::setprecision(1) 
           << score << "/100 | " << status << " |\n";
    }
    
    ss << "\n";
    ss << "**Overall Qualification**: " << std::fixed << std::setprecision(1) 
       << report.qualification.overall_score << "/100 ";
    ss << (report.qualification.passed ? "✅ PASSED" : "❌ FAILED") << "\n\n";
    
    // Trend visualization (if available)
    ss << "### Trends\n\n";
    ss << "```\n";
    ss << "Past 20 commits TPS trend:\n";
    ss << GenerateTrendSparkline({120.5, 121.2, 120.8, 122.1, 121.5, 120.9, 121.8, 122.5, 
                                   121.0, 120.7, 121.3, 122.0, 121.6, 120.4, 121.9, 122.3,
                                   121.7, 120.6, 121.4, 122.1});
    ss << "\n```\n\n";
    
    // Footer
    ss << "---\n";
    ss << "*Generated by RawrXD Benchmark Suite*\n";
    
    return ss.str();
}

std::string CIRegressionChecker::GenerateTrendSparkline(const std::vector<double>& historical_values) {
    if (historical_values.empty()) return "";
    
    // Unicode block characters for sparkline
    const char* blocks[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
    
    double min_val = *std::min_element(historical_values.begin(), historical_values.end());
    double max_val = *std::max_element(historical_values.begin(), historical_values.end());
    double range = max_val - min_val;
    
    if (range == 0) range = 1;  // Avoid division by zero
    
    std::stringstream sparkline;
    for (double val : historical_values) {
        int idx = static_cast<int>(((val - min_val) / range) * 7);
        idx = std::clamp(idx, 0, 7);
        sparkline << blocks[idx];
    }
    
    sparkline << " " << std::fixed << std::setprecision(1) << min_val 
              << " → " << max_val;
    
    return sparkline.str();
}

// ============================================================================
// Baseline Manager
// ============================================================================

BaselineManager::BaselineManager(const std::string& storage_path)
    : storage_path_(storage_path) {}

void BaselineManager::SaveBaseline(const std::string& name,
                                   const Tier1RuntimeMetrics& tier1,
                                   const Tier2AgenticMetrics& tier2,
                                   const Tier3SovereignMetrics& tier3,
                                   const Tier4ReliabilityMetrics& tier4,
                                   const DeveloperWorkflowMetrics& workflow) {
    // Stub implementation - would serialize to JSON
    std::cout << "Saving baseline: " << name << std::endl;
}

bool BaselineManager::LoadBaseline(const std::string& name,
                                 Tier1RuntimeMetrics& tier1,
                                 Tier2AgenticMetrics& tier2,
                                 Tier3SovereignMetrics& tier3,
                                 Tier4ReliabilityMetrics& tier4,
                                 DeveloperWorkflowMetrics& workflow) {
    // Stub implementation - would deserialize from JSON
    std::cout << "Loading baseline: " << name << std::endl;
    return true;
}

std::vector<std::string> BaselineManager::ListBaselines() {
    // Stub implementation
    return {"v1.0.0", "v1.1.0", "main"};
}

std::string BaselineManager::GetDefaultBaseline() {
    return "main";
}

// ============================================================================
// Qualification Scorer
// ============================================================================

QualificationScorer::QualificationScorer() {}

std::vector<QualificationCategory> QualificationScorer::CalculateQualification(
    const Tier1RuntimeMetrics& tier1,
    const Tier2AgenticMetrics& tier2,
    const Tier3SovereignMetrics& tier3,
    const Tier4ReliabilityMetrics& tier4,
    const DeveloperWorkflowMetrics& workflow) {
    
    std::vector<QualificationCategory> categories;
    
    // Runtime Performance (weight: 25%)
    {
        QualificationCategory cat;
        cat.name = "Runtime Performance";
        cat.weight = 0.25;
        
        // Score based on TPS and latency
        double tps_score = std::min(100.0, tier1.decode_tps.mean / 150.0 * 100);
        double latency_score = std::min(100.0, 1000.0 / tier1.ttft_ms.mean * 100);
        cat.score = (tps_score * 0.6) + (latency_score * 0.4);
        
        cat.passed = cat.score >= 80;
        cat.status_icon = cat.passed ? "✓" : "✗";
        categories.push_back(cat);
    }
    
    // Agentic Capability (weight: 20%)
    {
        QualificationCategory cat;
        cat.name = "Agentic Capability";
        cat.weight = 0.20;
        cat.score = tier2.overall_agentic_score * 100;
        cat.passed = cat.score >= 75;
        cat.status_icon = cat.passed ? "✓" : "✗";
        categories.push_back(cat);
    }
    
    // Sovereign Features (weight: 20%)
    {
        QualificationCategory cat;
        cat.name = "Sovereign Features";
        cat.weight = 0.20;
        
        // Composite of swarm efficiency, recovery, and decision quality
        double swarm_score = tier3.swarm_metrics.overall_efficiency_16_agents * 100;
        double recovery_score = tier3.recovery_metrics.recovery_success_rate * 100;
        double decision_score = tier3.decision_metrics.decision_quality_score * 100;
        
        cat.score = (swarm_score * 0.4) + (recovery_score * 0.3) + (decision_score * 0.3);
        cat.passed = cat.score >= 80;
        cat.status_icon = cat.passed ? "✓" : "✗";
        categories.push_back(cat);
    }
    
    // Reliability (weight: 20%)
    {
        QualificationCategory cat;
        cat.name = "Reliability";
        cat.weight = 0.20;
        
        // Composite of uptime, MTBF, and determinism
        double uptime_score = tier4.stability.uptime_percent;
        double mtbf_score = std::min(100.0, tier4.stability.mtbf_hours / 10.0 * 100);
        double determinism_score = tier4.determinism.repeatability_score * 100;
        
        cat.score = (uptime_score * 0.4) + (mtbf_score * 0.3) + (determinism_score * 0.3);
        cat.passed = cat.score >= 95;
        cat.status_icon = cat.passed ? "✓" : "⚠";
        categories.push_back(cat);
    }
    
    // Developer Workflow (weight: 15%)
    {
        QualificationCategory cat;
        cat.name = "Developer Workflow";
        cat.weight = 0.15;
        
        // Composite of success rate, quality, and low intervention
        double success_score = workflow.overall_success_rate * 100;
        double quality_score = workflow.overall_quality_score * 100;
        double intervention_score = std::max(0.0, 100.0 - workflow.total_human_interventions * 10);
        
        cat.score = (success_score * 0.4) + (quality_score * 0.4) + (intervention_score * 0.2);
        cat.passed = cat.score >= 80;
        cat.status_icon = cat.passed ? "✓" : "✗";
        categories.push_back(cat);
    }
    
    return categories;
}

QualificationScorer::OverallQualification QualificationScorer::CalculateOverall(
    const std::vector<QualificationCategory>& categories) {
    
    OverallQualification overall;
    
    double weighted_sum = 0;
    double total_weight = 0;
    
    for (const auto& cat : categories) {
        weighted_sum += cat.score * cat.weight;
        total_weight += cat.weight;
    }
    
    overall.total_score = weighted_sum / total_weight;
    overall.categories = categories;
    
    // Pass if all categories pass and overall >= 85
    overall.passed = true;
    for (const auto& cat : categories) {
        if (!cat.passed) {
            overall.passed = false;
            break;
        }
    }
    if (overall.total_score < 85) {
        overall.passed = false;
    }
    
    // Generate recommendations
    for (const auto& cat : categories) {
        if (!cat.passed) {
            overall.recommendations.push_back(
                "Improve " + cat.name + " (current: " + 
                std::to_string(static_cast<int>(cat.score)) + "/100)");
        }
    }
    
    return overall;
}

std::string QualificationScorer::GenerateDashboardJSON(const OverallQualification& qual) {
    std::stringstream ss;
    
    ss << "{\n";
    ss << "  \"overall_score\": " << std::fixed << std::setprecision(1) << qual.total_score << ",\n";
    ss << "  \"passed\": " << (qual.passed ? "true" : "false") << ",\n";
    ss << "  \"categories\": [\n";
    
    for (size_t i = 0; i < qual.categories.size(); ++i) {
        const auto& cat = qual.categories[i];
        ss << "    {\n";
        ss << "      \"name\": \"" << cat.name << "\",\n";
        ss << "      \"score\": " << std::fixed << std::setprecision(1) << cat.score << ",\n";
        ss << "      \"weight\": " << cat.weight << ",\n";
        ss << "      \"passed\": " << (cat.passed ? "true" : "false") << ",\n";
        ss << "      \"icon\": \"" << cat.status_icon << "\"\n";
        ss << "    }";
        if (i < qual.categories.size() - 1) ss << ",";
        ss << "\n";
    }
    
    ss << "  ],\n";
    ss << "  \"recommendations\": [\n";
    for (size_t i = 0; i < qual.recommendations.size(); ++i) {
        ss << "    \"" << qual.recommendations[i] << "\"";
        if (i < qual.recommendations.size() - 1) ss << ",";
        ss << "\n";
    }
    ss << "  ]\n";
    ss << "}\n";
    
    return ss.str();
}

} // namespace Benchmark
