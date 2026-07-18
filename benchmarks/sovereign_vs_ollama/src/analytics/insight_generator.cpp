// insight_generator.cpp
// Batch 12: Automated Insight Generation
//
// Generates human-readable insights from analysis results
// Features: Natural language summaries, recommendations, action items

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>
#include <algorithm>

namespace Benchmark {
namespace Analytics {

// Insight structure
struct Insight {
    std::string category;      // "performance", "reliability", "trend", "anomaly"
    std::string severity;    // "info", "warning", "critical"
    std::string title;
    std::string description;
    std::vector<std::string> recommendations;
    std::map<std::string, double> metrics;
};

// Report structure
struct InsightReport {
    std::string generated_at;
    std::string benchmark_id;
    std::vector<Insight> insights;
    std::vector<std::string> executive_summary;
    std::vector<std::string> action_items;
    
    int CountBySeverity(const std::string& severity) const {
        int count = 0;
        for (const auto& insight : insights) {
            if (insight.severity == severity) ++count;
        }
        return count;
    }
};

// Insight generator
class InsightGenerator {
public:
    // Generate insights from benchmark results
    static InsightReport GenerateFromBenchmark(
        const std::string& benchmark_id,
        const DescriptiveStats& stats,
        const TrendResult& trend,
        const std::vector<AnomalyResult>& anomalies) {
        
        InsightReport report;
        report.benchmark_id = benchmark_id;
        report.generated_at = GetCurrentTimestamp();
        
        // Performance insights
        GeneratePerformanceInsights(stats, report);
        
        // Trend insights
        GenerateTrendInsights(trend, report);
        
        // Anomaly insights
        GenerateAnomalyInsights(anomalies, report);
        
        // Reliability insights
        GenerateReliabilityInsights(stats, report);
        
        // Generate executive summary
        GenerateExecutiveSummary(report);
        
        // Generate action items
        GenerateActionItems(report);
        
        return report;
    }
    
    // Generate comparison insights
    static InsightReport GenerateComparison(
        const std::string& benchmark_id,
        const std::vector<std::pair<std::string, DescriptiveStats>>& backend_stats) {
        
        InsightReport report;
        report.benchmark_id = benchmark_id;
        report.generated_at = GetCurrentTimestamp();
        
        if (backend_stats.size() < 2) {
            report.executive_summary.push_back("Insufficient data for comparison");
            return report;
        }
        
        // Find best and worst performers
        auto best = *std::max_element(backend_stats.begin(), backend_stats.end(),
            [](const auto& a, const auto& b) {
                return a.second.mean < b.second.mean;
            });
        
        auto worst = *std::min_element(backend_stats.begin(), backend_stats.end(),
            [](const auto& a, const auto& b) {
                return a.second.mean < b.second.mean;
            });
        
        // Generate comparison insight
        Insight comparison;
        comparison.category = "performance";
        comparison.severity = "info";
        comparison.title = "Backend Performance Comparison";
        
        double improvement = ((best.second.mean - worst.second.mean) / worst.second.mean) * 100.0;
        
        std::stringstream desc;
        desc << std::fixed << std::setprecision(1);
        desc << best.first << " shows the best performance with " << best.second.mean
             << " TPS, which is " << improvement << "% faster than " << worst.first
             << " (" << worst.second.mean << " TPS).";
        comparison.description = desc.str();
        
        comparison.metrics["best_tps"] = best.second.mean;
        comparison.metrics["worst_tps"] = worst.second.mean;
        comparison.metrics["improvement_percent"] = improvement;
        
        report.insights.push_back(comparison);
        
        // Consistency comparison
        auto most_consistent = *std::min_element(backend_stats.begin(), backend_stats.end(),
            [](const auto& a, const auto& b) {
                return a.second.cv < b.second.cv;
            });
        
        Insight consistency;
        consistency.category = "reliability";
        consistency.severity = most_consistent.second.cv < 0.05 ? "info" : "warning";
        consistency.title = "Performance Consistency";
        
        std::stringstream cons_desc;
        cons_desc << std::fixed << std::setprecision(2);
        cons_desc << most_consistent.first << " shows the most consistent performance (CV = "
                  << most_consistent.second.cv << "). ";
        
        if (most_consistent.second.cv > 0.1) {
            cons_desc << "High variability detected - consider investigating sources of variance.";
            consistency.recommendations.push_back("Review system load during benchmark runs");
            consistency.recommendations.push_back("Check for resource contention");
        } else {
            cons_desc << "Performance is stable and predictable.";
        }
        
        consistency.description = cons_desc.str();
        consistency.metrics["cv"] = most_consistent.second.cv;
        
        report.insights.push_back(consistency);
        
        GenerateExecutiveSummary(report);
        GenerateActionItems(report);
        
        return report;
    }
    
    // Generate regression insights
    static InsightReport GenerateRegressionReport(
        const std::string& benchmark_id,
        const std::vector<std::pair<std::string, double>>& regressions,
        const std::vector<std::pair<std::string, double>>& improvements) {
        
        InsightReport report;
        report.benchmark_id = benchmark_id;
        report.generated_at = GetCurrentTimestamp();
        
        // Regressions
        for (const auto& reg : regressions) {
            Insight insight;
            insight.category = "performance";
            insight.severity = reg.second < -10.0 ? "critical" : "warning";
            insight.title = "Performance Regression: " + reg.first;
            
            std::stringstream desc;
            desc << std::fixed << std::setprecision(1);
            desc << reg.first << " shows a " << std::abs(reg.second) 
                 << "% regression compared to baseline.";
            insight.description = desc.str();
            
            insight.metrics["regression_percent"] = reg.second;
            
            insight.recommendations.push_back("Investigate recent changes to " + reg.first);
            insight.recommendations.push_back("Review system configuration changes");
            insight.recommendations.push_back("Check for resource constraints");
            
            report.insights.push_back(insight);
        }
        
        // Improvements
        for (const auto& imp : improvements) {
            Insight insight;
            insight.category = "performance";
            insight.severity = "info";
            insight.title = "Performance Improvement: " + imp.first;
            
            std::stringstream desc;
            desc << std::fixed << std::setprecision(1);
            desc << imp.first << " shows a " << imp.second << "% improvement.";
            insight.description = desc.str();
            
            insight.metrics["improvement_percent"] = imp.second;
            
            report.insights.push_back(insight);
        }
        
        GenerateExecutiveSummary(report);
        GenerateActionItems(report);
        
        return report;
    }
    
    // Export report to Markdown
    static std::string ExportToMarkdown(const InsightReport& report) {
        std::stringstream md;
        
        md << "# Benchmark Analysis Report\n\n";
        md << "**Benchmark:** " << report.benchmark_id << "\n\n";
        md << "**Generated:** " << report.generated_at << "\n\n";
        
        // Executive Summary
        md << "## Executive Summary\n\n";
        for (const auto& summary : report.executive_summary) {
            md << "- " << summary << "\n";
        }
        md << "\n";
        
        // Statistics
        md << "### Issue Summary\n\n";
        md << "- 🔴 Critical: " << report.CountBySeverity("critical") << "\n";
        md << "- 🟡 Warnings: " << report.CountBySeverity("warning") << "\n";
        md << "- 🔵 Info: " << report.CountBySeverity("info") << "\n\n";
        
        // Insights
        md << "## Detailed Insights\n\n";
        for (const auto& insight : report.insights) {
            std::string icon = insight.severity == "critical" ? "🔴" :
                              insight.severity == "warning" ? "🟡" : "🔵";
            
            md << "### " << icon << " " << insight.title << "\n\n";
            md << "**Category:** " << insight.category << "\n\n";
            md << insight.description << "\n\n";
            
            if (!insight.metrics.empty()) {
                md << "**Metrics:**\n\n";
                for (const auto& [key, value] : insight.metrics) {
                    md << "- " << key << ": " << std::fixed << std::setprecision(3) << value << "\n";
                }
                md << "\n";
            }
            
            if (!insight.recommendations.empty()) {
                md << "**Recommendations:**\n\n";
                for (const auto& rec : insight.recommendations) {
                    md << "- " << rec << "\n";
                }
                md << "\n";
            }
        }
        
        // Action Items
        if (!report.action_items.empty()) {
            md << "## Action Items\n\n";
            for (size_t i = 0; i < report.action_items.size(); ++i) {
                md << (i + 1) << ". " << report.action_items[i] << "\n";
            }
            md << "\n";
        }
        
        return md.str();
    }
    
    // Export report to JSON
    static std::string ExportToJSON(const InsightReport& report) {
        std::stringstream json;
        
        json << "{\n";
        json << "  \"benchmark_id\": \"" << report.benchmark_id << "\",\n";
        json << "  \"generated_at\": \"" << report.generated_at << "\",\n";
        json << "  \"summary\": {\n";
        json << "    \"critical\": " << report.CountBySeverity("critical") << ",\n";
        json << "    \"warning\": " << report.CountBySeverity("warning") << ",\n";
        json << "    \"info\": " << report.CountBySeverity("info") << "\n";
        json << "  },\n";
        json << "  \"insights\": [\n";
        
        for (size_t i = 0; i < report.insights.size(); ++i) {
            const auto& insight = report.insights[i];
            json << "    {\n";
            json << "      \"category\": \"" << insight.category << "\",\n";
            json << "      \"severity\": \"" << insight.severity << "\",\n";
            json << "      \"title\": \"" << insight.title << "\",\n";
            json << "      \"description\": \"" << insight.description << "\"";
            
            if (!insight.metrics.empty()) {
                json << ",\n      \"metrics\": {\n";
                size_t j = 0;
                for (const auto& [key, value] : insight.metrics) {
                    json << "        \"" << key << "\": " << value;
                    if (++j < insight.metrics.size()) json << ",";
                    json << "\n";
                }
                json << "      }";
            }
            
            json << "\n    }";
            if (i < report.insights.size() - 1) json << ",";
            json << "\n";
        }
        
        json << "  ]\n";
        json << "}\n";
        
        return json.str();
    }

private:
    static void GeneratePerformanceInsights(const DescriptiveStats& stats,
                                            InsightReport& report) {
        // Mean performance
        Insight mean_perf;
        mean_perf.category = "performance";
        mean_perf.severity = "info";
        mean_perf.title = "Mean Performance";
        
        std::stringstream desc;
        desc << std::fixed << std::setprecision(2);
        desc << "Average throughput is " << stats.mean << " TPS ";
        desc << "(95% CI: " << stats.ci95_lower << " - " << stats.ci95_upper << ").";
        mean_perf.description = desc.str();
        
        mean_perf.metrics["mean_tps"] = stats.mean;
        mean_perf.metrics["ci_lower"] = stats.ci95_lower;
        mean_perf.metrics["ci_upper"] = stats.ci95_upper;
        
        report.insights.push_back(mean_perf);
        
        // Variability
        if (stats.cv > 0.1) {
            Insight variability;
            variability.category = "reliability";
            variability.severity = stats.cv > 0.2 ? "warning" : "info";
            variability.title = "Performance Variability";
            
            std::stringstream var_desc;
            var_desc << std::fixed << std::setprecision(2);
            var_desc << "Coefficient of variation is " << stats.cv 
                     << ", indicating ";
            var_desc << (stats.cv > 0.2 ? "high" : "moderate") << " variability.";
            variability.description = var_desc.str();
            
            variability.metrics["cv"] = stats.cv;
            variability.metrics["std_dev"] = stats.std_dev;
            
            if (stats.cv > 0.2) {
                variability.recommendations.push_back("Investigate sources of variance");
                variability.recommendations.push_back("Consider running more iterations");
            }
            
            report.insights.push_back(variability);
        }
    }
    
    static void GenerateTrendInsights(const TrendResult& trend,
                                      InsightReport& report) {
        if (trend.r_squared < 0.1) return;  // No significant trend
        
        Insight trend_insight;
        trend_insight.category = "trend";
        trend_insight.severity = trend.is_significant ? "info" : "warning";
        trend_insight.title = "Performance Trend";
        
        std::stringstream desc;
        desc << std::fixed << std::setprecision(3);
        desc << "Performance shows a " << trend.direction << " trend ";
        desc << "(slope = " << trend.slope << ", R² = " << trend.r_squared << "). ";
        
        if (trend.is_significant) {
            desc << "This trend is statistically significant (p < 0.05).";
        } else {
            desc << "This trend is not statistically significant.";
        }
        
        trend_insight.description = desc.str();
        trend_insight.metrics["slope"] = trend.slope;
        trend_insight.metrics["r_squared"] = trend.r_squared;
        trend_insight.metrics["p_value"] = trend.p_value;
        
        if (trend.direction == "degrading" && trend.is_significant) {
            trend_insight.severity = "warning";
            trend_insight.recommendations.push_back("Investigate performance degradation");
            trend_insight.recommendations.push_back("Review recent system changes");
        }
        
        report.insights.push_back(trend_insight);
    }
    
    static void GenerateAnomalyInsights(const std::vector<AnomalyResult>& anomalies,
                                        InsightReport& report) {
        if (anomalies.empty()) return;
        
        Insight anomaly_insight;
        anomaly_insight.category = "anomaly";
        anomaly_insight.severity = anomalies.size() > 5 ? "warning" : "info";
        anomaly_insight.title = "Anomaly Detection";
        
        std::stringstream desc;
        desc << "Detected " << anomalies.size() << " anomalous data points. ";
        
        // Find most severe
        auto max_it = std::max_element(anomalies.begin(), anomalies.end(),
            [](const auto& a, const auto& b) { return a.severity < b.severity; });
        
        if (max_it != anomalies.end()) {
            desc << "Maximum severity: " << std::fixed << std::setprecision(2) 
                 << max_it->severity;
        }
        
        anomaly_insight.description = desc.str();
        anomaly_insight.metrics["anomaly_count"] = anomalies.size();
        anomaly_insight.metrics["max_severity"] = max_it != anomalies.end() ? max_it->severity : 0.0;
        
        if (anomalies.size() > 5) {
            anomaly_insight.recommendations.push_back("Review anomalous measurements");
            anomaly_insight.recommendations.push_back("Check for measurement errors");
        }
        
        report.insights.push_back(anomaly_insight);
    }
    
    static void GenerateReliabilityInsights(const DescriptiveStats& stats,
                                            InsightReport& report) {
        // Check for outliers in percentiles
        double iqr = stats.p75 - stats.p25;
        if (iqr > stats.mean * 0.5) {
            Insight spread;
            spread.category = "reliability";
            spread.severity = "info";
            spread.title = "Performance Spread";
            
            std::stringstream desc;
            desc << std::fixed << std::setprecision(2);
            desc << "IQR is " << iqr << " TPS, indicating significant spread between ";
            desc << "25th and 75th percentiles.";
            spread.description = desc.str();
            
            spread.metrics["iqr"] = iqr;
            spread.metrics["p25"] = stats.p25;
            spread.metrics["p75"] = stats.p75;
            
            report.insights.push_back(spread);
        }
    }
    
    static void GenerateExecutiveSummary(InsightReport& report) {
        int critical = report.CountBySeverity("critical");
        int warnings = report.CountBySeverity("warning");
        
        if (critical > 0) {
            report.executive_summary.push_back(
                std::to_string(critical) + " critical issues require immediate attention");
        }
        
        if (warnings > 0) {
            report.executive_summary.push_back(
                std::to_string(warnings) + " warnings detected - review recommended");
        }
        
        if (critical == 0 && warnings == 0) {
            report.executive_summary.push_back("No significant issues detected - performance is stable");
        }
        
        // Add performance summary
        auto perf_insight = std::find_if(report.insights.begin(), report.insights.end(),
            [](const auto& i) { return i.title == "Mean Performance"; });
        
        if (perf_insight != report.insights.end()) {
            auto it = perf_insight->metrics.find("mean_tps");
            if (it != perf_insight->metrics.end()) {
                report.executive_summary.push_back(
                    "Average throughput: " + std::to_string(static_cast<int>(it->second)) + " TPS");
            }
        }
    }
    
    static void GenerateActionItems(InsightReport& report) {
        for (const auto& insight : report.insights) {
            for (const auto& rec : insight.recommendations) {
                report.action_items.push_back("[" + insight.severity + "] " + rec);
            }
        }
        
        if (report.action_items.empty()) {
            report.action_items.push_back("No immediate action required");
        }
    }
    
    static std::string GetCurrentTimestamp() {
        // Simplified - in production use proper time formatting
        return "2024-01-15T10:30:00Z";
    }
};

} // namespace Analytics
} // namespace Benchmark
