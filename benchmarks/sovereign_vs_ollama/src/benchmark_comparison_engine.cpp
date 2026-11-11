// benchmark_comparison_engine.cpp
// Batch 5: Benchmark Comparison Engine
//
// Compares benchmark results across runs, backends, and versions
// Features: Statistical comparison, trend analysis, regression detection
// Output: Comparison reports with significance testing

#include "benchmark_tiers.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>
#include <cmath>

namespace Benchmark {

class BenchmarkComparisonEngine {
public:
    struct ComparisonConfig {
        double significance_level = 0.05; // 95% confidence
        double regression_threshold = 0.10; // 10% degradation
        double improvement_threshold = 0.10; // 10% improvement
        bool use_welch_ttest = true; // Welch's t-test for unequal variances
    };

    struct BenchmarkData {
        std::string name;
        std::string backend;
        std::string timestamp;
        StatisticalSummary metrics;
        int sample_count;
    };

    enum class ComparisonResult {
        SIGNIFICANT_IMPROVEMENT,
        SIGNIFICANT_REGRESSION,
        NO_SIGNIFICANT_CHANGE,
        INSUFFICIENT_DATA
    };

    struct Comparison {
        std::string metric_name;
        double baseline_mean;
        double current_mean;
        double percent_change;
        double p_value;
        ComparisonResult result;
        bool is_statistically_significant;
    };

    struct BenchmarkComparison {
        std::string benchmark_name;
        std::vector<Comparison> metric_comparisons;
        ComparisonResult overall_result;
        std::string summary;
    };

    struct SuiteComparison {
        std::string baseline_label;
        std::string current_label;
        std::vector<BenchmarkComparison> comparisons;
        int improvements = 0;
        int regressions = 0;
        int unchanged = 0;
        int insufficient = 0;
    };

    explicit BenchmarkComparisonEngine(const ComparisonConfig& config = ComparisonConfig())
        : config_(config) {}

    // Compare two benchmark results
    BenchmarkComparison Compare(const BenchmarkData& baseline,
                             const BenchmarkData& current) {
        BenchmarkComparison comparison;
        comparison.benchmark_name = baseline.name;
        
        // Compare mean
        Comparison mean_comp;
        mean_comp.metric_name = "mean";
        mean_comp.baseline_mean = baseline.metrics.mean;
        mean_comp.current_mean = current.metrics.mean;
        mean_comp.percent_change = CalculatePercentChange(
            baseline.metrics.mean, current.metrics.mean);
        mean_comp.p_value = CalculatePValue(baseline.metrics, current.metrics);
        mean_comp.is_statistically_significant = 
            mean_comp.p_value < config_.significance_level;
        mean_comp.result = ClassifyResult(mean_comp.percent_change, 
                                         mean_comp.is_statistically_significant);
        
        comparison.metric_comparisons.push_back(mean_comp);
        
        // Compare P95
        Comparison p95_comp;
        p95_comp.metric_name = "p95";
        p95_comp.baseline_mean = baseline.metrics.p95;
        p95_comp.current_mean = current.metrics.p95;
        p95_comp.percent_change = CalculatePercentChange(
            baseline.metrics.p95, current.metrics.p95);
        p95_comp.p_value = 0.0; // Would need full distributions
        p95_comp.is_statistically_significant = false;
        p95_comp.result = ClassifyResult(p95_comp.percent_change, false);
        
        comparison.metric_comparisons.push_back(p95_comp);
        
        // Determine overall result
        comparison.overall_result = DetermineOverallResult(comparison.metric_comparisons);
        comparison.summary = GenerateSummary(comparison);
        
        return comparison;
    }

    // Compare full suites
    SuiteComparison CompareSuites(const std::vector<BenchmarkData>& baseline_suite,
                                 const std::vector<BenchmarkData>& current_suite,
                                 const std::string& baseline_label = "baseline",
                                 const std::string& current_label = "current") {
        SuiteComparison suite_comp;
        suite_comp.baseline_label = baseline_label;
        suite_comp.current_label = current_label;
        
        // Match benchmarks by name
        std::map<std::string, const BenchmarkData*> baseline_map;
        for (const auto& b : baseline_suite) {
            baseline_map[b.name] = &b;
        }
        
        for (const auto& current : current_suite) {
            auto it = baseline_map.find(current.name);
            if (it != baseline_map.end()) {
                auto comp = Compare(*it->second, current);
                suite_comp.comparisons.push_back(comp);
                
                // Count results
                switch (comp.overall_result) {
                    case ComparisonResult::SIGNIFICANT_IMPROVEMENT:
                        suite_comp.improvements++;
                        break;
                    case ComparisonResult::SIGNIFICANT_REGRESSION:
                        suite_comp.regressions++;
                        break;
                    case ComparisonResult::NO_SIGNIFICANT_CHANGE:
                        suite_comp.unchanged++;
                        break;
                    case ComparisonResult::INSUFFICIENT_DATA:
                        suite_comp.insufficient++;
                        break;
                }
            }
        }
        
        return suite_comp;
    }

    // Print comparison report
    static void PrintComparison(const BenchmarkComparison& comp) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Comparison: " << comp.benchmark_name << "\n";
        std::cout << std::string(70, '=') << "\n";
        
        for (const auto& metric : comp.metric_comparisons) {
            std::cout << "\n  Metric: " << metric.metric_name << "\n";
            std::cout << "    Baseline: " << std::fixed << std::setprecision(2) 
                      << metric.baseline_mean << "\n";
            std::cout << "    Current:  " << metric.current_mean << "\n";
            std::cout << "    Change:   " << std::showpos << std::setprecision(1)
                      << (metric.percent_change * 100) << "%\n" << std::noshowpos;
            std::cout << "    P-value:  " << std::setprecision(4) << metric.p_value << "\n";
            std::cout << "    Result:   " << ResultToString(metric.result) << "\n";
        }
        
        std::cout << "\n  Overall: " << ResultToString(comp.overall_result) << "\n";
        std::cout << "  " << comp.summary << "\n";
    }

    static void PrintSuiteComparison(const SuiteComparison& suite) {
        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "  Suite Comparison: " << suite.baseline_label << " vs " 
                  << suite.current_label << "\n";
        std::cout << std::string(80, '=') << "\n\n";
        
        std::cout << "  Summary:\n";
        std::cout << "    Improvements:  " << suite.improvements << "\n";
        std::cout << "    Regressions:   " << suite.regressions << "\n";
        std::cout << "    Unchanged:     " << suite.unchanged << "\n";
        std::cout << "    Insufficient:  " << suite.insufficient << "\n\n";
        
        if (suite.regressions > 0) {
            std::cout << "  Regressions Detected:\n";
            for (const auto& comp : suite.comparisons) {
                if (comp.overall_result == ComparisonResult::SIGNIFICANT_REGRESSION) {
                    std::cout << "    - " << comp.benchmark_name << "\n";
                }
            }
        }
        
        if (suite.improvements > 0) {
            std::cout << "\n  Improvements Detected:\n";
            for (const auto& comp : suite.comparisons) {
                if (comp.overall_result == ComparisonResult::SIGNIFICANT_IMPROVEMENT) {
                    std::cout << "    + " << comp.benchmark_name << "\n";
                }
            }
        }
        
        std::cout << "\n" << std::string(80, '=') << "\n";
    }

    // Generate trend analysis over multiple runs
    struct TrendAnalysis {
        std::string benchmark_name;
        std::string metric;
        double slope;
        double r_squared;
        std::string direction; // "improving", "degrading", "stable"
    };

    std::vector<TrendAnalysis> AnalyzeTrends(
        const std::vector<std::vector<BenchmarkData>>& historical_runs) {
        
        std::vector<TrendAnalysis> trends;
        
        if (historical_runs.size() < 2) {
            return trends;
        }
        
        // Group by benchmark name
        std::map<std::string, std::vector<const BenchmarkData*>> by_name;
        for (size_t i = 0; i < historical_runs.size(); ++i) {
            for (const auto& bench : historical_runs[i]) {
                by_name[bench.name].push_back(&bench);
            }
        }
        
        // Calculate trend for each benchmark
        for (const auto& [name, data] : by_name) {
            if (data.size() < 2) continue;
            
            // Simple linear regression on means
            std::vector<double> x;
            std::vector<double> y;
            for (size_t i = 0; i < data.size(); ++i) {
                x.push_back(static_cast<double>(i));
                y.push_back(data[i]->metrics.mean);
            }
            
            auto [slope, r2] = CalculateLinearRegression(x, y);
            
            TrendAnalysis trend;
            trend.benchmark_name = name;
            trend.metric = "mean";
            trend.slope = slope;
            trend.r_squared = r2;
            
            if (slope < -0.01) {
                trend.direction = "improving"; // Lower is better (latency)
            } else if (slope > 0.01) {
                trend.direction = "degrading";
            } else {
                trend.direction = "stable";
            }
            
            trends.push_back(trend);
        }
        
        return trends;
    }

private:
    ComparisonConfig config_;

    double CalculatePercentChange(double baseline, double current) {
        if (baseline == 0) return 0;
        return (current - baseline) / baseline;
    }

    double CalculatePValue(const StatisticalSummary& baseline,
                          const StatisticalSummary& current) {
        // Welch's t-test for unequal variances
        if (baseline.sample_count < 2 || current.sample_count < 2) {
            return 1.0; // Insufficient data
        }
        
        double mean_diff = std::abs(baseline.mean - current.mean);
        double se1 = baseline.std_dev * baseline.std_dev / baseline.sample_count;
        double se2 = current.std_dev * current.std_dev / current.sample_count;
        double se_diff = std::sqrt(se1 + se2);
        
        if (se_diff == 0) return 1.0;
        
        double t_stat = mean_diff / se_diff;
        
        // Simplified p-value calculation (would use proper t-distribution in production)
        // Using normal approximation for large samples
        double p_value = 2.0 * (1.0 - NormalCDF(t_stat));
        
        return std::min(1.0, std::max(0.0, p_value));
    }

    double NormalCDF(double x) {
        // Approximation of standard normal CDF
        return 0.5 * (1.0 + std::erf(x / std::sqrt(2.0)));
    }

    ComparisonResult ClassifyResult(double percent_change, bool significant) {
        if (!significant) {
            return ComparisonResult::NO_SIGNIFICANT_CHANGE;
        }
        
        if (percent_change < -config_.regression_threshold) {
            return ComparisonResult::SIGNIFICANT_IMPROVEMENT;
        } else if (percent_change > config_.regression_threshold) {
            return ComparisonResult::SIGNIFICANT_REGRESSION;
        }
        
        return ComparisonResult::NO_SIGNIFICANT_CHANGE;
    }

    ComparisonResult DetermineOverallResult(const std::vector<Comparison>& comparisons) {
        bool has_regression = false;
        bool has_improvement = false;
        
        for (const auto& comp : comparisons) {
            if (comp.result == ComparisonResult::SIGNIFICANT_REGRESSION) {
                has_regression = true;
            } else if (comp.result == ComparisonResult::SIGNIFICANT_IMPROVEMENT) {
                has_improvement = true;
            }
        }
        
        if (has_regression) return ComparisonResult::SIGNIFICANT_REGRESSION;
        if (has_improvement) return ComparisonResult::SIGNIFICANT_IMPROVEMENT;
        return ComparisonResult::NO_SIGNIFICANT_CHANGE;
    }

    std::string GenerateSummary(const BenchmarkComparison& comp) {
        std::ostringstream oss;
        switch (comp.overall_result) {
            case ComparisonResult::SIGNIFICANT_IMPROVEMENT:
                oss << "Significant improvement detected";
                break;
            case ComparisonResult::SIGNIFICANT_REGRESSION:
                oss << "Significant regression detected";
                break;
            case ComparisonResult::NO_SIGNIFICANT_CHANGE:
                oss << "No significant change";
                break;
            case ComparisonResult::INSUFFICIENT_DATA:
                oss << "Insufficient data for comparison";
                break;
        }
        return oss.str();
    }

    static std::string ResultToString(ComparisonResult result) {
        switch (result) {
            case ComparisonResult::SIGNIFICANT_IMPROVEMENT: return "IMPROVEMENT";
            case ComparisonResult::SIGNIFICANT_REGRESSION: return "REGRESSION";
            case ComparisonResult::NO_SIGNIFICANT_CHANGE: return "UNCHANGED";
            case ComparisonResult::INSUFFICIENT_DATA: return "INSUFFICIENT";
        }
        return "UNKNOWN";
    }

    std::pair<double, double> CalculateLinearRegression(const std::vector<double>& x,
                                                        const std::vector<double>& y) {
        if (x.size() != y.size() || x.size() < 2) {
            return {0.0, 0.0};
        }
        
        double n = static_cast<double>(x.size());
        double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0, sum_y2 = 0;
        
        for (size_t i = 0; i < x.size(); ++i) {
            sum_x += x[i];
            sum_y += y[i];
            sum_xy += x[i] * y[i];
            sum_x2 += x[i] * x[i];
            sum_y2 += y[i] * y[i];
        }
        
        double slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        
        double ss_tot = sum_y2 - (sum_y * sum_y) / n;
        double ss_res = sum_y2 - 2 * slope * sum_xy + slope * slope * sum_x2;
        double r2 = (ss_tot > 0) ? 1.0 - (ss_res / ss_tot) : 0.0;
        
        return {slope, r2};
    }
};

// Convenience function for quick comparison
void CompareBenchmarkResults(const std::string& baseline_file,
                            const std::string& current_file) {
    std::cout << "Comparing benchmark results...\n";
    std::cout << "Baseline: " << baseline_file << "\n";
    std::cout << "Current:  " << current_file << "\n";
    
    // In production, would load JSON files and compare
    // For now, print placeholder
    std::cout << "\nComparison functionality requires JSON result files.\n";
}

} // namespace Benchmark
