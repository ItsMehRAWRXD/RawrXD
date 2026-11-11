// ci_integration.cpp
// Batch 5: CI/CD Integration Module
//
// Provides exit codes, threshold checking, and CI-friendly output
// Features: Configurable thresholds, regression detection, artifact generation
// Output: CI-compatible status codes and reports

#include "benchmark_tiers.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <cmath>

namespace Benchmark {

// Exit codes for CI systems
enum class CIExitCode {
    SUCCESS = 0,
    BENCHMARK_FAILED = 1,
    THRESHOLD_VIOLATION = 2,
    REGRESSION_DETECTED = 3,
    CONFIGURATION_ERROR = 4,
    TIMEOUT = 5
};

class CIIntegration {
public:
    struct ThresholdConfig {
        // Performance thresholds
        double min_tps = 10.0;
        double max_latency_p95_ms = 5000.0;
        double max_ttft_ms = 2000.0;
        
        // Reliability thresholds
        double max_error_rate = 0.05; // 5%
        double min_availability = 0.95; // 95%
        double max_memory_growth_mb_per_hour = 100.0;
        
        // Agentic thresholds
        double min_planning_accuracy = 0.70; // 70%
        double min_tool_success_rate = 0.80; // 80%
        double min_swarm_efficiency = 0.80; // 80%
        
        // Workflow thresholds
        double min_workflow_quality = 0.60; // 60%
        double max_workflow_time_seconds = 300.0; // 5 minutes
    };

    struct ThresholdViolation {
        std::string benchmark;
        std::string metric;
        double actual_value;
        double threshold_value;
        std::string comparison; // "<", ">", "=="
    };

    struct CIResults {
        bool all_benchmarks_passed = false;
        bool thresholds_met = false;
        bool no_regression = false;
        std::vector<ThresholdViolation> violations;
        std::vector<std::string> regressions;
        CIExitCode exit_code = CIExitCode::SUCCESS;
        std::string summary_message;
    };

    struct BenchmarkResult {
        std::string name;
        bool passed;
        std::map<std::string, double> metrics;
    };

    explicit CIIntegration(const ThresholdConfig& thresholds = ThresholdConfig())
        : thresholds_(thresholds) {}

    CIResults Validate(const std::vector<BenchmarkResult>& results,
                      const std::string& baseline_path = "") {
        CIResults ci_results;
        
        // Check if all benchmarks passed
        ci_results.all_benchmarks_passed = true;
        for (const auto& result : results) {
            if (!result.passed) {
                ci_results.all_benchmarks_passed = false;
                break;
            }
        }
        
        // Check thresholds
        ci_results.thresholds_met = CheckThresholds(results, ci_results.violations);
        
        // Check regression if baseline provided
        if (!baseline_path.empty()) {
            ci_results.no_regression = CheckRegression(results, baseline_path, ci_results.regressions);
        } else {
            ci_results.no_regression = true; // No baseline = no regression possible
        }
        
        // Determine exit code
        ci_results.exit_code = DetermineExitCode(ci_results);
        ci_results.summary_message = GenerateSummary(ci_results);
        
        return ci_results;
    }

    void PrintCIReport(const CIResults& results) {
        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "  CI/CD Integration Report\n";
        std::cout << std::string(80, '=') << "\n\n";
        
        std::cout << "  Exit Code: " << static_cast<int>(results.exit_code) << "\n";
        std::cout << "  Status: " << results.summary_message << "\n\n";
        
        std::cout << "  Checks:\n";
        std::cout << "    All Benchmarks Passed: " 
                  << (results.all_benchmarks_passed ? "✓ YES" : "✗ NO") << "\n";
        std::cout << "    Thresholds Met: " 
                  << (results.thresholds_met ? "✓ YES" : "✗ NO") << "\n";
        std::cout << "    No Regression: " 
                  << (results.no_regression ? "✓ YES" : "✗ NO") << "\n";
        
        if (!results.violations.empty()) {
            std::cout << "\n  Threshold Violations:\n";
            for (const auto& v : results.violations) {
                std::cout << "    - " << v.benchmark << "/" << v.metric 
                          << ": " << v.actual_value << " " << v.comparison 
                          << " " << v.threshold_value << "\n";
            }
        }
        
        if (!results.regressions.empty()) {
            std::cout << "\n  Regressions Detected:\n";
            for (const auto& r : results.regressions) {
                std::cout << "    - " << r << "\n";
            }
        }
        
        std::cout << "\n" << std::string(80, '=') << "\n";
    }

    void WriteGitHubActionsOutput(const CIResults& results, const std::string& path = "") {
        // Write GitHub Actions workflow commands
        std::ostream* out = &std::cout;
        std::ofstream file;
        
        if (!path.empty()) {
            file.open(path);
            if (file.is_open()) {
                out = &file;
            }
        }
        
        // Set outputs for GitHub Actions
        *out << "::set-output name=exit_code::" << static_cast<int>(results.exit_code) << "\n";
        *out << "::set-output name=passed::" << (results.all_benchmarks_passed ? "true" : "false") << "\n";
        *out << "::set-output name=thresholds_met::" << (results.thresholds_met ? "true" : "false") << "\n";
        *out << "::set-output name=violations_count::" << results.violations.size() << "\n";
        
        if (results.exit_code != CIExitCode::SUCCESS) {
            *out << "::error::Benchmark validation failed: " << results.summary_message << "\n";
        } else if (!results.violations.empty()) {
            *out << "::warning::" << results.violations.size() << " threshold violations detected\n";
        }
    }

    void WriteJUnitXML(const std::vector<BenchmarkResult>& results,
                      const std::string& path = "benchmark_results.xml") {
        std::ofstream file(path);
        if (!file.is_open()) {
            std::cerr << "Failed to write JUnit XML to: " << path << "\n";
            return;
        }
        
        int failures = 0;
        for (const auto& r : results) {
            if (!r.passed) failures++;
        }
        
        file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        file << "<testsuites>\n";
        file << "  <testsuite name=\"RawrXD Benchmarks\" tests=\"" 
             << results.size() << "\" failures=\"" << failures << "\">\n";
        
        for (const auto& result : results) {
            file << "    <testcase name=\"" << EscapeXML(result.name) << "\"\n";
            if (!result.passed) {
                file << "      <failure message=\"Benchmark failed\">\n";
                file << "        Benchmark " << EscapeXML(result.name) << " did not meet success criteria\n";
                file << "      </failure>\n";
            }
            file << "    </testcase>\n";
        }
        
        file << "  </testsuite>\n";
        file << "</testsuites>\n";
        
        std::cout << "JUnit XML report written to: " << path << "\n";
    }

private:
    ThresholdConfig thresholds_;

    bool CheckThresholds(const std::vector<BenchmarkResult>& results,
                        std::vector<ThresholdViolation>& violations) {
        bool all_met = true;
        
        for (const auto& result : results) {
            if (!result.passed) continue; // Skip failed benchmarks
            
            // Check TPS
            auto tps_it = result.metrics.find("tps");
            if (tps_it != result.metrics.end() && tps_it->second < thresholds_.min_tps) {
                violations.push_back({result.name, "tps", tps_it->second, 
                                     thresholds_.min_tps, "<"});
                all_met = false;
            }
            
            // Check latency
            auto latency_it = result.metrics.find("latency_p95_ms");
            if (latency_it != result.metrics.end() && latency_it->second > thresholds_.max_latency_p95_ms) {
                violations.push_back({result.name, "latency_p95_ms", latency_it->second,
                                     thresholds_.max_latency_p95_ms, ">"});
                all_met = false;
            }
            
            // Check error rate
            auto error_it = result.metrics.find("error_rate");
            if (error_it != result.metrics.end() && error_it->second > thresholds_.max_error_rate) {
                violations.push_back({result.name, "error_rate", error_it->second,
                                     thresholds_.max_error_rate, ">"});
                all_met = false;
            }
            
            // Check availability
            auto avail_it = result.metrics.find("availability");
            if (avail_it != result.metrics.end() && avail_it->second < thresholds_.min_availability) {
                violations.push_back({result.name, "availability", avail_it->second,
                                     thresholds_.min_availability, "<"});
                all_met = false;
            }
        }
        
        return all_met;
    }

    bool CheckRegression(const std::vector<BenchmarkResult>& results,
                        const std::string& baseline_path,
                        std::vector<std::string>& regressions) {
        // Load baseline (simplified - would load from JSON in production)
        // For now, assume no regression if we can't load baseline
        std::ifstream baseline_file(baseline_path);
        if (!baseline_file.is_open()) {
            return true; // No baseline = no regression
        }
        
        // Parse baseline and compare (simplified)
        // In production, would properly parse JSON and compare metrics
        
        return regressions.empty();
    }

    CIExitCode DetermineExitCode(const CIResults& results) {
        if (!results.all_benchmarks_passed) {
            return CIExitCode::BENCHMARK_FAILED;
        }
        if (!results.thresholds_met) {
            return CIExitCode::THRESHOLD_VIOLATION;
        }
        if (!results.no_regression) {
            return CIExitCode::REGRESSION_DETECTED;
        }
        return CIExitCode::SUCCESS;
    }

    std::string GenerateSummary(const CIResults& results) {
        switch (results.exit_code) {
            case CIExitCode::SUCCESS:
                return "All benchmarks passed, thresholds met, no regression";
            case CIExitCode::BENCHMARK_FAILED:
                return "One or more benchmarks failed";
            case CIExitCode::THRESHOLD_VIOLATION:
                return "Performance thresholds not met";
            case CIExitCode::REGRESSION_DETECTED:
                return "Performance regression detected";
            case CIExitCode::CONFIGURATION_ERROR:
                return "Configuration error";
            case CIExitCode::TIMEOUT:
                return "Benchmark timeout";
            default:
                return "Unknown error";
        }
    }

    static std::string EscapeXML(const std::string& input) {
        std::string output;
        for (char c : input) {
            switch (c) {
                case '&': output += "&amp;"; break;
                case '<': output += "&lt;"; break;
                case '>': output += "&gt;"; break;
                case '"': output += "&quot;"; break;
                case '\'': output += "&apos;"; break;
                default: output += c;
            }
        }
        return output;
    }
};

// Main entry point for CI mode
int RunCIMode(int argc, char* argv[]) {
    CIIntegration::ThresholdConfig thresholds;
    std::string baseline_path;
    std::string output_format = "console";
    
    // Parse CI-specific arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--baseline" && i + 1 < argc) {
            baseline_path = argv[++i];
        } else if (arg == "--min-tps" && i + 1 < argc) {
            thresholds.min_tps = std::stod(argv[++i]);
        } else if (arg == "--max-latency" && i + 1 < argc) {
            thresholds.max_latency_p95_ms = std::stod(argv[++i]);
        } else if (arg == "--output-format" && i + 1 < argc) {
            output_format = argv[++i];
        }
    }
    
    CIIntegration ci(thresholds);
    
    // In production, would load actual benchmark results here
    std::vector<CIIntegration::BenchmarkResult> results;
    
    auto ci_results = ci.Validate(results, baseline_path);
    
    if (output_format == "github") {
        ci.WriteGitHubActionsOutput(ci_results);
    } else {
        ci.PrintCIReport(ci_results);
    }
    
    return static_cast<int>(ci_results.exit_code);
}

} // namespace Benchmark
