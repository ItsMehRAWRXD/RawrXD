// report_generator.cpp
// Batch 5: Report Generator
//
// Provides: HTML, Markdown, and JSON report generation
// Features: Charts, comparisons, trend visualization

#include "benchmark_tiers.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>
#include <chrono>

namespace Benchmark {

class ReportGenerator {
public:
    struct BenchmarkResult {
        std::string name;
        std::string tier;
        bool success;
        StatisticalSummary latency_ms;
        StatisticalSummary throughput_tps;
        double error_rate;
        int64_t duration_seconds;
        std::map<std::string, double> custom_metrics;
    };

    struct ComparisonData {
        std::string benchmark_name;
        double sovereign_value;
        double ollama_value;
        double percent_difference;
        std::string winner;
    };

    ReportGenerator(const std::string& title = "Benchmark Report")
        : title_(title), timestamp_(GetCurrentTimestamp()) {}

    void AddResult(const BenchmarkResult& result) {
        results_.push_back(result);
    }

    bool GenerateHTML(const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return false;
        }

        file << R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>)" << title_ << R"(</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 { margin: 0 0 10px 0; }
        .header .timestamp { opacity: 0.9; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #667eea;
        }
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        .tier-section {
            background: white;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .tier-header {
            background: #667eea;
            color: white;
            padding: 15px 20px;
            font-weight: bold;
            text-transform: uppercase;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #555;
        }
        tr:hover { background: #f8f9fa; }
        .success { color: #28a745; }
        .failure { color: #dc3545; }
        .metric { font-family: 'Courier New', monospace; }
        .ci { color: #666; font-size: 0.9em; }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .comparison-bar {
            display: flex;
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }
        .comparison-bar .sovereign {
            background: #667eea;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.85em;
        }
        .comparison-bar .ollama {
            background: #764ba2;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.85em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>)" << title_ << R"(</h1>
        <div class="timestamp">Generated: )" << timestamp_ << R"(</div>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Total Benchmarks</h3>
            <div class="value">)" << results_.size() << R"(</div>
        </div>
        <div class="summary-card">
            <h3>Passed</h3>
            <div class="value" style="color: #28a745;">)" << CountSuccess() << R"(</div>
        </div>
        <div class="summary-card">
            <h3>Failed</h3>
            <div class="value" style="color: #dc3545;">)" << CountFailures() << R"(</div>
        </div>
        <div class="summary-card">
            <h3>Success Rate</h3>
            <div class="value">)" << std::fixed << std::setprecision(1) 
               << (results_.empty() ? 0.0 : (CountSuccess() * 100.0 / results_.size())) 
               << "%</div>
        </div>
    </div>

    <div class="chart-container">
        <h2>Performance Overview</h2>
        <p>Mean latency across all benchmarks (lower is better)</p>
        <div id="latency-chart"></div>
    </div>

    <h2>Detailed Results</h2>
)";

        // Group by tier
        std::map<std::string, std::vector<BenchmarkResult>> by_tier;
        for (const auto& result : results_) {
            by_tier[result.tier].push_back(result);
        }

        for (const auto& [tier, tier_results] : by_tier) {
            file << R"(
    <div class="tier-section">
        <div class="tier-header">)" << tier << R"(</div>
        <table>
            <thead>
                <tr>
                    <th>Benchmark</th>
                    <th>Status</th>
                    <th>Latency (ms)</th>
                    <th>Throughput (TPS)</th>
                    <th>Error Rate</th>
                </tr>
            </thead>
            <tbody>
)";
            for (const auto& result : tier_results) {
                file << R"(
                <tr>
                    <td>)" << result.name << R"(</td>
                    <td class=")" << (result.success ? "success">✓ Success" : "failure">✗ Failed") << R"(</td>
                    <td class="metric">)" << std::fixed << std::setprecision(2) << result.latency_ms.mean
                       << R"( <span class="ci">±)" << result.latency_ms.ci_half_width << R"(</span></td>
                    <td class="metric">)" << result.throughput_tps.mean << R"(</td>
                    <td>)" << std::setprecision(1) << (result.error_rate * 100) << "%</td>
                </tr>
)";
            }
            file << R"(
            </tbody>
        </table>
    </div>
)";
        }

        file << R"(
</body>
</html>
)";

        file.close();
        std::cout << "[ReportGenerator] HTML report saved to: " << filename << std::endl;
        return true;
    }

    bool GenerateMarkdown(const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return false;
        }

        file << "# " << title_ << "\n\n";
        file << "**Generated:** " << timestamp_ << "\n\n";

        // Summary
        file << "## Summary\n\n";
        file << "| Metric | Value |\n";
        file << "|--------|-------|\n";
        file << "| Total Benchmarks | " << results_.size() << " |\n";
        file << "| Passed | " << CountSuccess() << " |\n";
        file << "| Failed | " << CountFailures() << " |\n";
        file << "| Success Rate | " << std::fixed << std::setprecision(1)
             << (results_.empty() ? 0.0 : (CountSuccess() * 100.0 / results_.size())) << "% |\n\n";

        // Results by tier
        std::map<std::string, std::vector<BenchmarkResult>> by_tier;
        for (const auto& result : results_) {
            by_tier[result.tier].push_back(result);
        }

        for (const auto& [tier, tier_results] : by_tier) {
            file << "## " << tier << "\n\n";
            file << "| Benchmark | Status | Latency (ms) | Throughput (TPS) | Error Rate |\n";
            file << "|-----------|--------|--------------|------------------|------------|\n";
            
            for (const auto& result : tier_results) {
                file << "| " << result.name << " | "
                     << (result.success ? "✓ Pass" : "✗ Fail") << " | "
                     << std::fixed << std::setprecision(2) << result.latency_ms.mean << " ± "
                     << result.latency_ms.ci_half_width << " | "
                     << result.throughput_tps.mean << " | "
                     << std::setprecision(1) << (result.error_rate * 100) << "% |\n";
            }
            file << "\n";
        }

        file.close();
        std::cout << "[ReportGenerator] Markdown report saved to: " << filename << std::endl;
        return true;
    }

    bool GenerateJSON(const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return false;
        }

        file << "{\n";
        file << "  \"title\": \"" << title_ << "\",\n";
        file << "  \"timestamp\": \"" << timestamp_ << "\",\n";
        file << "  \"summary\": {\n";
        file << "    \"total\": " << results_.size() << ",\n";
        file << "    \"passed\": " << CountSuccess() << ",\n";
        file << "    \"failed\": " << CountFailures() << "\n";
        file << "  },\n";
        file << "  \"results\": [\n";

        for (size_t i = 0; i < results_.size(); ++i) {
            const auto& r = results_[i];
            file << "    {\n";
            file << "      \"name\": \"" << r.name << "\",\n";
            file << "      \"tier\": \"" << r.tier << "\",\n";
            file << "      \"success\": " << (r.success ? "true" : "false") << ",\n";
            file << "      \"latency_ms\": {\n";
            file << "        \"mean\": " << r.latency_ms.mean << ",\n";
            file << "        \"std_dev\": " << r.latency_ms.std_dev << ",\n";
            file << "        \"ci_95\": " << r.latency_ms.ci_half_width << "\n";
            file << "      },\n";
            file << "      \"throughput_tps\": " << r.throughput_tps.mean << ",\n";
            file << "      \"error_rate\": " << r.error_rate << "\n";
            file << "    }";
            if (i < results_.size() - 1) file << ",";
            file << "\n";
        }

        file << "  ]\n";
        file << "}\n";

        file.close();
        std::cout << "[ReportGenerator] JSON report saved to: " << filename << std::endl;
        return true;
    }

    void PrintConsoleReport() {
        std::cout << "\n" << std::string(70, '=') << std::endl;
        std::cout << "  " << title_ << std::endl;
        std::cout << "  " << timestamp_ << std::endl;
        std::cout << std::string(70, '=') << std::endl;

        // Group by tier
        std::map<std::string, std::vector<BenchmarkResult>> by_tier;
        for (const auto& result : results_) {
            by_tier[result.tier].push_back(result);
        }

        for (const auto& [tier, tier_results] : by_tier) {
            std::cout << "\n[" << tier << "]" << std::endl;
            std::cout << std::string(70, '-') << std::endl;
            std::cout << std::left << std::setw(25) << "Benchmark"
                      << std::setw(10) << "Status"
                      << std::setw(20) << "Latency (ms)"
                      << std::setw(15) << "Throughput"
                      << std::endl;
            std::cout << std::string(70, '-') << std::endl;

            for (const auto& result : tier_results) {
                std::cout << std::left << std::setw(25) << result.name
                          << std::setw(10) << (result.success ? "✓ PASS" : "✗ FAIL")
                          << std::fixed << std::setprecision(1)
                          << std::setw(15) << result.latency_ms.mean
                          << "±" << std::setw(3) << result.latency_ms.ci_half_width
                          << std::setw(15) << result.throughput_tps.mean
                          << std::endl;
            }
        }

        std::cout << "\n" << std::string(70, '=') << std::endl;
        std::cout << "Summary: " << CountSuccess() << "/" << results_.size() 
                  << " benchmarks passed" << std::endl;
        std::cout << std::string(70, '=') << std::endl;
    }

private:
    std::string title_;
    std::string timestamp_;
    std::vector<BenchmarkResult> results_;

    size_t CountSuccess() const {
        return std::count_if(results_.begin(), results_.end(),
            [](const BenchmarkResult& r) { return r.success; });
    }

    size_t CountFailures() const {
        return std::count_if(results_.begin(), results_.end(),
            [](const BenchmarkResult& r) { return !r.success; });
    }

    std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

} // namespace Benchmark
