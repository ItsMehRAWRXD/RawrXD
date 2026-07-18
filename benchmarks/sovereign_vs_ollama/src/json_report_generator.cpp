// json_report_generator.cpp
// Batch 5: JSON Report Generator
//
// Generates machine-readable JSON reports for CI/CD integration
// Features: Structured output, historical tracking, comparison data
// Output: JSON files compatible with CI systems and dashboards

#include "benchmark_tiers.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

namespace Benchmark {

class JSONReportGenerator {
public:
    struct ReportConfig {
        std::string output_path = "benchmark_report.json";
        std::string suite_name = "RawrXD Benchmark Suite";
        std::string backend_name = "sovereign";
        bool include_raw_samples = false;
        bool pretty_print = true;
    };

    struct BenchmarkEntry {
        std::string name;
        std::string tier;
        std::string category;
        bool passed;
        double duration_seconds;
        StatisticalSummary metrics;
        std::map<std::string, double> custom_metrics;
        std::string error_message;
    };

    struct SuiteReport {
        std::string timestamp;
        std::string version = "1.0.0";
        std::string backend;
        std::vector<BenchmarkEntry> benchmarks;
        int total_count = 0;
        int passed_count = 0;
        int failed_count = 0;
        double total_duration_seconds = 0;
        bool overall_success = false;
    };

    explicit JSONReportGenerator(const ReportConfig& config = ReportConfig())
        : config_(config) {}

    void Generate(const SuiteReport& report) {
        std::ofstream file(config_.output_path);
        if (!file.is_open()) {
            std::cerr << "Failed to open output file: " << config_.output_path << "\n";
            return;
        }

        if (config_.pretty_print) {
            WritePrettyJSON(file, report);
        } else {
            WriteCompactJSON(file, report);
        }

        std::cout << "JSON report written to: " << config_.output_path << "\n";
    }

    std::string GenerateString(const SuiteReport& report) {
        std::ostringstream oss;
        if (config_.pretty_print) {
            WritePrettyJSON(oss, report);
        } else {
            WriteCompactJSON(oss, report);
        }
        return oss.str();
    }

    // Helper to create a report from benchmark results
    static SuiteReport CreateReport(const std::string& backend,
                                   const std::vector<BenchmarkResult>& results,
                                   double total_duration) {
        SuiteReport report;
        
        // Generate timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
        report.timestamp = ss.str();
        
        report.backend = backend;
        report.total_duration_seconds = total_duration;
        
        for (const auto& result : results) {
            BenchmarkEntry entry;
            entry.name = result.name;
            entry.tier = result.tier;
            entry.category = InferCategory(result.name);
            entry.passed = result.passed;
            entry.duration_seconds = result.duration_seconds;
            entry.error_message = result.error_message;
            
            report.benchmarks.push_back(entry);
            report.total_count++;
            
            if (entry.passed) {
                report.passed_count++;
            } else {
                report.failed_count++;
            }
        }
        
        report.overall_success = (report.failed_count == 0);
        return report;
    }

private:
    ReportConfig config_;

    template<typename Stream>
    void WritePrettyJSON(Stream& stream, const SuiteReport& report) {
        stream << "{\n";
        stream << "  \"metadata\": {\n";
        stream << "    \"version\": \"" << report.version << "\",\n";
        stream << "    \"timestamp\": \"" << EscapeJSON(report.timestamp) << "\",\n";
        stream << "    \"backend\": \"" << EscapeJSON(report.backend) << "\",\n";
        stream << "    \"suite_name\": \"" << EscapeJSON(config_.suite_name) << "\"\n";
        stream << "  },\n";
        
        stream << "  \"summary\": {\n";
        stream << "    \"total_benchmarks\": " << report.total_count << ",\n";
        stream << "    \"passed\": " << report.passed_count << ",\n";
        stream << "    \"failed\": " << report.failed_count << ",\n";
        stream << "    \"success_rate\": " << std::fixed << std::setprecision(2)
               << (report.total_count > 0 ? 100.0 * report.passed_count / report.total_count : 0)
               << ",\n";
        stream << "    \"total_duration_seconds\": " << report.total_duration_seconds << ",\n";
        stream << "    \"overall_success\": " << (report.overall_success ? "true" : "false") << "\n";
        stream << "  },\n";
        
        stream << "  \"benchmarks\": [\n";
        
        for (size_t i = 0; i < report.benchmarks.size(); ++i) {
            const auto& bench = report.benchmarks[i];
            stream << "    {\n";
            stream << "      \"name\": \"" << EscapeJSON(bench.name) << "\",\n";
            stream << "      \"tier\": \"" << EscapeJSON(bench.tier) << "\",\n";
            stream << "      \"category\": \"" << EscapeJSON(bench.category) << "\",\n";
            stream << "      \"passed\": " << (bench.passed ? "true" : "false") << ",\n";
            stream << "      \"duration_seconds\": " << bench.duration_seconds;
            
            if (bench.passed) {
                stream << ",\n";
                stream << "      \"metrics\": {\n";
                stream << "        \"mean\": " << bench.metrics.mean << ",\n";
                stream << "        \"median\": " << bench.metrics.median << ",\n";
                stream << "        \"std_dev\": " << bench.metrics.std_dev << ",\n";
                stream << "        \"min\": " << bench.metrics.min << ",\n";
                stream << "        \"max\": " << bench.metrics.max << ",\n";
                stream << "        \"p95\": " << bench.metrics.p95 << ",\n";
                stream << "        \"sample_count\": " << bench.metrics.sample_count << ",\n";
                stream << "        \"ci_95_lower\": " << (bench.metrics.mean - bench.metrics.ci_half_width) << ",\n";
                stream << "        \"ci_95_upper\": " << (bench.metrics.mean + bench.metrics.ci_half_width) << "\n";
                stream << "      }";
            } else {
                stream << ",\n";
                stream << "      \"error\": \"" << EscapeJSON(bench.error_message) << "\"";
            }
            
            // Custom metrics
            if (!bench.custom_metrics.empty()) {
                stream << ",\n";
                stream << "      \"custom_metrics\": {\n";
                size_t cm_idx = 0;
                for (const auto& [key, value] : bench.custom_metrics) {
                    stream << "        \"" << EscapeJSON(key) << "\": " << value;
                    if (++cm_idx < bench.custom_metrics.size()) stream << ",";
                    stream << "\n";
                }
                stream << "      }";
            }
            
            stream << "\n    }";
            if (i + 1 < report.benchmarks.size()) stream << ",";
            stream << "\n";
        }
        
        stream << "  ]\n";
        stream << "}\n";
    }

    template<typename Stream>
    void WriteCompactJSON(Stream& stream, const SuiteReport& report) {
        // Compact version without pretty printing
        stream << "{";
        stream << "\"metadata\":{";
        stream << "\"version\":\"" << report.version << "\",";
        stream << "\"timestamp\":\"" << EscapeJSON(report.timestamp) << "\",";
        stream << "\"backend\":\"" << EscapeJSON(report.backend) << "\"},";
        
        stream << "\"summary\":{";
        stream << "\"total\":" << report.total_count << ",";
        stream << "\"passed\":" << report.passed_count << ",";
        stream << "\"failed\":" << report.failed_count << ",";
        stream << "\"success\":" << (report.overall_success ? "true" : "false") << "},";
        
        stream << "\"benchmarks\":[";
        for (size_t i = 0; i < report.benchmarks.size(); ++i) {
            const auto& bench = report.benchmarks[i];
            stream << "{";
            stream << "\"name\":\"" << EscapeJSON(bench.name) << "\",";
            stream << "\"passed\":" << (bench.passed ? "true" : "false") << "}";
            if (i + 1 < report.benchmarks.size()) stream << ",";
        }
        stream << "]}";
    }

    static std::string EscapeJSON(const std::string& input) {
        std::string output;
        output.reserve(input.size());
        for (char c : input) {
            switch (c) {
                case '"': output += "\\\""; break;
                case '\\': output += "\\\\"; break;
                case '\b': output += "\\b"; break;
                case '\f': output += "\\f"; break;
                case '\n': output += "\\n"; break;
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;
                default:
                    if (c >= 0x20 && c <= 0x7E) {
                        output += c;
                    } else {
                        char buf[7];
                        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                        output += buf;
                    }
            }
        }
        return output;
    }

    static std::string InferCategory(const std::string& benchmark_name) {
        if (benchmark_name.find("inference") != std::string::npos ||
            benchmark_name.find("latency") != std::string::npos ||
            benchmark_name.find("tps") != std::string::npos) {
            return "performance";
        }
        if (benchmark_name.find("memory") != std::string::npos ||
            benchmark_name.find("resource") != std::string::npos) {
            return "resource";
        }
        if (benchmark_name.find("swarm") != std::string::npos ||
            benchmark_name.find("agent") != std::string::npos) {
            return "agentic";
        }
        if (benchmark_name.find("chaos") != std::string::npos ||
            benchmark_name.find("stress") != std::string::npos) {
            return "reliability";
        }
        if (benchmark_name.find("workflow") != std::string::npos) {
            return "workflow";
        }
        return "general";
    }
};

// Convenience function for quick report generation
void GenerateJSONReport(const std::string& output_path,
                       const std::string& backend,
                       const std::vector<BenchmarkResult>& results,
                       double total_duration) {
    JSONReportGenerator::ReportConfig config;
    config.output_path = output_path;
    config.backend_name = backend;
    
    JSONReportGenerator generator(config);
    auto report = JSONReportGenerator::CreateReport(backend, results, total_duration);
    generator.Generate(report);
}

} // namespace Benchmark
