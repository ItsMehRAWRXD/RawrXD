// tool_use_benchmark.cpp
// Tier 2: Tool Use Benchmark
//
// Measures: Tool execution correctness and latency
// Tools: File read, file write, shell exec, grep search, semantic search
// Output: Execution time, success rate, correct usage rate

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <functional>

namespace Benchmark {

class ToolUseBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        float temperature = 0.0f;
        int seed = 42;
        int measured_runs = 30;
        
        struct Tool {
            std::string name;
            std::string description;
            std::string test_prompt;
            std::function<bool(const std::string&)> validator;
        };
    };

    struct ToolResult {
        std::string tool_name;
        StatisticalSummary execution_time_ms;
        double success_rate;
        double correct_usage_rate;
        bool success = false;
    };

    struct Results {
        std::vector<ToolResult> tool_results;
        double overall_success_rate;
        double overall_correct_usage;
        bool success = false;
    };

    explicit ToolUseBenchmark(const Config& config = Config())
        : config_(config) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[ToolUse] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunToolBenchmark([&adapter](const std::string& prompt) {
            Backends::InferenceRequest req;
            req.model = "phi-4";
            req.prompt = prompt;
            req.temperature = 0.0f;
            req.max_tokens = 256;
            return adapter.RunInference(req);
        });
    }

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Tool Use Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        std::cout << std::left << std::setw(20) << "Tool"
                  << std::setw(18) << "Time (ms)"
                  << std::setw(15) << "Success"
                  << std::setw(15) << "Correct Use"
                  << "\n";
        std::cout << std::string(70, '-') << "\n";

        for (const auto& tool : results.tool_results) {
            if (!tool.success) continue;
            
            std::cout << std::left << std::setw(20) << tool.tool_name
                      << std::fixed << std::setprecision(1)
                      << std::setw(18) << tool.execution_time_ms.mean
                      << std::setw(14) << (tool.success_rate * 100) << "%"
                      << std::setw(14) << (tool.correct_usage_rate * 100) << "%"
                      << "\n";
        }
        
        std::cout << "\nOverall Success Rate: " << (results.overall_success_rate * 100) << "%\n";
        std::cout << "Overall Correct Usage: " << (results.overall_correct_usage * 100) << "%\n";
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunToolBenchmark(BackendFunc backend_call) {
        Results results;
        
        // Define tool tests
        std::vector<std::pair<std::string, std::string>> tool_tests = {
            {"file_read", "Read the contents of /etc/passwd and show the first 5 lines."},
            {"file_write", "Write 'Hello World' to /tmp/test_file.txt."},
            {"shell_exec", "Execute 'ls -la' and show the output."},
            {"grep_search", "Search for 'function' in all .js files in the current directory."},
            {"semantic_search", "Find documents related to machine learning in the knowledge base."}
        };
        
        for (const auto& [tool_name, prompt] : tool_tests) {
            std::cout << "  Testing tool: " << tool_name << "...\n";
            
            ToolResult tool_result;
            tool_result.tool_name = tool_name;
            
            std::vector<double> time_samples;
            int successes = 0;
            int correct_usage = 0;
            
            for (int i = 0; i < config_.measured_runs; ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                
                auto inference_result = backend_call(prompt);
                
                auto end = std::chrono::high_resolution_clock::now();
                double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
                
                if (inference_result.success) {
                    time_samples.push_back(elapsed_ms);
                    successes++;
                    
                    // Check if tool was used correctly
                    if (ValidateToolUsage(tool_name, inference_result.generated_text)) {
                        correct_usage++;
                    }
                }
            }
            
            if (!time_samples.empty()) {
                tool_result.execution_time_ms = CalculateStatistics(time_samples);
                tool_result.success_rate = static_cast<double>(successes) / config_.measured_runs;
                tool_result.correct_usage_rate = static_cast<double>(correct_usage) / successes;
                tool_result.success = true;
            }
            
            results.tool_results.push_back(tool_result);
        }
        
        // Calculate overall metrics
        double total_success = 0;
        double total_correct = 0;
        for (const auto& tool : results.tool_results) {
            total_success += tool.success_rate;
            total_correct += tool.correct_usage_rate;
        }
        
        if (!results.tool_results.empty()) {
            results.overall_success_rate = total_success / results.tool_results.size();
            results.overall_correct_usage = total_correct / results.tool_results.size();
            results.success = true;
        }
        
        return results;
    }

    bool ValidateToolUsage(const std::string& tool_name, const std::string& output) {
        std::string lower_output = output;
        std::transform(lower_output.begin(), lower_output.end(), lower_output.begin(), ::tolower);
        
        if (tool_name == "file_read") {
            return lower_output.find("read") != std::string::npos ||
                   lower_output.find("cat") != std::string::npos ||
                   lower_output.find("content") != std::string::npos;
        } else if (tool_name == "file_write") {
            return lower_output.find("write") != std::string::npos ||
                   lower_output.find("echo") != std::string::npos ||
                   lower_output.find("save") != std::string::npos;
        } else if (tool_name == "shell_exec") {
            return lower_output.find("execute") != std::string::npos ||
                   lower_output.find("run") != std::string::npos ||
                   lower_output.find("command") != std::string::npos;
        } else if (tool_name == "grep_search") {
            return lower_output.find("search") != std::string::npos ||
                   lower_output.find("find") != std::string::npos ||
                   lower_output.find("grep") != std::string::npos;
        } else if (tool_name == "semantic_search") {
            return lower_output.find("search") != std::string::npos ||
                   lower_output.find("find") != std::string::npos ||
                   lower_output.find("semantic") != std::string::npos;
        }
        
        return false;
    }

    StatisticalSummary CalculateStatistics(const std::vector<double>& samples) {
        StatisticalSummary summary;
        if (samples.empty()) return summary;
        
        summary.sample_count = static_cast<uint32_t>(samples.size());
        summary.mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        
        auto [min_it, max_it] = std::minmax_element(samples.begin(), samples.end());
        summary.min = *min_it;
        summary.max = *max_it;
        
        double variance = 0.0;
        for (double s : samples) {
            variance += (s - summary.mean) * (s - summary.mean);
        }
        variance /= samples.size();
        summary.std_dev = std::sqrt(variance);
        
        std::vector<double> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        summary.median = sorted[sorted.size() / 2];
        summary.p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
        
        double t_value = 2.045;
        summary.ci_half_width = t_value * (summary.std_dev / std::sqrt(samples.size()));
        summary.ci_lower = summary.mean - summary.ci_half_width;
        summary.ci_upper = summary.mean + summary.ci_half_width;
        
        return summary;
    }
};

void RunToolUseBenchmark(const std::string& backend = "sovereign") {
    ToolUseBenchmark benchmark;
    
    ToolUseBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else {
        std::cout << "Tool use benchmark requires Sovereign backend\n";
        return;
    }
    
    ToolUseBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
