// planning_task_benchmark.cpp
// Tier 2: Planning Task Benchmark
//
// Measures: Multi-step planning with success metrics
// Tasks: Simple sequence, parallel tasks, conditional branching, error recovery
// Output: Completion time, success rate, plan optimality

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include "backends/ollama_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>

namespace Benchmark {

class PlanningTaskBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        float temperature = 0.0f;
        int seed = 42;
        int measured_runs = 30;
        int max_planning_steps = 20;
        
        struct Task {
            std::string name;
            std::string description;
            std::string expected_output_pattern;
            int expected_steps_min;
            int expected_steps_max;
        };
        
        std::vector<Task> tasks = {
            {
                "simple_sequence",
                "Plan the steps to make a cup of coffee: boil water, grind beans, brew, pour.",
                "step|sequence|order",
                3, 6
            },
            {
                "parallel_tasks",
                "Plan how to prepare a meal where you can chop vegetables while water boils.",
                "parallel|concurrent|simultaneous",
                4, 8
            },
            {
                "conditional_branching",
                "Plan a commute with alternatives: if raining take bus, else bike.",
                "if|condition|branch|alternative",
                3, 7
            },
            {
                "error_recovery",
                "Plan a file backup strategy that handles disk full errors gracefully.",
                "error|exception|recovery|fallback",
                4, 10
            }
        };
    };

    struct TaskResult {
        std::string task_name;
        StatisticalSummary completion_time_ms;
        StatisticalSummary steps_taken;
        double success_rate;
        double optimality_score;
        bool success = false;
    };

    struct Results {
        std::vector<TaskResult> task_results;
        double overall_success_rate;
        double overall_optimality;
        bool success = false;
    };

    explicit PlanningTaskBenchmark(const Config& config = Config())
        : config_(config) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[PlanningTask] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunPlanningBenchmark([&adapter](const std::string& prompt) {
            Backends::InferenceRequest req;
            req.model = "phi-4";
            req.prompt = prompt;
            req.temperature = 0.0f;
            req.max_tokens = 512;
            return adapter.RunInference(req);
        });
    }

    Results RunOllama(const std::string& base_url = "http://localhost:11434") {
        std::cout << "[PlanningTask] Testing Ollama backend...\n";
        
        Backends::OllamaAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunPlanningBenchmark([&adapter](const std::string& prompt) {
            Backends::OllamaGenerateRequest req;
            req.model = "phi3:mini";
            req.prompt = prompt;
            req.temperature = 0.0f;
            req.num_predict = 512;
            
            auto result = adapter.Generate(req);
            return adapter.ToInferenceResult(result);
        });
    }

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Planning Task Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        std::cout << std::left << std::setw(25) << "Task"
                  << std::setw(18) << "Time (ms)"
                  << std::setw(12) << "Success"
                  << std::setw(12) << "Optimality"
                  << "\n";
        std::cout << std::string(70, '-') << "\n";

        for (const auto& task : results.task_results) {
            if (!task.success) continue;
            
            std::cout << std::left << std::setw(25) << task.task_name
                      << std::fixed << std::setprecision(1)
                      << std::setw(18) << task.completion_time_ms.mean
                      << std::setw(11) << (task.success_rate * 100) << "%"
                      << std::setw(11) << (task.optimality_score * 100) << "%"
                      << "\n";
        }
        
        std::cout << "\nOverall Success Rate: " << (results.overall_success_rate * 100) << "%\n";
        std::cout << "Overall Optimality: " << (results.overall_optimality * 100) << "%\n";
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunPlanningBenchmark(BackendFunc backend_call) {
        Results results;
        
        for (const auto& task_config : config_.tasks) {
            std::cout << "  Testing task: " << task_config.name << "...\n";
            
            TaskResult task_result;
            task_result.task_name = task_config.name;
            
            std::vector<double> time_samples;
            std::vector<double> step_samples;
            int successes = 0;
            
            for (int i = 0; i < config_.measured_runs; ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                
                auto inference_result = backend_call(task_config.description);
                
                auto end = std::chrono::high_resolution_clock::now();
                double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
                
                if (inference_result.success) {
                    time_samples.push_back(elapsed_ms);
                    
                    // Analyze output for steps
                    int steps = CountPlanningSteps(inference_result.generated_text);
                    step_samples.push_back(steps);
                    
                    // Check success criteria
                    bool task_success = ValidatePlanningOutput(
                        inference_result.generated_text, 
                        task_config
                    );
                    if (task_success) successes++;
                }
            }
            
            if (!time_samples.empty()) {
                task_result.completion_time_ms = CalculateStatistics(time_samples);
                task_result.steps_taken = CalculateStatistics(step_samples);
                task_result.success_rate = static_cast<double>(successes) / config_.measured_runs;
                task_result.optimality_score = CalculateOptimality(step_samples, task_config);
                task_result.success = true;
            }
            
            results.task_results.push_back(task_result);
        }
        
        // Calculate overall metrics
        double total_success = 0;
        double total_optimality = 0;
        for (const auto& task : results.task_results) {
            total_success += task.success_rate;
            total_optimality += task.optimality_score;
        }
        
        if (!results.task_results.empty()) {
            results.overall_success_rate = total_success / results.task_results.size();
            results.overall_optimality = total_optimality / results.task_results.size();
            results.success = true;
        }
        
        return results;
    }

    int CountPlanningSteps(const std::string& output) {
        // Simple heuristic: count numbered items, bullet points, or "step" mentions
        int steps = 0;
        
        // Count numbered items (1., 2., etc.)
        for (int i = 1; i <= 20; ++i) {
            std::string pattern = std::to_string(i) + ".";
            size_t pos = 0;
            while ((pos = output.find(pattern, pos)) != std::string::npos) {
                steps++;
                pos++;
            }
        }
        
        // Count bullet points
        size_t pos = 0;
        while ((pos = output.find("- ", pos)) != std::string::npos) {
            steps++;
            pos++;
        }
        
        // Count "step" mentions
        pos = 0;
        while ((pos = output.find("step", pos)) != std::string::npos) {
            steps++;
            pos++;
        }
        
        return std::max(1, steps); // At least 1 step
    }

    bool ValidatePlanningOutput(const std::string& output, const Config::Task& task) {
        // Check if output contains expected patterns
        std::string lower_output = output;
        std::transform(lower_output.begin(), lower_output.end(), lower_output.begin(), ::tolower);
        
        // Simple pattern matching
        if (task.expected_output_pattern.find("|") != std::string::npos) {
            // Multiple alternatives
            size_t pos = 0;
            std::string token;
            while ((pos = task.expected_output_pattern.find("|")) != std::string::npos) {
                token = task.expected_output_pattern.substr(0, pos);
                if (lower_output.find(token) != std::string::npos) {
                    return true;
                }
                task.expected_output_pattern.erase(0, pos + 1);
            }
            // Check last token
            if (lower_output.find(task.expected_output_pattern) != std::string::npos) {
                return true;
            }
        } else {
            if (lower_output.find(task.expected_output_pattern) != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }

    double CalculateOptimality(const std::vector<double>& step_samples, const Config::Task& task) {
        if (step_samples.empty()) return 0.0;
        
        double avg_steps = std::accumulate(step_samples.begin(), step_samples.end(), 0.0) 
                          / step_samples.size();
        
        // Optimal is within expected range
        if (avg_steps >= task.expected_steps_min && avg_steps <= task.expected_steps_max) {
            return 1.0;
        }
        
        // Penalize for being outside range
        if (avg_steps < task.expected_steps_min) {
            return avg_steps / task.expected_steps_min;
        } else {
            return task.expected_steps_max / avg_steps;
        }
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

void RunPlanningTaskBenchmark(const std::string& backend = "sovereign") {
    PlanningTaskBenchmark benchmark;
    
    PlanningTaskBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else if (backend == "ollama") {
        results = benchmark.RunOllama();
    } else {
        std::cout << "Unknown backend: " << backend << "\n";
        return;
    }
    
    PlanningTaskBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
