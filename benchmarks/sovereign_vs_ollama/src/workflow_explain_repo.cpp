// workflow_explain_repo.cpp
// Developer Workflow: Explain Repository Benchmark
//
// Task: Provide high-level overview of codebase structure and purpose
// Measures: Time, quality, correctness

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <regex>

namespace Benchmark {

class WorkflowExplainRepoBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        float temperature = 0.0f;
        int seed = 42;
        int measured_runs = 30;
        
        // Repository context (simulated)
        std::string repo_name = "RawrXD";
        std::string repo_structure = R"(
Project: RawrXD - AI-Powered Development Environment
Structure:
- src/          Core runtime and inference engine
- include/      Public API headers
- benchmarks/   Performance testing suite
- tests/        Unit and integration tests
- docs/         Documentation
Key Features:
- Sovereign runtime for local AI inference
- Agentic capabilities for autonomous coding
- Swarm coordination for multi-agent tasks
- SEG (Self-Evolving Graph) for execution planning
)";
    };

    struct Results {
        StatisticalSummary wall_clock_time_ms;
        StatisticalSummary model_time_ms;
        double completion_rate;
        double quality_score;
        double correctness_score;
        int human_interventions;
        bool success = false;
    };

    explicit WorkflowExplainRepoBenchmark(const Config& config = Config())
        : config_(config) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[Workflow:ExplainRepo] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunWorkflowBenchmark([&adapter](const std::string& prompt) {
            Backends::InferenceRequest req;
            req.model = "phi-4";
            req.prompt = prompt;
            req.temperature = 0.0f;
            req.max_tokens = 512;
            return adapter.RunInference(req);
        });
    }

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Workflow: Explain Repository Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        std::cout << "Wall Clock Time: " << results.wall_clock_time_ms.mean << " ms (±"
                  << results.wall_clock_time_ms.ci_half_width << " 95% CI)\n";
        std::cout << "Model Time: " << results.model_time_ms.mean << " ms\n";
        std::cout << "Completion Rate: " << (results.completion_rate * 100) << "%\n";
        std::cout << "Quality Score: " << (results.quality_score * 100) << "%\n";
        std::cout << "Correctness Score: " << (results.correctness_score * 100) << "%\n";
        std::cout << "Human Interventions: " << results.human_interventions << "\n";
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunWorkflowBenchmark(BackendFunc backend_call) {
        Results results;
        
        std::vector<double> wall_times;
        std::vector<double> model_times;
        int completions = 0;
        double total_quality = 0;
        double total_correctness = 0;
        int interventions = 0;

        std::string prompt = "Explain the purpose and structure of this repository:\n\n" + config_.repo_structure;

        std::cout << "  Running " << config_.measured_runs << " workflow iterations...\n";

        for (int i = 0; i < config_.measured_runs; ++i) {
            auto wall_start = std::chrono::high_resolution_clock::now();
            
            auto inference_result = backend_call(prompt);
            
            auto wall_end = std::chrono::high_resolution_clock::now();
            double wall_ms = std::chrono::duration<double, std::milli>(wall_end - wall_start).count();

            if (inference_result.success) {
                wall_times.push_back(wall_ms);
                model_times.push_back(inference_result.total_latency_ms);
                
                // Check completion
                if (inference_result.generated_text.length() > 50) {
                    completions++;
                }
                
                // Score quality
                double quality = ScoreQuality(inference_result.generated_text);
                total_quality += quality;
                
                // Score correctness
                double correctness = ScoreCorrectness(inference_result.generated_text);
                total_correctness += correctness;
                
                // Check if human intervention needed
                if (quality < 0.5) {
                    interventions++;
                }
            }

            if ((i + 1) % 10 == 0) {
                std::cout << "    " << (i + 1) << "/" << config_.measured_runs << " complete\n";
            }
        }

        if (!wall_times.empty()) {
            results.wall_clock_time_ms = CalculateStatistics(wall_times);
            results.model_time_ms = CalculateStatistics(model_times);
            results.completion_rate = static_cast<double>(completions) / config_.measured_runs;
            results.quality_score = total_quality / config_.measured_runs;
            results.correctness_score = total_correctness / config_.measured_runs;
            results.human_interventions = interventions;
            results.success = true;
        }

        return results;
    }

    double ScoreQuality(const std::string& output) {
        double score = 0.0;
        
        // Check for structure indicators
        if (output.find("Structure") != std::string::npos || 
            output.find("structure") != std::string::npos) score += 0.2;
        
        if (output.find("Purpose") != std::string::npos ||
            output.find("purpose") != std::string::npos) score += 0.2;
        
        // Check for key terms
        std::vector<std::string> key_terms = {"runtime", "inference", "agent", "swarm", "graph"};
        int terms_found = 0;
        for (const auto& term : key_terms) {
            if (output.find(term) != std::string::npos) terms_found++;
        }
        score += (terms_found / static_cast<double>(key_terms.size())) * 0.4;
        
        // Length check (not too short, not too long)
        if (output.length() > 100 && output.length() < 2000) score += 0.2;
        
        return std::min(1.0, score);
    }

    double ScoreCorrectness(const std::string& output) {
        double score = 0.0;
        
        // Check for correct project name
        if (output.find("RawrXD") != std::string::npos) score += 0.3;
        
        // Check for correct key features
        if (output.find("Sovereign") != std::string::npos ||
            output.find("sovereign") != std::string::npos) score += 0.2;
        
        if (output.find("SEG") != std::string::npos ||
            output.find("Self-Evolving") != std::string::npos) score += 0.2;
        
        if (output.find("swarm") != std::string::npos) score += 0.15;
        
        if (output.find("agent") != std::string::npos) score += 0.15;
        
        return std::min(1.0, score);
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

void RunWorkflowExplainRepoBenchmark(const std::string& backend = "sovereign") {
    WorkflowExplainRepoBenchmark benchmark;
    
    WorkflowExplainRepoBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else {
        std::cout << "Workflow benchmark requires Sovereign backend\n";
        return;
    }
    
    WorkflowExplainRepoBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
