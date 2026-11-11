// determinism_benchmark.cpp
// Tier 4: Determinism Benchmark
//
// Measures: Output repeatability with fixed seed and temperature 0
// Output: Repeatability score, output variance, identical run percentage

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <unordered_map>

namespace Benchmark {

class DeterminismBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string prompt = "What is 2+2? Explain your reasoning.";
        int max_tokens = 128;
        float temperature = 0.0f; // Must be 0 for determinism
        int seed = 42;
        int repeat_count = 100; // Number of identical runs
    };

    struct RunResult {
        std::string output;
        int token_count;
        double latency_ms;
    };

    struct Results {
        int identical_runs;
        int divergent_runs;
        double repeatability_score; // 0-1
        StatisticalSummary output_length_variance;
        StatisticalSummary latency_variance;
        bool deterministic_under_test_conditions;
        std::vector<std::string> unique_outputs;
        bool success = false;
    };

    explicit DeterminismBenchmark(const Config& config = Config())
        : config_(config) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[Determinism] Testing Sovereign backend...\n";
        std::cout << "  Temperature: " << config_.temperature << " (must be 0)\n";
        std::cout << "  Seed: " << config_.seed << "\n";
        std::cout << "  Repeats: " << config_.repeat_count << "\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunDeterminismBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Determinism Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        std::cout << "Identical Runs: " << results.identical_runs << "\n";
        std::cout << "Divergent Runs: " << results.divergent_runs << "\n";
        std::cout << "Repeatability Score: " << (results.repeatability_score * 100) << "%\n";
        std::cout << "Deterministic: " << (results.deterministic_under_test_conditions ? "YES" : "NO") << "\n";
        std::cout << "Unique Outputs: " << results.unique_outputs.size() << "\n";

        if (results.unique_outputs.size() > 1) {
            std::cout << "\nSample Divergent Outputs:\n";
            for (size_t i = 0; i < std::min(size_t(3), results.unique_outputs.size()); ++i) {
                std::cout << "  [" << i << "] " << results.unique_outputs[i].substr(0, 50) << "...\n";
            }
        }
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunDeterminismBenchmark(BackendFunc backend_call) {
        Results results;
        std::vector<RunResult> runs;
        std::unordered_map<std::string, int> output_counts;

        std::cout << "  Running " << config_.repeat_count << " identical requests...\n";

        for (int i = 0; i < config_.repeat_count; ++i) {
            Backends::InferenceRequest request;
            request.model = config_.model;
            request.prompt = config_.prompt;
            request.temperature = config_.temperature;
            request.max_tokens = config_.max_tokens;
            request.seed = config_.seed; // Fixed seed!

            auto result = backend_call(request);

            if (result.success) {
                RunResult run;
                run.output = result.generated_text;
                run.token_count = result.tokens_generated;
                run.latency_ms = result.total_latency_ms;
                
                runs.push_back(run);
                output_counts[run.output]++;
            }

            if ((i + 1) % 10 == 0) {
                std::cout << "    " << (i + 1) << "/" << config_.repeat_count << " complete\n";
            }
        }

        // Analyze results
        if (!runs.empty()) {
            // Find most common output
            std::string most_common_output;
            int max_count = 0;
            
            for (const auto& [output, count] : output_counts) {
                if (count > max_count) {
                    max_count = count;
                    most_common_output = output;
                }
                results.unique_outputs.push_back(output);
            }

            results.identical_runs = max_count;
            results.divergent_runs = runs.size() - max_count;
            results.repeatability_score = static_cast<double>(max_count) / runs.size();
            
            // Calculate variances
            std::vector<double> token_counts;
            std::vector<double> latencies;
            
            for (const auto& run : runs) {
                token_counts.push_back(run.token_count);
                latencies.push_back(run.latency_ms);
            }
            
            results.output_length_variance = CalculateVariance(token_counts);
            results.latency_variance = CalculateVariance(latencies);
            
            // Deterministic if >99% identical
            results.deterministic_under_test_conditions = results.repeatability_score >= 0.99;
            results.success = true;
        }

        return results;
    }

    StatisticalSummary CalculateVariance(const std::vector<double>& samples) {
        StatisticalSummary summary;
        if (samples.size() < 2) return summary;

        summary.sample_count = static_cast<uint32_t>(samples.size());
        summary.mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();

        double variance = 0.0;
        for (double s : samples) {
            variance += (s - summary.mean) * (s - summary.mean);
        }
        variance /= samples.size();
        summary.std_dev = std::sqrt(variance);

        auto [min_it, max_it] = std::minmax_element(samples.begin(), samples.end());
        summary.min = *min_it;
        summary.max = *max_it;

        return summary;
    }
};

void RunDeterminismBenchmark(const std::string& backend = "sovereign") {
    DeterminismBenchmark benchmark;
    
    DeterminismBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else {
        std::cout << "Determinism benchmark requires Sovereign backend\n";
        return;
    }
    
    DeterminismBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
