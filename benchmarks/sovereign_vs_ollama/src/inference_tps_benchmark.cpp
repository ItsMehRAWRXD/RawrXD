// inference_tps_benchmark.cpp
// Tier 1: Inference TPS Benchmark with Statistical Rigor
//
// Measures: Prompt TPS, Decode TPS, TTFT, End-to-end latency
// Protocol: 5 warmup runs, 30 measured runs, seed 42, temp 0
// Output: Mean ± 95% CI for all metrics

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include "backends/ollama_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>

namespace Benchmark {

class InferenceTPSBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string quantization = "Q4_K_M";
        std::string prompt = "Explain the concept of machine learning in simple terms.";
        int max_tokens = 256;
        float temperature = 0.0f;
        int seed = 42;
        int warmup_runs = 5;
        int measured_runs = 30;
    };

    struct Results {
        StatisticalSummary prompt_tps;
        StatisticalSummary decode_tps;
        StatisticalSummary ttft_ms;
        StatisticalSummary total_latency_ms;
        StatisticalSummary tokens_generated;
        
        bool success = false;
        std::string error_message;
    };

    explicit InferenceTPSBenchmark(const Config& config = Config()) 
        : config_(config) {}

    // Run against Sovereign backend
    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[InferenceTPS] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Sovereign backend not available at " + base_url;
            return results;
        }
        
        return RunBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    // Run against Ollama backend
    Results RunOllama(const std::string& base_url = "http://localhost:11434") {
        std::cout << "[InferenceTPS] Testing Ollama backend...\n";
        
        Backends::OllamaAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Ollama backend not available at " + base_url;
            return results;
        }
        
        return RunBenchmark([&adapter](const Backends::InferenceRequest& req) {
            Backends::OllamaGenerateRequest ollama_req;
            ollama_req.model = req.model;
            ollama_req.prompt = req.prompt;
            ollama_req.temperature = req.temperature;
            ollama_req.num_predict = req.max_tokens;
            ollama_req.seed = req.seed;
            
            auto ollama_result = adapter.Generate(ollama_req);
            return adapter.ToInferenceResult(ollama_result);
        });
    }

    // Print formatted results
    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "Inference TPS Results: " << backend_name << "\n";
        std::cout << std::string(60, '=') << "\n\n";
        
        if (!results.success) {
            std::cout << "FAILED: " << results.error_message << "\n";
            return;
        }
        
        auto print_metric = [](const std::string& name, const StatisticalSummary& s) {
            std::cout << std::left << std::setw(20) << name << ": "
                      << std::fixed << std::setprecision(2)
                      << s.mean << " (±" << s.ci_half_width << " 95% CI)"
                      << " [n=" << s.sample_count << "]\n";
            std::cout << std::setw(24) << " " << "  min=" << s.min 
                      << ", max=" << s.max 
                      << ", p95=" << s.p95 << "\n\n";
        };
        
        print_metric("Prompt TPS", results.prompt_tps);
        print_metric("Decode TPS", results.decode_tps);
        print_metric("TTFT (ms)", results.ttft_ms);
        print_metric("Total Latency (ms)", results.total_latency_ms);
        print_metric("Tokens Generated", results.tokens_generated);
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunBenchmark(BackendFunc backend_call) {
        Results results;
        
        // Prepare request
        Backends::InferenceRequest request;
        request.model = config_.model;
        request.prompt = config_.prompt;
        request.temperature = config_.temperature;
        request.max_tokens = config_.max_tokens;
        request.seed = config_.seed;
        
        // Warmup phase
        std::cout << "  Warmup phase (" << config_.warmup_runs << " runs)...\n";
        for (int i = 0; i < config_.warmup_runs; ++i) {
            auto result = backend_call(request);
            if (!result.success) {
                results.error_message = "Warmup failed: " + result.error_message;
                return results;
            }
        }
        
        // Measurement phase
        std::cout << "  Measurement phase (" << config_.measured_runs << " runs)...\n";
        std::vector<double> prompt_tps_samples;
        std::vector<double> decode_tps_samples;
        std::vector<double> ttft_samples;
        std::vector<double> latency_samples;
        std::vector<double> tokens_samples;
        
        for (int i = 0; i < config_.measured_runs; ++i) {
            auto result = backend_call(request);
            
            if (!result.success) {
                results.error_message = "Measurement failed at run " + std::to_string(i) 
                                      + ": " + result.error_message;
                return results;
            }
            
            // Calculate prompt TPS (if prompt tokens known)
            // For now, estimate based on prompt length
            int prompt_tokens = EstimateTokenCount(config_.prompt);
            double prompt_time_ms = result.time_to_first_token_ms * 0.3; // Approximate
            if (prompt_time_ms > 0) {
                prompt_tps_samples.push_back(prompt_tokens / (prompt_time_ms / 1000.0));
            }
            
            // Decode TPS
            if (result.tokens_per_second > 0) {
                decode_tps_samples.push_back(result.tokens_per_second);
            }
            
            // TTFT
            if (result.time_to_first_token_ms > 0) {
                ttft_samples.push_back(result.time_to_first_token_ms);
            }
            
            // Total latency
            if (result.total_latency_ms > 0) {
                latency_samples.push_back(result.total_latency_ms);
            }
            
            // Tokens generated
            if (result.tokens_generated > 0) {
                tokens_samples.push_back(result.tokens_generated);
            }
            
            // Progress indicator
            if ((i + 1) % 10 == 0) {
                std::cout << "    " << (i + 1) << "/" << config_.measured_runs << " complete\n";
            }
        }
        
        // Calculate statistics
        results.prompt_tps = CalculateStatistics(prompt_tps_samples);
        results.decode_tps = CalculateStatistics(decode_tps_samples);
        results.ttft_ms = CalculateStatistics(ttft_samples);
        results.total_latency_ms = CalculateStatistics(latency_samples);
        results.tokens_generated = CalculateStatistics(tokens_samples);
        results.success = true;
        
        return results;
    }

    StatisticalSummary CalculateStatistics(const std::vector<double>& samples) {
        StatisticalSummary summary;
        if (samples.empty()) return summary;
        
        summary.sample_count = static_cast<uint32_t>(samples.size());
        
        // Calculate mean
        summary.mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        
        // Calculate min/max
        auto [min_it, max_it] = std::minmax_element(samples.begin(), samples.end());
        summary.min = *min_it;
        summary.max = *max_it;
        
        // Calculate standard deviation
        double variance = 0.0;
        for (double s : samples) {
            variance += (s - summary.mean) * (s - summary.mean);
        }
        variance /= samples.size();
        summary.std_dev = std::sqrt(variance);
        
        // Calculate percentiles (requires sorting)
        std::vector<double> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        
        summary.median = sorted[sorted.size() / 2];
        summary.p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
        summary.p99 = sorted[static_cast<size_t>(sorted.size() * 0.99)];
        
        // Calculate 95% CI (using t-distribution approximation)
        // For 95% CI with n=30, t ≈ 2.045
        double t_value = 2.045;
        summary.ci_half_width = t_value * (summary.std_dev / std::sqrt(samples.size()));
        summary.ci_lower = summary.mean - summary.ci_half_width;
        summary.ci_upper = summary.mean + summary.ci_half_width;
        
        return summary;
    }

    int EstimateTokenCount(const std::string& text) {
        // Rough estimate: ~4 characters per token for English
        return static_cast<int>(text.length() / 4.0);
    }
};

// Standalone runner for this benchmark
void RunInferenceTPSBenchmark(const std::string& backend = "sovereign") {
    InferenceTPSBenchmark benchmark;
    
    InferenceTPSBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else if (backend == "ollama") {
        results = benchmark.RunOllama();
    } else {
        std::cout << "Unknown backend: " << backend << "\n";
        return;
    }
    
    InferenceTPSBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
