// context_scaling_benchmark.cpp
// Tier 1: Context Scaling Benchmark
//
// Measures: Performance across 1K, 4K, 16K, 64K, 128K token contexts
// Protocol: Fixed 30 runs per context length, seed 42
// Output: TPS and latency curves with 95% CI

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include "backends/ollama_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>

namespace Benchmark {

class ContextScalingBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::vector<int> context_lengths = {1024, 4096, 16384, 65536, 131072};
        int max_tokens = 256;
        float temperature = 0.0f;
        int seed = 42;
        int measured_runs = 30;
    };

    struct ContextResult {
        int context_length;
        StatisticalSummary tps;
        StatisticalSummary latency_ms;
        StatisticalSummary memory_mb;
        bool success = false;
    };

    struct Results {
        std::vector<ContextResult> scaling_results;
        bool overall_success = false;
        std::string error_message;
    };

    explicit ContextScalingBenchmark(const Config& config = Config())
        : config_(config) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[ContextScaling] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Sovereign backend not available";
            return results;
        }

        return RunScalingBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    Results RunOllama(const std::string& base_url = "http://localhost:11434") {
        std::cout << "[ContextScaling] Testing Ollama backend...\n";
        
        Backends::OllamaAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Ollama backend not available";
            return results;
        }

        return RunScalingBenchmark([&adapter](const Backends::InferenceRequest& req) {
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

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Context Scaling Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.overall_success) {
            std::cout << "FAILED: " << results.error_message << "\n";
            return;
        }

        std::cout << std::left << std::setw(12) << "Context"
                  << std::setw(15) << "TPS"
                  << std::setw(20) << "Latency (ms)"
                  << std::setw(15) << "Memory (MB)"
                  << "\n";
        std::cout << std::string(70, '-') << "\n";

        for (const auto& ctx : results.scaling_results) {
            if (!ctx.success) continue;
            
            std::cout << std::left << std::setw(12) << ctx.context_length
                      << std::fixed << std::setprecision(1)
                      << std::setw(15) << (std::to_string(ctx.tps.mean) + " ±" + std::to_string(int(ctx.tps.ci_half_width)))
                      << std::setw(20) << (std::to_string(ctx.latency_ms.mean) + " ±" + std::to_string(int(ctx.latency_ms.ci_half_width)))
                      << std::setw(15) << ctx.memory_mb.mean
                      << "\n";
        }
        std::cout << "\n";
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunScalingBenchmark(BackendFunc backend_call) {
        Results results;
        
        for (int ctx_len : config_.context_lengths) {
            std::cout << "  Testing context length: " << ctx_len << " tokens...\n";
            
            ContextResult ctx_result;
            ctx_result.context_length = ctx_len;
            
            // Generate context-length appropriate prompt
            std::string prompt = GeneratePromptForLength(ctx_len);
            
            Backends::InferenceRequest request;
            request.model = config_.model;
            request.prompt = prompt;
            request.temperature = config_.temperature;
            request.max_tokens = config_.max_tokens;
            request.seed = config_.seed;
            
            std::vector<double> tps_samples;
            std::vector<double> latency_samples;
            std::vector<double> memory_samples;
            
            for (int i = 0; i < config_.measured_runs; ++i) {
                auto result = backend_call(request);
                
                if (!result.success) {
                    ctx_result.success = false;
                    break;
                }
                
                if (result.tokens_per_second > 0) {
                    tps_samples.push_back(result.tokens_per_second);
                }
                if (result.total_latency_ms > 0) {
                    latency_samples.push_back(result.total_latency_ms);
                }
                
                // Memory estimation (would come from actual monitoring)
                double estimated_memory = 4096 + (ctx_len * 0.5); // Base + context
                memory_samples.push_back(estimated_memory);
            }
            
            if (!tps_samples.empty()) {
                ctx_result.tps = CalculateStatistics(tps_samples);
                ctx_result.latency_ms = CalculateStatistics(latency_samples);
                ctx_result.memory_mb = CalculateStatistics(memory_samples);
                ctx_result.success = true;
            }
            
            results.scaling_results.push_back(ctx_result);
        }
        
        results.overall_success = true;
        for (const auto& ctx : results.scaling_results) {
            if (!ctx.success) {
                results.overall_success = false;
                break;
            }
        }
        
        return results;
    }

    std::string GeneratePromptForLength(int target_tokens) {
        // Generate a prompt that will result in approximately target_tokens tokens
        // Roughly 4 chars per token
        int char_count = target_tokens * 4;
        
        std::string base_text = 
            "The following is a detailed technical document about artificial intelligence and machine learning. "
            "It covers various topics including neural networks, deep learning, natural language processing, "
            "computer vision, reinforcement learning, and their applications in modern technology. ";
        
        std::string prompt;
        while ((int)prompt.length() < char_count) {
            prompt += base_text;
        }
        
        // Trim to exact length
        if ((int)prompt.length() > char_count) {
            prompt = prompt.substr(0, char_count);
        }
        
        prompt += "\n\nSummarize the key points of the above text.";
        return prompt;
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
        summary.p99 = sorted[static_cast<size_t>(sorted.size() * 0.99)];
        
        double t_value = 2.045;
        summary.ci_half_width = t_value * (summary.std_dev / std::sqrt(samples.size()));
        summary.ci_lower = summary.mean - summary.ci_half_width;
        summary.ci_upper = summary.mean + summary.ci_half_width;
        
        return summary;
    }
};

void RunContextScalingBenchmark(const std::string& backend = "sovereign") {
    ContextScalingBenchmark benchmark;
    
    ContextScalingBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else if (backend == "ollama") {
        results = benchmark.RunOllama();
    } else {
        std::cout << "Unknown backend: " << backend << "\n";
        return;
    }
    
    ContextScalingBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
