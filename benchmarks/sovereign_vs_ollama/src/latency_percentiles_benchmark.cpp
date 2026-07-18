// latency_percentiles_benchmark.cpp
// Tier 1: Latency Percentiles Benchmark
//
// Measures: P50, P90, P95, P99, P99.9 tail latencies
// Protocol: 1000 requests for accurate tail measurement
// Output: Full latency distribution with percentiles

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include "backends/ollama_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <map>

namespace Benchmark {

class LatencyPercentilesBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string prompt = "Write a haiku about coding.";
        int max_tokens = 64;
        float temperature = 0.0f;
        int seed = 42;
        int total_requests = 1000;
        std::vector<double> percentiles = {0.50, 0.90, 0.95, 0.99, 0.999};
    };

    struct LatencyDistribution {
        std::map<double, double> percentiles; // percentile -> latency_ms
        double mean;
        double std_dev;
        double min;
        double max;
        int total_samples;
        bool success = false;
    };

    struct Results {
        LatencyDistribution ttft_distribution;
        LatencyDistribution total_latency_distribution;
        bool success = false;
        std::string error_message;
    };

    explicit LatencyPercentilesBenchmark(const Config& config = Config())
        : config_(config) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[LatencyPercentiles] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Sovereign backend not available";
            return results;
        }

        return RunPercentileBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    Results RunOllama(const std::string& base_url = "http://localhost:11434") {
        std::cout << "[LatencyPercentiles] Testing Ollama backend...\n";
        
        Backends::OllamaAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Ollama backend not available";
            return results;
        }

        return RunPercentileBenchmark([&adapter](const Backends::InferenceRequest& req) {
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
        std::cout << "Latency Percentiles: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED: " << results.error_message << "\n";
            return;
        }

        // TTFT Distribution
        std::cout << "Time to First Token (TTFT):\n";
        std::cout << std::left << std::setw(12) << "Percentile"
                  << std::setw(15) << "Latency (ms)"
                  << "\n";
        std::cout << std::string(30, '-') << "\n";
        
        for (const auto& [pct, latency] : results.ttft_distribution.percentiles) {
            std::cout << std::left << std::setw(12) << ("P" + std::to_string(int(pct * 100)))
                      << std::fixed << std::setprecision(2) << std::setw(15) << latency
                      << "\n";
        }
        std::cout << std::left << std::setw(12) << "Mean"
                  << std::fixed << std::setprecision(2) << std::setw(15) 
                  << results.ttft_distribution.mean << "\n";
        std::cout << std::left << std::setw(12) << "Min"
                  << std::fixed << std::setprecision(2) << std::setw(15) 
                  << results.ttft_distribution.min << "\n";
        std::cout << std::left << std::setw(12) << "Max"
                  << std::fixed << std::setprecision(2) << std::setw(15) 
                  << results.ttft_distribution.max << "\n\n";

        // Total Latency Distribution
        std::cout << "Total Latency:\n";
        std::cout << std::left << std::setw(12) << "Percentile"
                  << std::setw(15) << "Latency (ms)"
                  << "\n";
        std::cout << std::string(30, '-') << "\n";
        
        for (const auto& [pct, latency] : results.total_latency_distribution.percentiles) {
            std::cout << std::left << std::setw(12) << ("P" + std::to_string(int(pct * 100)))
                      << std::fixed << std::setprecision(2) << std::setw(15) << latency
                      << "\n";
        }
        std::cout << std::left << std::setw(12) << "Mean"
                  << std::fixed << std::setprecision(2) << std::setw(15) 
                  << results.total_latency_distribution.mean << "\n";
        std::cout << std::left << std::setw(12) << "Min"
                  << std::fixed << std::setprecision(2) << std::setw(15) 
                  << results.total_latency_distribution.min << "\n";
        std::cout << std::left << std::setw(12) << "Max"
                  << std::fixed << std::setprecision(2) << std::setw(15) 
                  << results.total_latency_distribution.max << "\n\n";
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunPercentileBenchmark(BackendFunc backend_call) {
        Results results;
        
        std::vector<double> ttft_samples;
        std::vector<double> total_latency_samples;
        
        std::cout << "  Collecting " << config_.total_requests << " latency samples...\n";
        
        for (int i = 0; i < config_.total_requests; ++i) {
            Backends::InferenceRequest request;
            request.model = config_.model;
            request.prompt = config_.prompt;
            request.temperature = config_.temperature;
            request.max_tokens = config_.max_tokens;
            request.seed = config_.seed;
            
            auto result = backend_call(request);
            
            if (!result.success) {
                results.error_message = "Request " + std::to_string(i) + " failed: " + result.error_message;
                return results;
            }
            
            if (result.time_to_first_token_ms > 0) {
                ttft_samples.push_back(result.time_to_first_token_ms);
            }
            if (result.total_latency_ms > 0) {
                total_latency_samples.push_back(result.total_latency_ms);
            }
            
            if ((i + 1) % 100 == 0) {
                std::cout << "    " << (i + 1) << "/" << config_.total_requests << " complete\n";
            }
        }
        
        if (ttft_samples.empty() || total_latency_samples.empty()) {
            results.error_message = "No valid samples collected";
            return results;
        }
        
        results.ttft_distribution = CalculateDistribution(ttft_samples);
        results.total_latency_distribution = CalculateDistribution(total_latency_samples);
        results.success = true;
        
        return results;
    }

    LatencyDistribution CalculateDistribution(const std::vector<double>& samples) {
        LatencyDistribution dist;
        if (samples.empty()) return dist;
        
        dist.total_samples = static_cast<int>(samples.size());
        
        // Calculate mean
        dist.mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        
        // Calculate std dev
        double variance = 0.0;
        for (double s : samples) {
            variance += (s - dist.mean) * (s - dist.mean);
        }
        variance /= samples.size();
        dist.std_dev = std::sqrt(variance);
        
        // Sort for percentiles
        std::vector<double> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        
        dist.min = sorted.front();
        dist.max = sorted.back();
        
        // Calculate requested percentiles
        for (double pct : config_.percentiles) {
            size_t idx = static_cast<size_t>((sorted.size() - 1) * pct);
            dist.percentiles[pct] = sorted[idx];
        }
        
        dist.success = true;
        return dist;
    }
};

void RunLatencyPercentilesBenchmark(const std::string& backend = "sovereign") {
    LatencyPercentilesBenchmark benchmark;
    
    LatencyPercentilesBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else if (backend == "ollama") {
        results = benchmark.RunOllama();
    } else {
        std::cout << "Unknown backend: " << backend << "\n";
        return;
    }
    
    LatencyPercentilesBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
