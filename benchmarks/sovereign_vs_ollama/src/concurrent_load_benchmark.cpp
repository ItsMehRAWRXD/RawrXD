// concurrent_load_benchmark.cpp
// Tier 1: Concurrent Load Benchmark
//
// Measures: Throughput under parallel request load
// Protocol: 1, 4, 8, 16, 32 concurrent requests
// Output: TPS scaling curve with efficiency metrics

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include "backends/ollama_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <thread>
#include <future>
#include <atomic>

namespace Benchmark {

class ConcurrentLoadBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::vector<int> concurrency_levels = {1, 4, 8, 16, 32};
        std::string prompt = "What is the capital of France?";
        int max_tokens = 128;
        float temperature = 0.0f;
        int seed = 42;
        int requests_per_level = 100;
    };

    struct ConcurrencyResult {
        int concurrent_requests;
        StatisticalSummary total_tps;
        StatisticalSummary latency_ms;
        StatisticalSummary throughput_rps; // Requests per second
        double efficiency; // Actual TPS / (single_thread_tps * concurrency)
        bool success = false;
    };

    struct Results {
        std::vector<ConcurrencyResult> load_results;
        bool overall_success = false;
        std::string error_message;
    };

    explicit ConcurrentLoadBenchmark(const Config& config = Config())
        : config_(config) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[ConcurrentLoad] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Sovereign backend not available";
            return results;
        }

        return RunLoadBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    Results RunOllama(const std::string& base_url = "http://localhost:11434") {
        std::cout << "[ConcurrentLoad] Testing Ollama backend...\n";
        
        Backends::OllamaAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Ollama backend not available";
            return results;
        }

        return RunLoadBenchmark([&adapter](const Backends::InferenceRequest& req) {
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
        std::cout << "Concurrent Load Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.overall_success) {
            std::cout << "FAILED: " << results.error_message << "\n";
            return;
        }

        std::cout << std::left << std::setw(10) << "Concurrent"
                  << std::setw(15) << "TPS"
                  << std::setw(18) << "Latency (ms)"
                  << std::setw(12) << "Req/s"
                  << std::setw(12) << "Efficiency"
                  << "\n";
        std::cout << std::string(70, '-') << "\n";

        for (const auto& res : results.load_results) {
            if (!res.success) continue;
            
            std::cout << std::left << std::setw(10) << res.concurrent_requests
                      << std::fixed << std::setprecision(1)
                      << std::setw(15) << res.total_tps.mean
                      << std::setw(18) << res.latency_ms.mean
                      << std::setw(12) << res.throughput_rps.mean
                      << std::setw(11) << (res.efficiency * 100) << "%"
                      << "\n";
        }
        std::cout << "\n";
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunLoadBenchmark(BackendFunc backend_call) {
        Results results;
        
        // First, establish baseline with single request
        std::cout << "  Establishing baseline (1 request)...\n";
        double baseline_tps = 0;
        {
            Backends::InferenceRequest req;
            req.model = config_.model;
            req.prompt = config_.prompt;
            req.temperature = config_.temperature;
            req.max_tokens = config_.max_tokens;
            req.seed = config_.seed;
            
            auto result = backend_call(req);
            if (result.success) {
                baseline_tps = result.tokens_per_second;
            }
        }
        
        std::cout << "  Baseline TPS: " << baseline_tps << "\n\n";
        
        // Test each concurrency level
        for (int concurrency : config_.concurrency_levels) {
            std::cout << "  Testing concurrency: " << concurrency << " requests...\n";
            
            ConcurrencyResult res;
            res.concurrent_requests = concurrency;
            
            std::vector<double> tps_samples;
            std::vector<double> latency_samples;
            std::vector<double> rps_samples;
            
            // Run batches of concurrent requests
            int batches = config_.requests_per_level / concurrency;
            
            for (int batch = 0; batch < batches; ++batch) {
                auto start = std::chrono::high_resolution_clock::now();
                
                // Launch concurrent requests
                std::vector<std::future<Backends::InferenceResult>> futures;
                for (int i = 0; i < concurrency; ++i) {
                    futures.push_back(std::async(std::launch::async, [&]() {
                        Backends::InferenceRequest req;
                        req.model = config_.model;
                        req.prompt = config_.prompt;
                        req.temperature = config_.temperature;
                        req.max_tokens = config_.max_tokens;
                        req.seed = config_.seed;
                        return backend_call(req);
                    }));
                }
                
                // Collect results
                double batch_total_tokens = 0;
                double batch_total_latency = 0;
                int successful = 0;
                
                for (auto& fut : futures) {
                    auto result = fut.get();
                    if (result.success) {
                        batch_total_tokens += result.tokens_generated;
                        batch_total_latency += result.total_latency_ms;
                        successful++;
                    }
                }
                
                auto end = std::chrono::high_resolution_clock::now();
                double batch_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
                
                if (successful > 0) {
                    double batch_tps = batch_total_tokens / (batch_duration_ms / 1000.0);
                    double batch_rps = successful / (batch_duration_ms / 1000.0);
                    double avg_latency = batch_total_latency / successful;
                    
                    tps_samples.push_back(batch_tps);
                    latency_samples.push_back(avg_latency);
                    rps_samples.push_back(batch_rps);
                }
                
                if ((batch + 1) % 5 == 0) {
                    std::cout << "    " << (batch + 1) << "/" << batches << " batches complete\n";
                }
            }
            
            if (!tps_samples.empty()) {
                res.total_tps = CalculateStatistics(tps_samples);
                res.latency_ms = CalculateStatistics(latency_samples);
                res.throughput_rps = CalculateStatistics(rps_samples);
                
                // Calculate efficiency
                double ideal_tps = baseline_tps * concurrency;
                if (ideal_tps > 0) {
                    res.efficiency = res.total_tps.mean / ideal_tps;
                }
                
                res.success = true;
            }
            
            results.load_results.push_back(res);
        }
        
        results.overall_success = true;
        return results;
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

void RunConcurrentLoadBenchmark(const std::string& backend = "sovereign") {
    ConcurrentLoadBenchmark benchmark;
    
    ConcurrentLoadBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else if (backend == "ollama") {
        results = benchmark.RunOllama();
    } else {
        std::cout << "Unknown backend: " << backend << "\n";
        return;
    }
    
    ConcurrentLoadBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
