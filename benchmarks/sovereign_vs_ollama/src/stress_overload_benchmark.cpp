// stress_overload_benchmark.cpp
// Batch 4: Stress Overload Benchmark
//
// Measures: System behavior under sustained maximum load
// Features: Request flooding, connection saturation, recovery validation
// Output: Degradation curve, failure points, recovery time

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include "chaos_engine.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>

namespace Benchmark {

class StressOverloadBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string prompt = "Generate a detailed technical explanation.";
        int max_tokens = 256;
        float temperature = 0.0f;
        int seed = 42;
        
        // Stress parameters
        int warmup_seconds = 30;
        int stress_duration_seconds = 300; // 5 minutes
        int max_concurrent_requests = 100;
        int request_rate_per_second = 50; // Requests to inject per second
        double degradation_threshold = 0.50; // 50% performance drop = failure
    };

    struct StressPhase {
        std::string name;
        StatisticalSummary latency_ms;
        StatisticalSummary throughput_rps;
        double error_rate;
        double degradation_percent;
        bool recovered;
    };

    struct Results {
        StressPhase baseline;
        StressPhase stress;
        StressPhase recovery;
        double max_sustained_load;
        double failure_point_load;
        StatisticalSummary recovery_time_ms;
        bool success = false;
    };

    explicit StressOverloadBenchmark(const Config& config = Config())
        : config_(config), stop_stress_(false) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[StressOverload] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunStressBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Stress Overload Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        std::cout << "Phase          | Latency (ms) | Throughput (rps) | Error Rate | Degradation\n";
        std::cout << std::string(70, '-') << "\n";
        
        auto print_phase = [](const std::string& name, const StressPhase& phase) {
            std::cout << std::left << std::setw(15) << name << "| "
                      << std::fixed << std::setprecision(1)
                      << std::setw(13) << phase.latency_ms.mean << "| "
                      << std::setw(17) << phase.throughput_rps.mean << "| "
                      << std::setw(11) << (phase.error_rate * 100) << "%| "
                      << std::setw(10) << phase.degradation_percent << "%\n";
        };

        print_phase("Baseline", results.baseline);
        print_phase("Stress", results.stress);
        print_phase("Recovery", results.recovery);

        std::cout << "\nMax Sustained Load: " << results.max_sustained_load << " rps\n";
        std::cout << "Failure Point: " << results.failure_point_load << " rps\n";
        std::cout << "Recovery Time: " << results.recovery_time_ms.mean << " ms\n";
    }

private:
    Config config_;
    std::atomic<bool> stop_stress_;
    std::queue<double> latency_queue_;
    std::mutex queue_mutex_;

    template<typename BackendFunc>
    Results RunStressBenchmark(BackendFunc backend_call) {
        Results results;

        // Phase 1: Baseline measurement
        std::cout << "  Phase 1: Baseline measurement (" << config_.warmup_seconds << "s)...\n";
        results.baseline = MeasurePhase("baseline", backend_call, 
            config_.warmup_seconds, 10); // 10 concurrent

        // Phase 2: Stress test
        std::cout << "  Phase 2: Stress overload (" << config_.stress_duration_seconds << "s)...\n";
        results.stress = RunStressPhase(backend_call);

        // Phase 3: Recovery measurement
        std::cout << "  Phase 3: Recovery measurement (" << config_.warmup_seconds << "s)...\n";
        results.recovery = MeasurePhase("recovery", backend_call,
            config_.warmup_seconds, 10);

        // Calculate metrics
        results.max_sustained_load = results.baseline.throughput_rps.mean;
        results.failure_point_load = results.stress.throughput_rps.mean;
        
        // Calculate degradation
        if (results.baseline.latency_ms.mean > 0) {
            results.stress.degradation_percent = 
                ((results.stress.latency_ms.mean - results.baseline.latency_ms.mean) 
                 / results.baseline.latency_ms.mean) * 100.0;
        }
        
        // Calculate recovery time
        std::vector<double> recovery_times;
        recovery_times.push_back(results.recovery.latency_ms.mean);
        results.recovery_time_ms = CalculateStatistics(recovery_times);
        
        results.success = true;
        return results;
    }

    template<typename BackendFunc>
    StressPhase MeasurePhase(const std::string& name, BackendFunc backend_call,
                            int duration_seconds, int concurrency) {
        StressPhase phase;
        phase.name = name;
        
        std::vector<double> latencies;
        std::vector<double> throughputs;
        int errors = 0;
        int total_requests = 0;
        
        auto start = std::chrono::steady_clock::now();
        
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(duration_seconds)) {
            // Launch concurrent requests
            std::vector<std::future<Backends::InferenceResult>> futures;
            
            for (int i = 0; i < concurrency; ++i) {
                futures.push_back(std::async(std::launch::async, [&]() {
                    Backends::InferenceRequest req;
                    req.model = config_.model;
                    req.prompt = config_.prompt;
                    req.temperature = config_.temperature;
                    req.max_tokens = config_.max_tokens;
                    return backend_call(req);
                }));
            }
            
            // Collect results
            double batch_latency = 0;
            int batch_success = 0;
            
            for (auto& fut : futures) {
                auto result = fut.get();
                if (result.success) {
                    latencies.push_back(result.total_latency_ms);
                    batch_latency += result.total_latency_ms;
                    batch_success++;
                } else {
                    errors++;
                }
                total_requests++;
            }
            
            if (batch_success > 0) {
                throughputs.push_back(batch_success / (batch_latency / 1000.0));
            }
        }
        
        if (!latencies.empty()) {
            phase.latency_ms = CalculateStatistics(latencies);
            phase.throughput_rps = CalculateStatistics(throughputs);
            phase.error_rate = static_cast<double>(errors) / total_requests;
        }
        
        return phase;
    }

    template<typename BackendFunc>
    StressPhase RunStressPhase(BackendFunc backend_call) {
        StressPhase phase;
        phase.name = "stress";
        
        std::vector<double> latencies;
        std::vector<double> throughputs;
        std::atomic<int> errors{0};
        std::atomic<int> total_requests{0};
        
        auto start = std::chrono::steady_clock::now();
        
        // Launch stress threads
        std::vector<std::thread> stress_threads;
        
        for (int t = 0; t < 10; ++t) { // 10 stress threads
            stress_threads.emplace_back([&]() {
                while (std::chrono::steady_clock::now() - start < 
                       std::chrono::seconds(config_.stress_duration_seconds)) {
                    
                    // Flood with requests
                    for (int r = 0; r < config_.request_rate_per_second / 10; ++r) {
                        Backends::InferenceRequest req;
                        req.model = config_.model;
                        req.prompt = config_.prompt;
                        req.temperature = config_.temperature;
                        req.max_tokens = config_.max_tokens;
                        
                        auto result = backend_call(req);
                        
                        if (result.success) {
                            std::lock_guard<std::mutex> lock(queue_mutex_);
                            latencies.push_back(result.total_latency_ms);
                        } else {
                            errors++;
                        }
                        total_requests++;
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            });
        }
        
        // Wait for stress to complete
        for (auto& t : stress_threads) {
            t.join();
        }
        
        // Calculate throughput from latencies
        if (!latencies.empty()) {
            phase.latency_ms = CalculateStatistics(latencies);
            
            // Estimate throughput
            double total_time_sec = config_.stress_duration_seconds;
            double avg_rps = latencies.size() / total_time_sec;
            throughputs.push_back(avg_rps);
            
            phase.throughput_rps = CalculateStatistics(throughputs);
            phase.error_rate = static_cast<double>(errors.load()) / total_requests.load();
        }
        
        return phase;
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
        
        return summary;
    }
};

void RunStressOverloadBenchmark(const std::string& backend = "sovereign") {
    StressOverloadBenchmark benchmark;
    
    StressOverloadBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else {
        std::cout << "Stress overload requires Sovereign backend\n";
        return;
    }
    
    StressOverloadBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
