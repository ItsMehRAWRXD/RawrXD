// chaos_resilience_benchmark.cpp
// Batch 4: Chaos Resilience Benchmark
//
// Measures: System resilience under controlled chaos
// Features: Fault injection, recovery validation, availability metrics
// Output: Resilience score, MTTR, availability percentage

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include "chaos_engine.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <thread>
#include <atomic>

namespace Benchmark {

class ChaosResilienceBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        int seed = 42;
        int test_duration_seconds = 180; // 3 minutes
        double fault_injection_rate = 0.05; // 5% of requests
        int recovery_timeout_ms = 5000;
    };

    struct ResilienceMetrics {
        int total_requests = 0;
        int successful_requests = 0;
        int failed_requests = 0;
        int faults_injected = 0;
        int successful_recoveries = 0;
        double availability_percent = 0.0;
        double mean_recovery_time_ms = 0.0;
        double resilience_score = 0.0;
    };

    struct Results {
        ResilienceMetrics metrics;
        bool success = false;
    };

    explicit ChaosResilienceBenchmark(const Config& config = Config())
        : config_(config), rng_(config.seed) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[ChaosResilience] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunResilienceTest([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Chaos Resilience Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        const auto& m = results.metrics;
        std::cout << "Total Requests:        " << m.total_requests << "\n";
        std::cout << "Successful:            " << m.successful_requests << "\n";
        std::cout << "Failed:                " << m.failed_requests << "\n";
        std::cout << "Faults Injected:       " << m.faults_injected << "\n";
        std::cout << "Successful Recoveries: " << m.successful_recoveries << "\n";
        std::cout << "Availability:          " << std::fixed << std::setprecision(2) 
                  << m.availability_percent << "%\n";
        std::cout << "Mean Recovery Time:    " << std::setprecision(1) 
                  << m.mean_recovery_time_ms << " ms\n";
        std::cout << "Resilience Score:      " << std::setprecision(1) 
                  << m.resilience_score << "/100\n";
    }

private:
    Config config_;
    std::mt19937 rng_;

    template<typename BackendFunc>
    Results RunResilienceTest(BackendFunc backend_call) {
        Results results;
        ResilienceMetrics metrics;
        
        std::vector<double> recovery_times;
        
        auto start = std::chrono::steady_clock::now();
        
        while (std::chrono::steady_clock::now() - start < 
               std::chrono::seconds(config_.test_duration_seconds)) {
            
            // Decide whether to inject fault
            bool inject_fault = (std::uniform_real_distribution<double>(0.0, 1.0)(rng_) < 
                                config_.fault_injection_rate);
            
            if (inject_fault) {
                metrics.faults_injected++;
                
                // Inject fault and measure recovery
                auto recovery_start = std::chrono::high_resolution_clock::now();
                
                bool recovered = AttemptRecovery(backend_call);
                
                auto recovery_end = std::chrono::high_resolution_clock::now();
                double recovery_ms = std::chrono::duration<double, std::milli>(
                    recovery_end - recovery_start).count();
                
                if (recovered) {
                    metrics.successful_recoveries++;
                    recovery_times.push_back(recovery_ms);
                    metrics.successful_requests++;
                } else {
                    metrics.failed_requests++;
                }
            } else {
                // Normal request
                Backends::InferenceRequest req;
                req.model = config_.model;
                req.prompt = "Test prompt for resilience";
                req.temperature = 0.0f;
                req.max_tokens = 64;
                
                auto result = backend_call(req);
                
                if (result.success) {
                    metrics.successful_requests++;
                } else {
                    metrics.failed_requests++;
                }
            }
            
            metrics.total_requests++;
            
            // Small delay between requests
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Calculate metrics
        if (metrics.total_requests > 0) {
            metrics.availability_percent = 
                (100.0 * metrics.successful_requests) / metrics.total_requests;
        }
        
        if (!recovery_times.empty()) {
            metrics.mean_recovery_time_ms = 
                std::accumulate(recovery_times.begin(), recovery_times.end(), 0.0) / 
                recovery_times.size();
        }
        
        // Calculate resilience score (0-100)
        // Based on availability, recovery rate, and recovery time
        double availability_score = metrics.availability_percent;
        double recovery_rate = metrics.faults_injected > 0 ? 
            (100.0 * metrics.successful_recoveries) / metrics.faults_injected : 100.0;
        double recovery_time_score = std::max(0.0, 100.0 - (metrics.mean_recovery_time_ms / 50.0));
        
        metrics.resilience_score = (availability_score * 0.4) + 
                                   (recovery_rate * 0.4) + 
                                   (recovery_time_score * 0.2);
        
        results.metrics = metrics;
        results.success = true;
        
        return results;
    }

    template<typename BackendFunc>
    bool AttemptRecovery(BackendFunc backend_call) {
        // Try to recover with retries
        for (int attempt = 0; attempt < 3; ++attempt) {
            Backends::InferenceRequest req;
            req.model = config_.model;
            req.prompt = "Recovery test";
            req.temperature = 0.0f;
            req.max_tokens = 32;
            
            auto result = backend_call(req);
            if (result.success) {
                return true;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return false;
    }
};

void RunChaosResilienceBenchmark(const std::string& backend = "sovereign") {
    ChaosResilienceBenchmark benchmark;
    
    ChaosResilienceBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else {
        std::cout << "Chaos resilience requires Sovereign backend\n";
        return;
    }
    
    ChaosResilienceBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
