// Benchmark 16: Mutation Storm Benchmark
// Tests system stability under rapid configuration changes
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "json_reporter.hpp"
#include "backends/backend_factory.hpp"
#include "workload_profiles.hpp"
#include "chaos_engine.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <future>
#include <random>

namespace rawrxd::benchmark {

// ============================================================================
// Mutation Storm Benchmark
// ============================================================================
class MutationStormBenchmark : public Benchmark {
public:
    const char* GetName() const override { return "Mutation Storm (10,000)"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::RECOVERY; }
    
    BenchmarkResult Run(const BenchmarkConfig& config) override {
        std::cout << "\n========================================\n";
        std::cout << "Running: " << GetName() << "\n";
        std::cout << "Backend: " << BackendTypeToString(config.backend) << "\n";
        std::cout << "Configuration: 10,000 mutations over 5 minutes\n";
        std::cout << "========================================\n\n";
        
        auto backend = CreateBackendAdapter(config.backend);
        if (!backend || !backend->Initialize(config)) {
            std::cerr << "Failed to initialize backend\n";
            return CreateErrorResult(config, "Backend initialization failed");
        }
        
        BenchmarkResult result;
        result.benchmark_id = "mutation_storm_10k_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        // Test parameters
        const int NUM_MUTATIONS = 10000;
        const int DURATION_SECONDS = 300;  // 5 minutes
        const int CONCURRENT_WORKERS = 16;
        
        auto workload = ReferenceWorkloads::Stress();
        
        // Metrics
        std::atomic<int> mutations_applied{0};
        std::atomic<int> mutations_failed{0};
        std::atomic<int> requests_completed{0};
        std::atomic<int> requests_failed{0};
        std::vector<double> mutation_latencies;
        std::vector<double> request_latencies;
        std::mutex latency_mutex;
        
        Timer total_timer;
        total_timer.Start();
        
        // Launch mutation workers
        std::vector<std::future<void>> workers;
        std::atomic<bool> should_stop{false};
        
        for (int i = 0; i < CONCURRENT_WORKERS; ++i) {
            workers.push_back(std::async(std::launch::async, [&](int worker_id) {
                std::mt19937 rng(worker_id + 42);
                std::uniform_int_distribution<int> mutation_type(0, 9);
                std::uniform_int_distribution<int> prompt_idx(0, workload.prompts.size() - 1);
                
                while (!should_stop) {
                    // Apply a mutation
                    Timer mutation_timer;
                    mutation_timer.Start();
                    
                    bool mutation_success = ApplyMutation(backend.get(), mutation_type(rng));
                    
                    mutation_timer.Stop();
                    double mutation_latency = mutation_timer.ElapsedMs();
                    
                    {
                        std::lock_guard<std::mutex> lock(latency_mutex);
                        mutation_latencies.push_back(mutation_latency);
                    }
                    
                    if (mutation_success) {
                        mutations_applied++;
                    } else {
                        mutations_failed++;
                    }
                    
                    // Make a request
                    Timer request_timer;
                    request_timer.Start();
                    
                    auto response = backend->Generate(workload.prompts[prompt_idx(rng)], workload.max_tokens);
                    
                    request_timer.Stop();
                    double request_latency = request_timer.ElapsedMs();
                    
                    {
                        std::lock_guard<std::mutex> lock(latency_mutex);
                        request_latencies.push_back(request_latency);
                    }
                    
                    if (!response.empty()) {
                        requests_completed++;
                    } else {
                        requests_failed++;
                    }
                    
                    // Check if we've hit the mutation target
                    if (mutations_applied >= NUM_MUTATIONS) {
                        break;
                    }
                }
            }, i));
        }
        
        // Wait for duration or mutation target
        std::this_thread::sleep_for(std::chrono::seconds(DURATION_SECONDS));
        should_stop = true;
        
        for (auto& worker : workers) {
            worker.wait();
        }
        
        total_timer.Stop();
        result.total_time_ms = total_timer.ElapsedMs();
        
        // Calculate metrics
        if (!request_latencies.empty()) {
            result.latency = StatisticalMetrics::Calculate(request_latencies);
        }
        
        int total_requests = requests_completed + requests_failed;
        double total_time_sec = result.total_time_ms / 1000.0;
        double throughput = total_time_sec > 0 ? total_requests / total_time_sec : 0.0;
        
        result.throughput.mean = throughput;
        result.throughput.median = throughput;
        result.throughput.p95 = throughput;
        result.throughput.p99 = throughput;
        
        result.success_rate = total_requests > 0 
            ? static_cast<double>(requests_completed) / total_requests 
            : 0.0;
        
        result.resources = backend->GetResourceUsage();
        
        // Custom metrics
        int total_mutations = mutations_applied + mutations_failed;
        result.custom_metrics["mutations_applied"] = mutations_applied.load();
        result.custom_metrics["mutations_failed"] = mutations_failed.load();
        result.custom_metrics["mutation_success_rate"] = total_mutations > 0 
            ? static_cast<double>(mutations_applied) / total_mutations 
            : 0.0;
        result.custom_metrics["mutations_per_second"] = total_time_sec > 0 
            ? total_mutations / total_time_sec 
            : 0.0;
        result.custom_metrics["requests_completed"] = requests_completed.load();
        result.custom_metrics["requests_failed"] = requests_failed.load();
        result.custom_metrics["mean_mutation_latency_ms"] = mutation_latencies.empty() ? 0.0 :
            std::accumulate(mutation_latencies.begin(), mutation_latencies.end(), 0.0) / mutation_latencies.size();
        
        // Quality metrics
        double mutation_success = total_mutations > 0 
            ? static_cast<double>(mutations_applied) / total_mutations 
            : 0.0;
        result.quality.structure_score = mutation_success * 100.0;
        result.quality.correctness_score = result.success_rate * 100.0;
        result.quality.depth_score = mutation_success * 100.0;
        result.quality.coherence_score = mutation_success * 100.0;
        result.quality.actionability_score = mutation_success * 100.0;
        result.quality.overall_score = (mutation_success * 0.3 + result.success_rate * 0.7) * 100.0;
        
        // Print summary
        PrintSummary(result);
        
        return result;
    }
    
private:
    bool ApplyMutation(BackendAdapter* backend, int mutation_type) {
        // Simulate different types of mutations
        switch (mutation_type) {
            case 0: // Temperature change
                return backend->SetParameter("temperature", 0.0 + (rand() % 100) / 100.0);
            case 1: // Max tokens change
                return backend->SetParameter("max_tokens", 64 + (rand() % 448));
            case 2: // Top_p change
                return backend->SetParameter("top_p", 0.1 + (rand() % 90) / 100.0);
            case 3: // Presence penalty change
                return backend->SetParameter("presence_penalty", (rand() % 20) / 10.0 - 1.0);
            case 4: // Frequency penalty change
                return backend->SetParameter("frequency_penalty", (rand() % 20) / 10.0 - 1.0);
            case 5: // Context window resize
                return backend->SetParameter("context_window", 1024 + (rand() % 14336));
            case 6: // Batch size change
                return backend->SetParameter("batch_size", 1 + (rand() % 31));
            case 7: // Thread count change
                return backend->SetParameter("threads", 1 + (rand() % 15));
            case 8: // Seed change
                return backend->SetParameter("seed", rand());
            case 9: // Model reload (most disruptive)
                return backend->ReloadModel();
            default:
                return true;
        }
    }
    
    void PrintSummary(const BenchmarkResult& result) {
        std::cout << "\n========================================\n";
        std::cout << "Mutation Storm Summary\n";
        std::cout << "========================================\n";
        std::cout << "Mutations applied: " << result.custom_metrics.at("mutations_applied") << "\n";
        std::cout << "Mutations failed: " << result.custom_metrics.at("mutations_failed") << "\n";
        std::cout << "Mutation success rate: " << std::fixed << std::setprecision(1) << result.custom_metrics.at("mutation_success_rate") * 100 << "%\n";
        std::cout << "Mutations/sec: " << result.custom_metrics.at("mutations_per_second") << "\n";
        std::cout << "\nRequest Performance:\n";
        std::cout << "  Completed: " << result.custom_metrics.at("requests_completed") << "\n";
        std::cout << "  Failed: " << result.custom_metrics.at("requests_failed") << "\n";
        std::cout << "  Success rate: " << result.success_rate * 100 << "%\n";
        std::cout << "  Mean latency: " << result.latency.mean << "ms\n";
        std::cout << "========================================\n\n";
    }
    
    BenchmarkResult CreateErrorResult(const BenchmarkConfig& config, const std::string& error) {
        BenchmarkResult result;
        result.benchmark_id = "mutation_storm_10k_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        result.success_rate = 0.0;
        return result;
    }
    
    static std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

} // namespace rawrxd::benchmark
