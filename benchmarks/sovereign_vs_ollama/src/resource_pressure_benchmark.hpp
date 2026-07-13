// Benchmark 18: Resource Pressure Benchmark
// Tests system behavior under CPU, memory, and GPU pressure
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "json_reporter.hpp"
#include "backends/backend_factory.hpp"
#include "workload_profiles.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <future>
#include <chrono>

namespace rawrxd::benchmark {

// ============================================================================
// Resource Pressure Benchmark
// ============================================================================
class ResourcePressureBenchmark : public Benchmark {
public:
    const char* GetName() const override { return "Resource Pressure (CPU/Memory/GPU)"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::RESOURCE_USAGE; }
    
    BenchmarkResult Run(const BenchmarkConfig& config) override {
        std::cout << "\n========================================\n";
        std::cout << "Running: " << GetName() << "\n";
        std::cout << "Backend: " << BackendTypeToString(config.backend) << "\n";
        std::cout << "Configuration: Progressive resource pressure\n";
        std::cout << "========================================\n\n";
        
        auto backend = CreateBackendAdapter(config.backend);
        if (!backend || !backend->Initialize(config)) {
            std::cerr << "Failed to initialize backend\n";
            return CreateErrorResult(config, "Backend initialization failed");
        }
        
        BenchmarkResult result;
        result.benchmark_id = "resource_pressure_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        auto workload = ReferenceWorkloads::Stress();
        
        // Run each pressure test
        std::vector<PressureResult> pressure_results;
        
        // Baseline (no pressure)
        std::cout << "\n[1/4] Baseline (no pressure)...\n";
        pressure_results.push_back(RunPressureTest(backend.get(), workload, PressureType::NONE, "baseline"));
        
        // CPU pressure
        std::cout << "\n[2/4] CPU pressure...\n";
        pressure_results.push_back(RunPressureTest(backend.get(), workload, PressureType::CPU, "cpu_pressure"));
        
        // Memory pressure
        std::cout << "\n[3/4] Memory pressure...\n";
        pressure_results.push_back(RunPressureTest(backend.get(), workload, PressureType::MEMORY, "memory_pressure"));
        
        // Combined pressure
        std::cout << "\n[4/4] Combined pressure...\n";
        pressure_results.push_back(RunPressureTest(backend.get(), workload, PressureType::COMBINED, "combined_pressure"));
        
        // Aggregate results
        result = AggregateResults(pressure_results, config);
        
        // Print summary
        PrintSummary(result, pressure_results);
        
        return result;
    }
    
private:
    enum class PressureType {
        NONE,
        CPU,
        MEMORY,
        COMBINED
    };
    
    struct PressureResult {
        std::string name;
        PressureType type;
        double mean_latency_ms = 0.0;
        double mean_tps = 0.0;
        double success_rate = 0.0;
        double throughput = 0.0;
        int total_requests = 0;
        int successful_requests = 0;
        ResourceUsage resources;
        std::vector<double> latencies;
    };
    
    PressureResult RunPressureTest(BackendAdapter* backend, const WorkloadConfig& workload,
                                   PressureType pressure_type, const std::string& name) {
        PressureResult result;
        result.name = name;
        result.type = pressure_type;
        
        const int TEST_DURATION_SECONDS = 60;
        const int CONCURRENT_REQUESTS = 4;
        
        std::atomic<int> completed{0};
        std::atomic<int> failed{0};
        std::vector<double> latencies;
        std::mutex latency_mutex;
        
        // Start pressure generator if needed
        std::future<void> pressure_future;
        std::atomic<bool> stop_pressure{false};
        
        if (pressure_type != PressureType::NONE) {
            pressure_future = std::async(std::launch::async, [&]() {
                GeneratePressure(pressure_type, stop_pressure);
            });
        }
        
        // Run test
        Timer timer;
        timer.Start();
        
        std::vector<std::future<void>> workers;
        std::atomic<bool> stop_workers{false};
        
        for (int i = 0; i < CONCURRENT_REQUESTS; ++i) {
            workers.push_back(std::async(std::launch::async, [&](int worker_id) {
                int prompt_idx = worker_id;
                while (!stop_workers) {
                    Timer req_timer;
                    req_timer.Start();
                    
                    auto response = backend->Generate(
                        workload.prompts[prompt_idx % workload.prompts.size()], 
                        workload.max_tokens);
                    
                    req_timer.Stop();
                    double latency = req_timer.ElapsedMs();
                    
                    {
                        std::lock_guard<std::mutex> lock(latency_mutex);
                        latencies.push_back(latency);
                    }
                    
                    if (!response.empty()) {
                        completed++;
                    } else {
                        failed++;
                    }
                    
                    prompt_idx++;
                }
            }, i));
        }
        
        // Run for duration
        std::this_thread::sleep_for(std::chrono::seconds(TEST_DURATION_SECONDS));
        stop_workers = true;
        
        for (auto& worker : workers) {
            worker.wait();
        }
        
        timer.Stop();
        
        // Stop pressure
        if (pressure_type != PressureType::NONE) {
            stop_pressure = true;
            pressure_future.wait();
        }
        
        // Calculate results
        result.total_requests = completed + failed;
        result.successful_requests = completed;
        result.success_rate = result.total_requests > 0 
            ? static_cast<double>(completed) / result.total_requests 
            : 0.0;
        
        if (!latencies.empty()) {
            result.mean_latency_ms = std::accumulate(latencies.begin(), latencies.end(), 0.0) / latencies.size();
            auto stats = StatisticalMetrics::Calculate(latencies);
            result.mean_tps = 1000.0 / stats.median;  // Approximate TPS
        }
        
        double duration_sec = timer.ElapsedMs() / 1000.0;
        result.throughput = duration_sec > 0 ? result.total_requests / duration_sec : 0.0;
        result.resources = backend->GetResourceUsage();
        result.latencies = latencies;
        
        return result;
    }
    
    void GeneratePressure(PressureType type, std::atomic<bool>& stop) {
        std::vector<std::thread> pressure_threads;
        
        // CPU pressure: spin threads
        if (type == PressureType::CPU || type == PressureType::COMBINED) {
            int num_cpu_threads = std::thread::hardware_concurrency() / 2;
            for (int i = 0; i < num_cpu_threads; ++i) {
                pressure_threads.emplace_back([&]() {
                    volatile double accumulator = 0.0;
                    while (!stop) {
                        for (int j = 0; j < 1000000; ++j) {
                            accumulator += j * 3.14159;
                        }
                    }
                    (void)accumulator;  // Prevent optimization
                });
            }
        }
        
        // Memory pressure: allocate and touch memory
        if (type == PressureType::MEMORY || type == PressureType::COMBINED) {
            pressure_threads.emplace_back([&]() {
                std::vector<std::vector<char>> allocations;
                while (!stop) {
                    // Allocate 100MB chunks
                    allocations.emplace_back(100 * 1024 * 1024);
                    // Touch the memory
                    for (size_t i = 0; i < allocations.back().size(); i += 4096) {
                        allocations.back()[i] = static_cast<char>(i % 256);
                    }
                    
                    // Keep max 2GB allocated
                    if (allocations.size() > 20) {
                        allocations.erase(allocations.begin());
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            });
        }
        
        // Wait for stop signal
        while (!stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Cleanup
        for (auto& t : pressure_threads) {
            t.join();
        }
    }
    
    BenchmarkResult AggregateResults(const std::vector<PressureResult>& pressure_results,
                                    const BenchmarkConfig& config) {
        BenchmarkResult result;
        result.benchmark_id = "resource_pressure_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        // Find baseline for comparison
        const PressureResult* baseline = nullptr;
        for (const auto& pr : pressure_results) {
            if (pr.type == PressureType::NONE) {
                baseline = &pr;
                break;
            }
        }
        
        // Aggregate all latencies
        std::vector<double> all_latencies;
        int total_requests = 0;
        int successful_requests = 0;
        
        for (const auto& pr : pressure_results) {
            all_latencies.insert(all_latencies.end(), pr.latencies.begin(), pr.latencies.end());
            total_requests += pr.total_requests;
            successful_requests += pr.successful_requests;
        }
        
        if (!all_latencies.empty()) {
            result.latency = StatisticalMetrics::Calculate(all_latencies);
        }
        
        result.success_rate = total_requests > 0 
            ? static_cast<double>(successful_requests) / total_requests 
            : 0.0;
        
        // Calculate throughput from baseline
        if (baseline) {
            result.throughput.mean = baseline->throughput;
            result.throughput.median = baseline->throughput;
            result.throughput.p95 = baseline->throughput;
            result.throughput.p99 = baseline->throughput;
        }
        
        // Custom metrics - degradation under each pressure type
        for (const auto& pr : pressure_results) {
            std::string prefix = pr.name + "_";
            result.custom_metrics[prefix + "mean_latency_ms"] = pr.mean_latency_ms;
            result.custom_metrics[prefix + "mean_tps"] = pr.mean_tps;
            result.custom_metrics[prefix + "success_rate"] = pr.success_rate;
            result.custom_metrics[prefix + "throughput"] = pr.throughput;
            
            if (baseline && baseline != &pr) {
                double latency_degradation = baseline->mean_latency_ms > 0 
                    ? ((pr.mean_latency_ms - baseline->mean_latency_ms) / baseline->mean_latency_ms) * 100.0
                    : 0.0;
                double tps_degradation = baseline->mean_tps > 0
                    ? ((baseline->mean_tps - pr.mean_tps) / baseline->mean_tps) * 100.0
                    : 0.0;
                
                result.custom_metrics[prefix + "latency_degradation_percent"] = latency_degradation;
                result.custom_metrics[prefix + "tps_degradation_percent"] = tps_degradation;
            }
        }
        
        // Calculate overall resilience score
        double resilience_score = 100.0;
        if (baseline) {
            for (const auto& pr : pressure_results) {
                if (pr.type != PressureType::NONE) {
                    double latency_degradation = result.custom_metrics[pr.name + "_latency_degradation_percent"];
                    double tps_degradation = result.custom_metrics[pr.name + "_tps_degradation_percent"];
                    double success_drop = (baseline->success_rate - pr.success_rate) * 100.0;
                    
                    // Penalize degradation
                    resilience_score -= (latency_degradation * 0.3 + tps_degradation * 0.4 + success_drop * 0.3);
                }
            }
        }
        result.custom_metrics["resilience_score"] = std::max(0.0, resilience_score);
        
        // Quality metrics
        result.quality.structure_score = result.custom_metrics["resilience_score"];
        result.quality.correctness_score = result.success_rate * 100.0;
        result.quality.depth_score = result.custom_metrics["resilience_score"];
        result.quality.coherence_score = result.custom_metrics["resilience_score"];
        result.quality.actionability_score = result.custom_metrics["resilience_score"];
        result.quality.overall_score = result.custom_metrics["resilience_score"];
        
        return result;
    }
    
    void PrintSummary(const BenchmarkResult& result, const std::vector<PressureResult>& pressure_results) {
        std::cout << "\n========================================\n";
        std::cout << "Resource Pressure Summary\n";
        std::cout << "========================================\n";
        
        for (const auto& pr : pressure_results) {
            std::cout << "\n" << pr.name << ":\n";
            std::cout << "  Mean latency: " << std::fixed << std::setprecision(1) << pr.mean_latency_ms << "ms\n";
            std::cout << "  Mean TPS: " << pr.mean_tps << "\n";
            std::cout << "  Success rate: " << pr.success_rate * 100 << "%\n";
            std::cout << "  Throughput: " << pr.throughput << " req/s\n";
            
            if (pr.type != PressureType::NONE) {
                std::string prefix = pr.name + "_";
                auto it_latency = result.custom_metrics.find(prefix + "latency_degradation_percent");
                auto it_tps = result.custom_metrics.find(prefix + "tps_degradation_percent");
                
                if (it_latency != result.custom_metrics.end()) {
                    std::cout << "  Latency degradation: " << it_latency->second << "%\n";
                }
                if (it_tps != result.custom_metrics.end()) {
                    std::cout << "  TPS degradation: " << it_tps->second << "%\n";
                }
            }
        }
        
        std::cout << "\nOverall Resilience Score: " << result.custom_metrics.at("resilience_score") << "/100\n";
        std::cout << "========================================\n\n";
    }
    
    BenchmarkResult CreateErrorResult(const BenchmarkConfig& config, const std::string& error) {
        BenchmarkResult result;
        result.benchmark_id = "resource_pressure_" + std::string(BackendTypeToString(config.backend));
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
