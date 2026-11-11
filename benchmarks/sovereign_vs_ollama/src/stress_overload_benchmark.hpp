// Benchmark 14: Stress Overload Benchmark
// Tests system behavior under extreme load conditions
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

namespace rawrxd::benchmark {

// ============================================================================
// Stress Overload Benchmark
// ============================================================================
class StressOverloadBenchmark : public Benchmark {
public:
    const char* GetName() const override { return "Stress Overload"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::RESOURCE_USAGE; }
    
    BenchmarkResult Run(const BenchmarkConfig& config) override {
        std::cout << "\n========================================\n";
        std::cout << "Running: " << GetName() << "\n";
        std::cout << "Backend: " << BackendTypeToString(config.backend) << "\n";
        std::cout << "Duration: 5 minutes progressive overload\n";
        std::cout << "========================================\n\n";
        
        auto backend = CreateBackendAdapter(config.backend);
        if (!backend || !backend->Initialize(config)) {
            std::cerr << "Failed to initialize backend\n";
            return CreateErrorResult(config, "Backend initialization failed");
        }
        
        BenchmarkResult result;
        result.benchmark_id = "stress_overload_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        // Progressive load phases
        struct LoadPhase {
            const char* name;
            int duration_seconds;
            int concurrent_requests;
            double expected_tps;
        };
        
        LoadPhase phases[] = {
            {"baseline", 60, 1, 50.0},
            {"light_load", 60, 4, 40.0},
            {"medium_load", 60, 8, 30.0},
            {"heavy_load", 60, 16, 20.0},
            {"overload", 60, 32, 10.0},
            {"saturation", 60, 64, 5.0}
        };
        
        auto workload = ReferenceWorkloads::Stress();
        
        std::vector<double> all_latencies;
        std::vector<double> all_tps;
        std::vector<double> phase_success_rates;
        std::vector<double> degradation_curve;
        
        int total_requests = 0;
        int successful_requests = 0;
        
        Timer total_timer;
        total_timer.Start();
        
        // Run each phase
        for (const auto& phase : phases) {
            std::cout << "\nPhase: " << phase.name << "\n";
            std::cout << "  Concurrent: " << phase.concurrent_requests << "\n";
            std::cout << "  Duration: " << phase.duration_seconds << "s\n";
            
            auto phase_result = RunPhase(backend.get(), workload, phase);
            
            phase_success_rates.push_back(phase_result.success_rate);
            degradation_curve.push_back(phase_result.mean_tps);
            
            all_latencies.insert(all_latencies.end(), 
                                phase_result.latencies.begin(), 
                                phase_result.latencies.end());
            all_tps.insert(all_tps.end(), phase_result.tps_samples.begin(), phase_result.tps_samples.end());
            
            total_requests += phase_result.total_requests;
            successful_requests += phase_result.successful_requests;
            
            std::cout << "  Success rate: " << std::fixed << std::setprecision(1) << (phase_result.success_rate * 100) << "%\n";
            std::cout << "  Mean TPS: " << phase_result.mean_tps << "\n";
            std::cout << "  Mean latency: " << phase_result.mean_latency << "ms\n";
        }
        
        total_timer.Stop();
        result.total_time_ms = total_timer.ElapsedMs();
        
        // Calculate metrics
        if (!all_latencies.empty()) {
            result.latency = StatisticalMetrics::Calculate(all_latencies);
        }
        if (!all_tps.empty()) {
            result.throughput = StatisticalMetrics::Calculate(all_tps);
        }
        
        result.success_rate = static_cast<double>(successful_requests) / total_requests;
        result.resources = backend->GetResourceUsage();
        
        // Calculate degradation
        double baseline_tps = degradation_curve.empty() ? 0.0 : degradation_curve[0];
        double final_tps = degradation_curve.empty() ? 0.0 : degradation_curve.back();
        double degradation_percent = baseline_tps > 0 
            ? ((baseline_tps - final_tps) / baseline_tps) * 100.0 
            : 0.0;
        
        // Custom metrics
        result.custom_metrics["total_requests"] = total_requests;
        result.custom_metrics["successful_requests"] = successful_requests;
        result.custom_metrics["degradation_percent"] = degradation_percent;
        result.custom_metrics["baseline_tps"] = baseline_tps;
        result.custom_metrics["final_tps"] = final_tps;
        result.custom_metrics["min_success_rate"] = *std::min_element(phase_success_rates.begin(), phase_success_rates.end());
        result.custom_metrics["max_concurrent"] = 64;
        
        // Quality metrics
        result.quality.structure_score = 60.0;
        result.quality.correctness_score = result.success_rate * 100.0;
        result.quality.depth_score = 60.0;
        result.quality.coherence_score = 65.0;
        result.quality.actionability_score = 60.0;
        result.quality.overall_score = std::max(0.0, 100.0 - degradation_percent);
        
        // Print summary
        PrintSummary(result, degradation_curve, phase_success_rates);
        
        return result;
    }
    
private:
    struct PhaseResult {
        std::vector<double> latencies;
        std::vector<double> tps_samples;
        double mean_latency = 0.0;
        double mean_tps = 0.0;
        double success_rate = 0.0;
        int total_requests = 0;
        int successful_requests = 0;
    };
    
    PhaseResult RunPhase(BackendAdapter* backend, const WorkloadConfig& workload, 
                        const struct LoadPhase& phase) {
        PhaseResult result;
        
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::seconds(phase.duration_seconds);
        
        std::atomic<int> completed{0};
        std::atomic<int> failed{0};
        std::mutex data_mutex;
        
        // Launch concurrent workers
        std::vector<std::future<void>> workers;
        
        for (int i = 0; i < phase.concurrent_requests; ++i) {
            workers.push_back(std::async(std::launch::async, [&]() {
                int prompt_idx = 0;
                while (std::chrono::steady_clock::now() < end_time) {
                    Timer timer;
                    timer.Start();
                    
                    auto response = backend->Generate(
                        workload.prompts[prompt_idx % workload.prompts.size()], 
                        workload.max_tokens);
                    
                    timer.Stop();
                    double latency = timer.ElapsedMs();
                    
                    std::lock_guard<std::mutex> lock(data_mutex);
                    result.latencies.push_back(latency);
                    
                    if (!response.empty()) {
                        completed++;
                        double tps = backend->GetLastTokensPerSec();
                        result.tps_samples.push_back(tps);
                    } else {
                        failed++;
                    }
                    
                    prompt_idx++;
                }
            }));
        }
        
        // Wait for all workers
        for (auto& worker : workers) {
            worker.wait();
        }
        
        result.total_requests = completed + failed;
        result.successful_requests = completed;
        result.success_rate = result.total_requests > 0 
            ? static_cast<double>(completed) / result.total_requests 
            : 0.0;
        
        if (!result.latencies.empty()) {
            result.mean_latency = std::accumulate(result.latencies.begin(), result.latencies.end(), 0.0) 
                               / result.latencies.size();
        }
        
        if (!result.tps_samples.empty()) {
            result.mean_tps = std::accumulate(result.tps_samples.begin(), result.tps_samples.end(), 0.0) 
                             / result.tps_samples.size();
        }
        
        return result;
    }
    
    void PrintSummary(const BenchmarkResult& result, 
                     const std::vector<double>& degradation_curve,
                     const std::vector<double>& success_rates) {
        std::cout << "\n========================================\n";
        std::cout << "Stress Overload Summary\n";
        std::cout << "========================================\n";
        std::cout << "Total requests: " << result.custom_metrics.at("total_requests") << "\n";
        std::cout << "Success rate: " << std::fixed << std::setprecision(1) << result.success_rate * 100 << "%\n";
        std::cout << "Baseline TPS: " << result.custom_metrics.at("baseline_tps") << "\n";
        std::cout << "Final TPS: " << result.custom_metrics.at("final_tps") << "\n";
        std::cout << "Degradation: " << result.custom_metrics.at("degradation_percent") << "%\n";
        std::cout << "Min success rate: " << result.custom_metrics.at("min_success_rate") * 100 << "%\n";
        std::cout << "========================================\n\n";
        
        std::cout << "Degradation Curve:\n";
        const char* phase_names[] = {"Baseline", "Light", "Medium", "Heavy", "Overload", "Saturation"};
        for (size_t i = 0; i < degradation_curve.size() && i < 6; ++i) {
            std::cout << "  " << phase_names[i] << ": " << degradation_curve[i] << " TPS (";
            std::cout << success_rates[i] * 100 << "% success)\n";
        }
        std::cout << "\n";
    }
    
    BenchmarkResult CreateErrorResult(const BenchmarkConfig& config, const std::string& error) {
        BenchmarkResult result;
        result.benchmark_id = "stress_overload_" + std::string(BackendTypeToString(config.backend));
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
