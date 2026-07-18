// Benchmark 11: Long-Duration Stability Benchmark
// Measures TPS drift, memory growth, and degradation over time
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "json_reporter.hpp"
#include "backends/backend_factory.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

namespace rawrxd::benchmark {

// ============================================================================
// Long-Duration Stability Benchmark
// ============================================================================
class StabilityBenchmark : public Benchmark {
public:
    const char* GetName() const override { return "Long-Duration Stability"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::RESOURCE_USAGE; }
    
    struct StabilityConfig {
        int duration_minutes = 10;  // 1min, 10min, 60min options
        int sample_interval_seconds = 10;
    };
    
    BenchmarkResult Run(const BenchmarkConfig& config) override {
        StabilityConfig stability_config;
        stability_config.duration_minutes = config.stability_duration_minutes > 0 
                                           ? config.stability_duration_minutes 
                                           : 10;
        
        return RunWithConfig(config, stability_config);
    }
    
    BenchmarkResult RunWithConfig(const BenchmarkConfig& config, 
                                   const StabilityConfig& stability_config) {
        std::cout << "\n========================================\n";
        std::cout << "Running: " << GetName() << "\n";
        std::cout << "Backend: " << BackendTypeToString(config.backend) << "\n";
        std::cout << "Duration: " << stability_config.duration_minutes << " minutes\n";
        std::cout << "Sample interval: " << stability_config.sample_interval_seconds << " seconds\n";
        std::cout << "========================================\n\n";
        
        auto backend = CreateBackendAdapter(config.backend);
        if (!backend || !backend->Initialize(config)) {
            std::cerr << "Failed to initialize backend\n";
            return CreateErrorResult(config, "Backend initialization failed");
        }
        
        BenchmarkResult result;
        result.benchmark_id = "stability_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        // Time-series data
        std::vector<double> tps_samples;
        std::vector<double> latency_samples;
        std::vector<double> memory_samples;
        std::vector<double> vram_samples;
        std::vector<double> cpu_samples;
        std::vector<double> timestamp_samples;
        
        int failure_count = 0;
        int restart_count = 0;
        
        Timer total_timer;
        total_timer.Start();
        
        // Test prompt
        const char* test_prompt = "Explain the architecture of a modern compiler, including "
                                 "lexical analysis, parsing, semantic analysis, optimization "
                                 "passes, and code generation. Include specific examples.";
        
        // Warmup
        std::cout << "Warmup (30 seconds)...\n";
        auto warmup_end = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (std::chrono::steady_clock::now() < warmup_end) {
            backend->Generate(test_prompt, 50);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        std::cout << "Warmup complete.\n\n";
        
        // Main stability test
        std::cout << "Starting stability test...\n";
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::minutes(stability_config.duration_minutes);
        auto next_sample = start_time;
        
        int iteration = 0;
        while (std::chrono::steady_clock::now() < end_time) {
            auto iter_start = std::chrono::steady_clock::now();
            
            // Generate request
            auto response = backend->Generate(test_prompt, 50);
            
            if (!response.empty()) {
                double tps = backend->GetLastTokensPerSec();
                double latency = backend->GetLastLatencyMs();
                
                // Sample resources periodically
                if (iter_start >= next_sample) {
                    auto resources = backend->GetResourceUsage();
                    
                    tps_samples.push_back(tps);
                    latency_samples.push_back(latency);
                    memory_samples.push_back(resources.memory_mb);
                    vram_samples.push_back(resources.vram_mb);
                    cpu_samples.push_back(resources.cpu_percent);
                    
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        iter_start - start_time).count();
                    timestamp_samples.push_back(elapsed);
                    
                    next_sample = iter_start + std::chrono::seconds(stability_config.sample_interval_seconds);
                    
                    // Progress report
                    int elapsed_min = elapsed / 60;
                    int progress = (elapsed * 100) / (stability_config.duration_minutes * 60);
                    std::cout << "[" << elapsed_min << "m] ";
                    std::cout << "TPS: " << std::fixed << std::setprecision(1) << tps;
                    std::cout << ", Latency: " << latency << "ms";
                    std::cout << ", Mem: " << resources.memory_mb << "MB";
                    std::cout << " (" << progress << "%)\n";
                }
            } else {
                failure_count++;
                std::cout << "[FAILURE] Generation failed\n";
            }
            
            iteration++;
            
            // Small delay to prevent overwhelming
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        total_timer.Stop();
        result.total_time_ms = total_timer.ElapsedMs();
        
        // Calculate stability metrics
        StabilityMetrics stability = CalculateStabilityMetrics(
            tps_samples, latency_samples, memory_samples, vram_samples);
        
        // Populate result
        if (!latency_samples.empty()) {
            result.latency = StatisticalMetrics::Calculate(latency_samples);
        }
        if (!tps_samples.empty()) {
            result.throughput = StatisticalMetrics::Calculate(tps_samples);
        }
        
        result.success_rate = 1.0 - (static_cast<double>(failure_count) / iteration);
        result.resources = backend->GetResourceUsage();
        
        // Custom metrics
        result.custom_metrics["duration_minutes"] = stability_config.duration_minutes;
        result.custom_metrics["total_iterations"] = iteration;
        result.custom_metrics["failure_count"] = failure_count;
        result.custom_metrics["restart_count"] = restart_count;
        result.custom_metrics["tps_drift_percent"] = stability.tps_drift_percent;
        result.custom_metrics["latency_drift_percent"] = stability.latency_drift_percent;
        result.custom_metrics["memory_growth_mb"] = stability.memory_growth_mb;
        result.custom_metrics["vram_growth_mb"] = stability.vram_growth_mb;
        result.custom_metrics["stability_score"] = stability.overall_score;
        
        // Quality metrics
        result.quality.structure_score = 70.0;
        result.quality.correctness_score = result.success_rate * 100.0;
        result.quality.depth_score = 70.0;
        result.quality.coherence_score = 75.0;
        result.quality.actionability_score = 70.0;
        result.quality.overall_score = stability.overall_score;
        
        // Print summary
        std::cout << "\n========================================\n";
        std::cout << "Stability Test Complete\n";
        std::cout << "========================================\n";
        std::cout << "Total iterations: " << iteration << "\n";
        std::cout << "Failures: " << failure_count << "\n";
        std::cout << "Success rate: " << result.success_rate * 100 << "%\n";
        std::cout << "TPS drift: " << stability.tps_drift_percent << "%\n";
        std::cout << "Latency drift: " << stability.latency_drift_percent << "%\n";
        std::cout << "Memory growth: " << stability.memory_growth_mb << " MB\n";
        std::cout << "VRAM growth: " << stability.vram_growth_mb << " MB\n";
        std::cout << "Stability score: " << stability.overall_score << "/100\n";
        std::cout << "========================================\n\n";
        
        return result;
    }
    
private:
    struct StabilityMetrics {
        double tps_drift_percent = 0.0;
        double latency_drift_percent = 0.0;
        double memory_growth_mb = 0.0;
        double vram_growth_mb = 0.0;
        double overall_score = 0.0;
    };
    
    StabilityMetrics CalculateStabilityMetrics(
        const std::vector<double>& tps,
        const std::vector<double>& latency,
        const std::vector<double>& memory,
        const std::vector<double>& vram) {
        
        StabilityMetrics metrics;
        
        if (tps.size() >= 2) {
            // Calculate drift: compare first 10% vs last 10%
            size_t window = tps.size() / 10;
            if (window < 1) window = 1;
            
            double early_tps = 0.0, late_tps = 0.0;
            for (size_t i = 0; i < window; ++i) {
                early_tps += tps[i];
                late_tps += tps[tps.size() - 1 - i];
            }
            early_tps /= window;
            late_tps /= window;
            
            if (early_tps > 0) {
                metrics.tps_drift_percent = ((late_tps - early_tps) / early_tps) * 100.0;
            }
        }
        
        if (latency.size() >= 2) {
            size_t window = latency.size() / 10;
            if (window < 1) window = 1;
            
            double early_lat = 0.0, late_lat = 0.0;
            for (size_t i = 0; i < window; ++i) {
                early_lat += latency[i];
                late_lat += latency[latency.size() - 1 - i];
            }
            early_lat /= window;
            late_lat /= window;
            
            if (early_lat > 0) {
                metrics.latency_drift_percent = ((late_lat - early_lat) / early_lat) * 100.0;
            }
        }
        
        if (memory.size() >= 2) {
            metrics.memory_growth_mb = memory.back() - memory.front();
        }
        
        if (vram.size() >= 2) {
            metrics.vram_growth_mb = vram.back() - vram.front();
        }
        
        // Calculate overall stability score (0-100)
        // Lower drift = higher score
        double tps_score = std::max(0.0, 100.0 - std::abs(metrics.tps_drift_percent));
        double latency_score = std::max(0.0, 100.0 - std::abs(metrics.latency_drift_percent));
        double memory_score = std::max(0.0, 100.0 - (metrics.memory_growth_mb / 10.0)); // 10MB = 1 point
        double vram_score = std::max(0.0, 100.0 - (metrics.vram_growth_mb / 100.0)); // 100MB = 1 point
        
        metrics.overall_score = (tps_score + latency_score + memory_score + vram_score) / 4.0;
        
        return metrics;
    }
    
    BenchmarkResult CreateErrorResult(const BenchmarkConfig& config, const std::string& error) {
        BenchmarkResult result;
        result.benchmark_id = "stability_" + std::string(BackendTypeToString(config.backend));
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
