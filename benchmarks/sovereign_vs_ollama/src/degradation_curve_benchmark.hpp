// Benchmark 17: Degradation Curve Benchmark
// Tests performance degradation under sustained resource pressure
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
// Degradation Curve Benchmark
// ============================================================================
class DegradationCurveBenchmark : public Benchmark {
public:
    const char* GetName() const override { return "Degradation Curve (Resource Pressure)"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::RESOURCE_USAGE; }
    
    BenchmarkResult Run(const BenchmarkConfig& config) override {
        std::cout << "\n========================================\n";
        std::cout << "Running: " << GetName() << "\n";
        std::cout << "Backend: " << BackendTypeToString(config.backend) << "\n";
        std::cout << "Configuration: 30-minute sustained load with sampling\n";
        std::cout << "========================================\n\n";
        
        auto backend = CreateBackendAdapter(config.backend);
        if (!backend || !backend->Initialize(config)) {
            std::cerr << "Failed to initialize backend\n";
            return CreateErrorResult(config, "Backend initialization failed");
        }
        
        BenchmarkResult result;
        result.benchmark_id = "degradation_curve_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        // Test parameters
        const int DURATION_MINUTES = 30;
        const int SAMPLE_INTERVAL_SECONDS = 60;  // Sample every minute
        const int CONCURRENT_REQUESTS = 8;
        const int WARMUP_SECONDS = 60;
        
        auto workload = ReferenceWorkloads::Stress();
        
        // Metrics
        std::vector<SamplePoint> samples;
        std::vector<double> all_latencies;
        std::atomic<int> total_requests{0};
        std::atomic<int> successful_requests{0};
        
        // Warmup phase
        std::cout << "Warmup phase (" << WARMUP_SECONDS << " seconds)...\n";
        RunWarmup(backend.get(), workload, CONCURRENT_REQUESTS, WARMUP_SECONDS);
        
        // Main test phase
        std::cout << "\nStarting degradation test (" << DURATION_MINUTES << " minutes)...\n";
        
        Timer total_timer;
        total_timer.Start();
        
        std::atomic<bool> should_stop{false};
        std::mutex sample_mutex;
        
        // Background worker to generate load
        std::vector<std::future<void>> workers;
        for (int i = 0; i < CONCURRENT_REQUESTS; ++i) {
            workers.push_back(std::async(std::launch::async, [&](int worker_id) {
                int prompt_idx = worker_id;
                while (!should_stop) {
                    Timer timer;
                    timer.Start();
                    
                    auto response = backend->Generate(
                        workload.prompts[prompt_idx % workload.prompts.size()], 
                        workload.max_tokens);
                    
                    timer.Stop();
                    double latency = timer.ElapsedMs();
                    
                    total_requests++;
                    if (!response.empty()) {
                        successful_requests++;
                        std::lock_guard<std::mutex> lock(sample_mutex);
                        all_latencies.push_back(latency);
                    }
                    
                    prompt_idx++;
                }
            }, i));
        }
        
        // Sample at regular intervals
        for (int minute = 0; minute < DURATION_MINUTES; ++minute) {
            std::this_thread::sleep_for(std::chrono::seconds(SAMPLE_INTERVAL_SECONDS));
            
            SamplePoint point;
            point.timestamp_minute = minute;
            point.cumulative_requests = total_requests.load();
            point.cumulative_successful = successful_requests.load();
            
            // Get current resource usage
            point.resources = backend->GetResourceUsage();
            
            // Calculate current throughput (requests in last minute)
            static int last_requests = 0;
            point.requests_per_minute = point.cumulative_requests - last_requests;
            last_requests = point.cumulative_requests;
            
            // Calculate latency stats from recent samples
            {
                std::lock_guard<std::mutex> lock(sample_mutex);
                if (!all_latencies.empty()) {
                    size_t recent_count = std::min(all_latencies.size(), size_t(100));
                    auto start = all_latencies.end() - recent_count;
                    std::vector<double> recent(start, all_latencies.end());
                    auto stats = StatisticalMetrics::Calculate(recent);
                    point.mean_latency_ms = stats.mean;
                    point.p95_latency_ms = stats.p95;
                    point.p99_latency_ms = stats.p99;
                }
            }
            
            samples.push_back(point);
            
            // Print progress
            std::cout << "  Minute " << (minute + 1) << "/" << DURATION_MINUTES << ": ";
            std::cout << "TPS=" << std::fixed << std::setprecision(1) << (point.requests_per_minute / 60.0);
            std::cout << ", Latency=" << point.mean_latency_ms << "ms";
            std::cout << ", Memory=" << (point.resources.memory_mb > 0 ? point.resources.memory_mb : 0) << "MB\n";
        }
        
        should_stop = true;
        for (auto& worker : workers) {
            worker.wait();
        }
        
        total_timer.Stop();
        result.total_time_ms = total_timer.ElapsedMs();
        
        // Calculate overall metrics
        if (!all_latencies.empty()) {
            result.latency = StatisticalMetrics::Calculate(all_latencies);
        }
        
        int total = total_requests.load();
        int successful = successful_requests.load();
        double total_time_sec = result.total_time_ms / 1000.0;
        double throughput = total_time_sec > 0 ? total / total_time_sec : 0.0;
        
        result.throughput.mean = throughput;
        result.throughput.median = throughput;
        result.throughput.p95 = throughput;
        result.throughput.p99 = throughput;
        
        result.success_rate = total > 0 ? static_cast<double>(successful) / total : 0.0;
        result.resources = backend->GetResourceUsage();
        
        // Calculate degradation metrics
        auto degradation = CalculateDegradation(samples);
        
        // Custom metrics
        result.custom_metrics["duration_minutes"] = DURATION_MINUTES;
        result.custom_metrics["total_requests"] = total;
        result.custom_metrics["successful_requests"] = successful;
        result.custom_metrics["baseline_tps"] = degradation.baseline_tps;
        result.custom_metrics["final_tps"] = degradation.final_tps;
        result.custom_metrics["tps_degradation_percent"] = degradation.tps_degradation_percent;
        result.custom_metrics["latency_increase_percent"] = degradation.latency_increase_percent;
        result.custom_metrics["memory_growth_mb"] = degradation.memory_growth_mb;
        result.custom_metrics["stability_score"] = degradation.stability_score;
        
        // Quality metrics
        result.quality.structure_score = std::max(0.0, 100.0 - degradation.tps_degradation_percent);
        result.quality.correctness_score = result.success_rate * 100.0;
        result.quality.depth_score = degradation.stability_score;
        result.quality.coherence_score = std::max(0.0, 100.0 - degradation.latency_increase_percent);
        result.quality.actionability_score = degradation.stability_score;
        result.quality.overall_score = degradation.stability_score;
        
        // Print summary
        PrintSummary(result, samples, degradation);
        
        return result;
    }
    
private:
    struct SamplePoint {
        int timestamp_minute = 0;
        int cumulative_requests = 0;
        int cumulative_successful = 0;
        int requests_per_minute = 0;
        double mean_latency_ms = 0.0;
        double p95_latency_ms = 0.0;
        double p99_latency_ms = 0.0;
        ResourceUsage resources;
    };
    
    struct DegradationMetrics {
        double baseline_tps = 0.0;
        double final_tps = 0.0;
        double tps_degradation_percent = 0.0;
        double baseline_latency = 0.0;
        double final_latency = 0.0;
        double latency_increase_percent = 0.0;
        double memory_growth_mb = 0.0;
        double stability_score = 0.0;
    };
    
    void RunWarmup(BackendAdapter* backend, const WorkloadConfig& workload, 
                  int concurrent, int duration_seconds) {
        std::atomic<bool> stop{false};
        std::vector<std::future<void>> workers;
        
        for (int i = 0; i < concurrent; ++i) {
            workers.push_back(std::async(std::launch::async, [&](int worker_id) {
                int prompt_idx = worker_id;
                auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(duration_seconds);
                while (std::chrono::steady_clock::now() < end_time) {
                    backend->Generate(workload.prompts[prompt_idx % workload.prompts.size()], workload.max_tokens);
                    prompt_idx++;
                }
            }, i));
        }
        
        for (auto& worker : workers) {
            worker.wait();
        }
    }
    
    DegradationMetrics CalculateDegradation(const std::vector<SamplePoint>& samples) {
        DegradationMetrics metrics;
        
        if (samples.size() < 2) return metrics;
        
        // Baseline: average of first 3 samples (or first sample if less than 3)
        size_t baseline_samples = std::min(size_t(3), samples.size());
        double baseline_tps_sum = 0.0;
        double baseline_latency_sum = 0.0;
        for (size_t i = 0; i < baseline_samples; ++i) {
            baseline_tps_sum += samples[i].requests_per_minute / 60.0;
            baseline_latency_sum += samples[i].mean_latency_ms;
        }
        metrics.baseline_tps = baseline_tps_sum / baseline_samples;
        metrics.baseline_latency = baseline_latency_sum / baseline_samples;
        
        // Final: average of last 3 samples
        size_t final_start = samples.size() > 3 ? samples.size() - 3 : 0;
        size_t final_count = samples.size() - final_start;
        double final_tps_sum = 0.0;
        double final_latency_sum = 0.0;
        for (size_t i = final_start; i < samples.size(); ++i) {
            final_tps_sum += samples[i].requests_per_minute / 60.0;
            final_latency_sum += samples[i].mean_latency_ms;
        }
        metrics.final_tps = final_tps_sum / final_count;
        metrics.final_latency = final_latency_sum / final_count;
        
        // Calculate degradation percentages
        if (metrics.baseline_tps > 0) {
            metrics.tps_degradation_percent = ((metrics.baseline_tps - metrics.final_tps) / metrics.baseline_tps) * 100.0;
        }
        if (metrics.baseline_latency > 0) {
            metrics.latency_increase_percent = ((metrics.final_latency - metrics.baseline_latency) / metrics.baseline_latency) * 100.0;
        }
        
        // Memory growth
        if (!samples.empty() && samples.front().resources.memory_mb > 0 && samples.back().resources.memory_mb > 0) {
            metrics.memory_growth_mb = samples.back().resources.memory_mb - samples.front().resources.memory_mb;
        }
        
        // Stability score: based on variance and degradation
        double variance = 0.0;
        double mean_tps = 0.0;
        for (const auto& s : samples) {
            mean_tps += s.requests_per_minute / 60.0;
        }
        mean_tps /= samples.size();
        
        for (const auto& s : samples) {
            double diff = (s.requests_per_minute / 60.0) - mean_tps;
            variance += diff * diff;
        }
        variance /= samples.size();
        double stddev = std::sqrt(variance);
        double cv = mean_tps > 0 ? stddev / mean_tps : 0.0;  // Coefficient of variation
        
        // Stability: penalize high variance and high degradation
        metrics.stability_score = std::max(0.0, 100.0 - (cv * 100.0) - (metrics.tps_degradation_percent * 0.5));
        
        return metrics;
    }
    
    void PrintSummary(const BenchmarkResult& result, 
                     const std::vector<SamplePoint>& samples,
                     const DegradationMetrics& degradation) {
        std::cout << "\n========================================\n";
        std::cout << "Degradation Curve Summary\n";
        std::cout << "========================================\n";
        std::cout << "Duration: " << result.custom_metrics.at("duration_minutes") << " minutes\n";
        std::cout << "Total requests: " << result.custom_metrics.at("total_requests") << "\n";
        std::cout << "Success rate: " << std::fixed << std::setprecision(1) << result.success_rate * 100 << "%\n";
        std::cout << "\nDegradation Analysis:\n";
        std::cout << "  Baseline TPS: " << degradation.baseline_tps << "\n";
        std::cout << "  Final TPS: " << degradation.final_tps << "\n";
        std::cout << "  TPS Degradation: " << degradation.tps_degradation_percent << "%\n";
        std::cout << "  Latency Increase: " << degradation.latency_increase_percent << "%\n";
        std::cout << "  Memory Growth: " << degradation.memory_growth_mb << " MB\n";
        std::cout << "  Stability Score: " << degradation.stability_score << "/100\n";
        std::cout << "========================================\n\n";
    }
    
    BenchmarkResult CreateErrorResult(const BenchmarkConfig& config, const std::string& error) {
        BenchmarkResult result;
        result.benchmark_id = "degradation_curve_" + std::string(BackendTypeToString(config.backend));
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
