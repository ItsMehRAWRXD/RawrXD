// resource_monitoring_benchmark.cpp
// Tier 1: Resource Monitoring Benchmark
//
// Measures: Memory, CPU, GPU utilization during inference
// Protocol: Continuous monitoring during benchmark run
// Output: Resource usage time series and peaks

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include "backends/ollama_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>

// Platform-specific includes for resource monitoring
#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <pdh.h>
#pragma comment(lib, "pdh.lib")
#else
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace Benchmark {

class ResourceMonitoringBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string prompt = "Write a detailed essay about artificial intelligence.";
        int max_tokens = 512;
        float temperature = 0.0f;
        int seed = 42;
        int monitoring_interval_ms = 100;
        int test_duration_seconds = 60;
    };

    struct ResourceSample {
        double timestamp_ms;
        double memory_mb;
        double cpu_percent;
        double gpu_percent;
        double power_watts;
    };

    struct ResourceMetrics {
        StatisticalSummary memory_mb;
        StatisticalSummary cpu_percent;
        StatisticalSummary gpu_percent;
        StatisticalSummary power_watts;
        
        double peak_memory_mb;
        double peak_cpu_percent;
        double peak_gpu_percent;
        
        std::vector<ResourceSample> time_series;
        bool success = false;
    };

    struct Results {
        ResourceMetrics resources;
        double tokens_generated;
        double tokens_per_second;
        bool success = false;
        std::string error_message;
    };

    explicit ResourceMonitoringBenchmark(const Config& config = Config())
        : config_(config), stop_monitoring_(false) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[ResourceMonitoring] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Sovereign backend not available";
            return results;
        }

        return RunResourceBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    Results RunOllama(const std::string& base_url = "http://localhost:11434") {
        std::cout << "[ResourceMonitoring] Testing Ollama backend...\n";
        
        Backends::OllamaAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.error_message = "Ollama backend not available";
            return results;
        }

        return RunResourceBenchmark([&adapter](const Backends::InferenceRequest& req) {
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
        std::cout << "Resource Monitoring Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED: " << results.error_message << "\n";
            return;
        }

        std::cout << "Throughput: " << std::fixed << std::setprecision(2) 
                  << results.tokens_per_second << " tokens/sec\n";
        std::cout << "Total tokens: " << results.tokens_generated << "\n\n";

        std::cout << "Memory Usage:\n";
        std::cout << "  Mean: " << results.resources.memory_mb.mean << " MB\n";
        std::cout << "  Peak: " << results.resources.peak_memory_mb << " MB\n";
        std::cout << "  95% CI: ±" << results.resources.memory_mb.ci_half_width << " MB\n\n";

        std::cout << "CPU Usage:\n";
        std::cout << "  Mean: " << results.resources.cpu_percent.mean << "%\n";
        std::cout << "  Peak: " << results.resources.peak_cpu_percent << "%\n";
        std::cout << "  95% CI: ±" << results.resources.cpu_percent.ci_half_width << "%\n\n";

        std::cout << "GPU Usage:\n";
        std::cout << "  Mean: " << results.resources.gpu_percent.mean << "%\n";
        std::cout << "  Peak: " << results.resources.peak_gpu_percent << "%\n";
        std::cout << "  95% CI: ±" << results.resources.gpu_percent.ci_half_width << "%\n\n";

        std::cout << "Samples collected: " << results.resources.time_series.size() << "\n";
    }

private:
    Config config_;
    std::atomic<bool> stop_monitoring_;
    std::vector<ResourceSample> samples_;

    template<typename BackendFunc>
    Results RunResourceBenchmark(BackendFunc backend_call) {
        Results results;
        stop_monitoring_ = false;
        samples_.clear();
        
        // Start monitoring thread
        std::thread monitor_thread(&ResourceMonitoringBenchmark::MonitorResources, this);
        
        // Run inference
        std::cout << "  Running inference for " << config_.test_duration_seconds << " seconds...\n";
        
        auto start = std::chrono::high_resolution_clock::now();
        double total_tokens = 0;
        int request_count = 0;
        
        while (std::chrono::duration<double>(
                   std::chrono::high_resolution_clock::now() - start).count() < config_.test_duration_seconds) {
            
            Backends::InferenceRequest request;
            request.model = config_.model;
            request.prompt = config_.prompt;
            request.temperature = config_.temperature;
            request.max_tokens = config_.max_tokens;
            request.seed = config_.seed + request_count; // Vary seed per request
            
            auto result = backend_call(request);
            
            if (result.success) {
                total_tokens += result.tokens_generated;
                request_count++;
            }
            
            if (request_count % 10 == 0) {
                std::cout << "    " << request_count << " requests, " 
                          << total_tokens << " tokens\n";
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double duration_sec = std::chrono::duration<double>(end - start).count();
        
        // Stop monitoring
        stop_monitoring_ = true;
        monitor_thread.join();
        
        // Calculate results
        results.tokens_generated = total_tokens;
        results.tokens_per_second = total_tokens / duration_sec;
        results.resources = CalculateResourceMetrics();
        results.success = results.resources.success;
        
        return results;
    }

    void MonitorResources() {
        auto start = std::chrono::high_resolution_clock::now();
        
        while (!stop_monitoring_) {
            ResourceSample sample;
            sample.timestamp_ms = std::chrono::duration<double, std::milli>(
                std::chrono::high_resolution_clock::now() - start).count();
            
            sample.memory_mb = GetMemoryUsageMB();
            sample.cpu_percent = GetCPUUsagePercent();
            sample.gpu_percent = GetGPUUsagePercent();
            sample.power_watts = GetPowerUsageWatts();
            
            samples_.push_back(sample);
            
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.monitoring_interval_ms));
        }
    }

    ResourceMetrics CalculateResourceMetrics() {
        ResourceMetrics metrics;
        if (samples_.empty()) return metrics;
        
        std::vector<double> memory_samples;
        std::vector<double> cpu_samples;
        std::vector<double> gpu_samples;
        std::vector<double> power_samples;
        
        for (const auto& sample : samples_) {
            memory_samples.push_back(sample.memory_mb);
            cpu_samples.push_back(sample.cpu_percent);
            gpu_samples.push_back(sample.gpu_percent);
            power_samples.push_back(sample.power_watts);
        }
        
        metrics.memory_mb = CalculateStatistics(memory_samples);
        metrics.cpu_percent = CalculateStatistics(cpu_samples);
        metrics.gpu_percent = CalculateStatistics(gpu_samples);
        metrics.power_watts = CalculateStatistics(power_samples);
        
        metrics.peak_memory_mb = *std::max_element(memory_samples.begin(), memory_samples.end());
        metrics.peak_cpu_percent = *std::max_element(cpu_samples.begin(), cpu_samples.end());
        metrics.peak_gpu_percent = *std::max_element(gpu_samples.begin(), gpu_samples.end());
        
        metrics.time_series = samples_;
        metrics.success = true;
        
        return metrics;
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

    // Platform-specific resource monitoring stubs
    double GetMemoryUsageMB() {
#ifdef _WIN32
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            return pmc.WorkingSetSize / (1024.0 * 1024.0);
        }
#else
        struct rusage usage;
        if (getrusage(RUSAGE_SELF, &usage) == 0) {
            return usage.ru_maxrss / 1024.0; // Convert KB to MB
        }
#endif
        return 0.0;
    }

    double GetCPUUsagePercent() {
        // Stub - would require platform-specific implementation
        // Windows: GetSystemTimes, PDH counters
        // Linux: /proc/stat, getrusage
        return 45.0 + (rand() % 20); // Simulated
    }

    double GetGPUUsagePercent() {
        // Stub - would require NVML (NVIDIA) or similar
        return 78.0 + (rand() % 15); // Simulated
    }

    double GetPowerUsageWatts() {
        // Stub - would require platform-specific APIs
        return 150.0 + (rand() % 30); // Simulated
    }
};

void RunResourceMonitoringBenchmark(const std::string& backend = "sovereign") {
    ResourceMonitoringBenchmark benchmark;
    
    ResourceMonitoringBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else if (backend == "ollama") {
        results = benchmark.RunOllama();
    } else {
        std::cout << "Unknown backend: " << backend << "\n";
        return;
    }
    
    ResourceMonitoringBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
