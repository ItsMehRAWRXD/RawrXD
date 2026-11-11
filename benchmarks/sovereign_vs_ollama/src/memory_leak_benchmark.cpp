// memory_leak_benchmark.cpp
// Tier 4: Memory Leak Detection Benchmark
//
// Measures: Memory growth over extended durations
// Durations: 1 hour (CI), 6 hours (nightly), 24 hours (weekly)
// Output: Growth rate MB/hour, leak score, time series

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>

namespace Benchmark {

class MemoryLeakBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string prompt = "Write a detailed technical document about artificial intelligence.";
        int max_tokens = 512;
        float temperature = 0.0f;
        int seed = 42;
        std::chrono::seconds duration = std::chrono::hours(1); // Default 1 hour
        std::chrono::seconds sampling_interval = std::chrono::seconds(60); // Sample every minute
        double leak_threshold_mb_per_hour = 50.0; // Alert if >50MB/hour growth
    };

    struct MemorySample {
        double timestamp_hours;
        double memory_mb;
        double tokens_generated;
    };

    struct Results {
        double initial_memory_mb;
        double final_memory_mb;
        double peak_memory_mb;
        double growth_rate_mb_per_hour;
        double leak_score; // 0-1, 1 = no leak detected
        StatisticalSummary memory_stats;
        std::vector<MemorySample> time_series;
        bool leak_detected;
        bool success = false;
    };

    explicit MemoryLeakBenchmark(const Config& config = Config())
        : config_(config), stop_sampling_(false) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[MemoryLeak] Testing Sovereign backend...\n";
        std::cout << "  Duration: " << config_.duration.count() << " seconds\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunLeakBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Memory Leak Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        std::cout << "Initial Memory: " << results.initial_memory_mb << " MB\n";
        std::cout << "Final Memory: " << results.final_memory_mb << " MB\n";
        std::cout << "Peak Memory: " << results.peak_memory_mb << " MB\n";
        std::cout << "Growth Rate: " << results.growth_rate_mb_per_hour << " MB/hour\n";
        std::cout << "Leak Score: " << (results.leak_score * 100) << "%\n";
        std::cout << "Leak Detected: " << (results.leak_detected ? "YES" : "NO") << "\n";
        std::cout << "Samples: " << results.time_series.size() << "\n";
    }

private:
    Config config_;
    std::atomic<bool> stop_sampling_;
    std::vector<MemorySample> samples_;

    template<typename BackendFunc>
    Results RunLeakBenchmark(BackendFunc backend_call) {
        Results results;
        stop_sampling_ = false;
        samples_.clear();

        // Start memory sampling thread
        std::thread sampler(&MemoryLeakBenchmark::SampleMemory, this);

        // Run inference continuously
        std::cout << "  Running inference...\n";
        auto start = std::chrono::steady_clock::now();
        double total_tokens = 0;
        int request_count = 0;

        while (std::chrono::steady_clock::now() - start < config_.duration) {
            Backends::InferenceRequest request;
            request.model = config_.model;
            request.prompt = config_.prompt;
            request.temperature = config_.temperature;
            request.max_tokens = config_.max_tokens;
            request.seed = config_.seed + request_count;

            auto result = backend_call(request);

            if (result.success) {
                total_tokens += result.tokens_generated;
                request_count++;
            }

            // Progress update every 10 minutes
            auto elapsed = std::chrono::steady_clock::now() - start;
            if (std::chrono::duration_cast<std::chrono::minutes>(elapsed).count() % 10 == 0 && 
                std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() % 60 == 0) {
                double hours = std::chrono::duration<double>(elapsed).count() / 3600.0;
                std::cout << "    " << hours << " hours, " << request_count << " requests\n";
            }

            // Small delay to prevent overwhelming the system
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // Stop sampling
        stop_sampling_ = true;
        sampler.join();

        // Calculate results
        if (!samples_.empty()) {
            results.initial_memory_mb = samples_.front().memory_mb;
            results.final_memory_mb = samples_.back().memory_mb;
            
            double peak = 0;
            for (const auto& s : samples_) {
                peak = std::max(peak, s.memory_mb);
            }
            results.peak_memory_mb = peak;

            double hours_run = config_.duration.count() / 3600.0;
            results.growth_rate_mb_per_hour = (results.final_memory_mb - results.initial_memory_mb) / hours_run;
            
            // Leak score: 1.0 = no leak, 0.0 = severe leak
            results.leak_score = std::max(0.0, 1.0 - (std::abs(results.growth_rate_mb_per_hour) / config_.leak_threshold_mb_per_hour));
            results.leak_detected = std::abs(results.growth_rate_mb_per_hour) > config_.leak_threshold_mb_per_hour;
            
            results.time_series = samples_;
            results.success = true;
        }

        return results;
    }

    void SampleMemory() {
        auto start = std::chrono::steady_clock::now();
        double initial_memory = GetCurrentMemoryMB();

        while (!stop_sampling_) {
            auto now = std::chrono::steady_clock::now();
            double hours = std::chrono::duration<double>(now - start).count() / 3600.0;

            MemorySample sample;
            sample.timestamp_hours = hours;
            sample.memory_mb = GetCurrentMemoryMB();
            sample.tokens_generated = 0; // Would track from main thread

            samples_.push_back(sample);

            std::this_thread::sleep_for(config_.sampling_interval);
        }
    }

    double GetCurrentMemoryMB() {
        // Platform-specific memory measurement
        // Windows
        #ifdef _WIN32
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            return pmc.WorkingSetSize / (1024.0 * 1024.0);
        }
        #else
        // Linux/Mac
        struct rusage usage;
        if (getrusage(RUSAGE_SELF, &usage) == 0) {
            return usage.ru_maxrss / 1024.0;
        }
        #endif
        return 4096.0; // Fallback
    }
};

void RunMemoryLeakBenchmark(int hours = 1, const std::string& backend = "sovereign") {
    MemoryLeakBenchmark::Config config;
    config.duration = std::chrono::hours(hours);
    
    MemoryLeakBenchmark benchmark(config);
    
    MemoryLeakBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else {
        std::cout << "Memory leak benchmark requires Sovereign backend\n";
        return;
    }
    
    MemoryLeakBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
