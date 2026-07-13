// performance_drift_benchmark.cpp
// Tier 4: Performance Drift Benchmark
//
// Measures: TPS and latency degradation over time
// Output: Drift percentage, trend slope, time series

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <numeric>

namespace Benchmark {

class PerformanceDriftBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string prompt = "Explain quantum computing.";
        int max_tokens = 256;
        float temperature = 0.0f;
        int seed = 42;
        std::chrono::seconds duration = std::chrono::hours(1);
        int samples_per_hour = 60; // Sample every minute
    };

    struct PerformanceSample {
        double timestamp_hours;
        double tps;
        double latency_ms;
        int tokens_generated;
    };

    struct DriftMetrics {
        StatisticalSummary initial_tps;
        StatisticalSummary final_tps;
        double tps_drift_percent;
        StatisticalSummary initial_latency;
        StatisticalSummary final_latency;
        double latency_drift_percent;
        double trend_slope; // Change per hour
        bool degrading;
    };

    struct Results {
        DriftMetrics drift;
        std::vector<PerformanceSample> time_series;
        bool success = false;
    };

    explicit PerformanceDriftBenchmark(const Config& config = Config())
        : config_(config) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[PerformanceDrift] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunDriftBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Performance Drift Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        std::cout << "Initial TPS: " << results.drift.initial_tps.mean << "\n";
        std::cout << "Final TPS: " << results.drift.final_tps.mean << "\n";
        std::cout << "TPS Drift: " << results.drift.tps_drift_percent << "%\n";
        std::cout << "Trend Slope: " << results.drift.trend_slope << " TPS/hour\n\n";

        std::cout << "Initial Latency: " << results.drift.initial_latency.mean << " ms\n";
        std::cout << "Final Latency: " << results.drift.final_latency.mean << " ms\n";
        std::cout << "Latency Drift: " << results.drift.latency_drift_percent << "%\n";
        std::cout << "Degrading: " << (results.drift.degrading ? "YES" : "NO") << "\n";
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunDriftBenchmark(BackendFunc backend_call) {
        Results results;
        std::vector<PerformanceSample> samples;

        auto start = std::chrono::steady_clock::now();
        int total_samples = (config_.duration.count() / 3600.0) * config_.samples_per_hour;
        int samples_taken = 0;

        std::cout << "  Collecting " << total_samples << " samples...\n";

        while (samples_taken < total_samples) {
            auto sample_start = std::chrono::steady_clock::now();
            
            // Take a batch of measurements
            std::vector<double> tps_batch;
            std::vector<double> latency_batch;
            
            for (int i = 0; i < 5; ++i) { // 5 measurements per sample point
                Backends::InferenceRequest request;
                request.model = config_.model;
                request.prompt = config_.prompt;
                request.temperature = config_.temperature;
                request.max_tokens = config_.max_tokens;
                request.seed = config_.seed + samples_taken + i;

                auto result = backend_call(request);

                if (result.success) {
                    tps_batch.push_back(result.tokens_per_second);
                    latency_batch.push_back(result.total_latency_ms);
                }
            }

            if (!tps_batch.empty()) {
                double avg_tps = std::accumulate(tps_batch.begin(), tps_batch.end(), 0.0) / tps_batch.size();
                double avg_latency = std::accumulate(latency_batch.begin(), latency_batch.end(), 0.0) / latency_batch.size();

                auto now = std::chrono::steady_clock::now();
                double hours = std::chrono::duration<double>(now - start).count() / 3600.0;

                PerformanceSample sample;
                sample.timestamp_hours = hours;
                sample.tps = avg_tps;
                sample.latency_ms = avg_latency;
                sample.tokens_generated = 0;

                samples.push_back(sample);
                samples_taken++;

                if (samples_taken % 10 == 0) {
                    std::cout << "    " << samples_taken << "/" << total_samples << " samples\n";
                }
            }

            // Wait for next sample interval
            auto elapsed = std::chrono::steady_clock::now() - sample_start;
            auto target_interval = std::chrono::seconds(3600 / config_.samples_per_hour);
            if (elapsed < target_interval) {
                std::this_thread::sleep_for(target_interval - elapsed);
            }
        }

        // Calculate drift metrics
        if (samples.size() >= 10) {
            // Split into initial and final periods
            size_t split = samples.size() / 5; // First 20% vs last 20%
            
            std::vector<double> initial_tps, final_tps;
            std::vector<double> initial_latency, final_latency;

            for (size_t i = 0; i < split; ++i) {
                initial_tps.push_back(samples[i].tps);
                initial_latency.push_back(samples[i].latency_ms);
            }
            
            for (size_t i = samples.size() - split; i < samples.size(); ++i) {
                final_tps.push_back(samples[i].tps);
                final_latency.push_back(samples[i].latency_ms);
            }

            results.drift.initial_tps = CalculateStatistics(initial_tps);
            results.drift.final_tps = CalculateStatistics(final_tps);
            results.drift.initial_latency = CalculateStatistics(initial_latency);
            results.drift.final_latency = CalculateStatistics(final_latency);

            // Calculate drift percentages
            if (results.drift.initial_tps.mean > 0) {
                results.drift.tps_drift_percent = ((results.drift.final_tps.mean - results.drift.initial_tps.mean) 
                                                   / results.drift.initial_tps.mean) * 100.0;
            }
            
            if (results.drift.initial_latency.mean > 0) {
                results.drift.latency_drift_percent = ((results.drift.final_latency.mean - results.drift.initial_latency.mean) 
                                                       / results.drift.initial_latency.mean) * 100.0;
            }

            // Calculate trend slope (linear regression)
            results.drift.trend_slope = CalculateTrendSlope(samples);
            results.drift.degrading = results.drift.tps_drift_percent < -10.0 || results.drift.latency_drift_percent > 10.0;

            results.time_series = samples;
            results.success = true;
        }

        return results;
    }

    double CalculateTrendSlope(const std::vector<PerformanceSample>& samples) {
        if (samples.size() < 2) return 0.0;

        double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
        int n = samples.size();

        for (const auto& s : samples) {
            sum_x += s.timestamp_hours;
            sum_y += s.tps;
            sum_xy += s.timestamp_hours * s.tps;
            sum_x2 += s.timestamp_hours * s.timestamp_hours;
        }

        double denominator = n * sum_x2 - sum_x * sum_x;
        if (denominator == 0) return 0.0;

        return (n * sum_xy - sum_x * sum_y) / denominator;
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

void RunPerformanceDriftBenchmark(int hours = 1, const std::string& backend = "sovereign") {
    PerformanceDriftBenchmark::Config config;
    config.duration = std::chrono::hours(hours);
    
    PerformanceDriftBenchmark benchmark(config);
    
    PerformanceDriftBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else {
        std::cout << "Performance drift benchmark requires Sovereign backend\n";
        return;
    }
    
    PerformanceDriftBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
