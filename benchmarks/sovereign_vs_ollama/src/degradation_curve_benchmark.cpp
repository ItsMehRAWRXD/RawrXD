// degradation_curve_benchmark.cpp
// Batch 4: Degradation Curve Benchmark
//
// Measures: Performance under gradually increasing load
// Output: Degradation curve, knee point detection, saturation level

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>

namespace Benchmark {

class DegradationCurveBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string prompt = "Generate code for a simple function.";
        int max_tokens = 256;
        float temperature = 0.0f;
        int seed = 42;
        
        // Load progression
        int start_rps = 1;
        int end_rps = 100;
        int rps_step = 5;
        int duration_per_step = 30; // seconds
        
        // Knee point detection
        double latency_threshold_ms = 1000.0; // 1 second
        double degradation_threshold = 0.50; // 50% degradation
    };

    struct LoadPoint {
        int target_rps;
        StatisticalSummary actual_rps;
        StatisticalSummary latency_ms;
        StatisticalSummary throughput_tps;
        double error_rate;
        bool saturated;
    };

    struct Results {
        std::vector<LoadPoint> curve;
        int knee_point_rps;
        int saturation_rps;
        double max_sustainable_tps;
        double latency_at_knee_ms;
        bool success = false;
    };

    explicit DegradationCurveBenchmark(const Config& config = Config())
        : config_(config) {}

    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[DegradationCurve] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunDegradationBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Degradation Curve Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        std::cout << "Knee Point: " << results.knee_point_rps << " rps\n";
        std::cout << "Saturation: " << results.saturation_rps << " rps\n";
        std::cout << "Max Sustainable TPS: " << results.max_sustainable_tps << "\n";
        std::cout << "Latency at Knee: " << results.latency_at_knee_ms << " ms\n\n";

        std::cout << "Load | Target RPS | Actual RPS | Latency (ms) | Throughput | Error | Sat\n";
        std::cout << std::string(70, '-') << "\n";

        for (const auto& point : results.curve) {
            std::cout << std::fixed << std::setprecision(1)
                      << std::setw(5) << point.target_rps << " | "
                      << std::setw(10) << point.actual_rps.mean << " | "
                      << std::setw(11) << point.latency_ms.mean << " | "
                      << std::setw(10) << point.throughput_tps.mean << " | "
                      << std::setw(5) << (point.error_rate * 100) << "%| "
                      << (point.saturated ? "YES" : "NO") << "\n";
        }
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunDegradationBenchmark(BackendFunc backend_call) {
        Results results;
        
        std::cout << "  Measuring degradation curve...\n";
        
        double baseline_latency = 0;
        bool first_point = true;
        
        for (int target_rps = config_.start_rps; 
             target_rps <= config_.end_rps; 
             target_rps += config_.rps_step) {
            
            std::cout << "    Testing " << target_rps << " rps...\n";
            
            LoadPoint point;
            point.target_rps = target_rps;
            
            // Measure at this load level
            auto measurements = MeasureAtLoad(backend_call, target_rps, 
                                             config_.duration_per_step);
            
            point.actual_rps = CalculateStatistics(measurements.rps_samples);
            point.latency_ms = CalculateStatistics(measurements.latency_samples);
            point.throughput_tps = CalculateStatistics(measurements.throughput_samples);
            point.error_rate = measurements.error_rate;
            
            // Establish baseline
            if (first_point) {
                baseline_latency = point.latency_ms.mean;
                first_point = false;
            }
            
            // Check for saturation
            double degradation = (point.latency_ms.mean - baseline_latency) / baseline_latency;
            point.saturated = (point.latency_ms.mean > config_.latency_threshold_ms) ||
                             (degradation > config_.degradation_threshold);
            
            results.curve.push_back(point);
            
            // Detect knee point
            if (results.knee_point_rps == 0 && point.saturated) {
                results.knee_point_rps = target_rps;
                results.latency_at_knee_ms = point.latency_ms.mean;
            }
            
            // Detect saturation point
            if (results.saturation_rps == 0 && point.error_rate > 0.10) {
                results.saturation_rps = target_rps;
            }
        }
        
        // Find max sustainable TPS
        double max_tps = 0;
        for (const auto& point : results.curve) {
            if (!point.saturated) {
                max_tps = std::max(max_tps, point.throughput_tps.mean);
            }
        }
        results.max_sustainable_tps = max_tps;
        
        if (results.knee_point_rps == 0) {
            results.knee_point_rps = config_.end_rps;
        }
        if (results.saturation_rps == 0) {
            results.saturation_rps = config_.end_rps;
        }
        
        results.success = true;
        return results;
    }

    struct Measurements {
        std::vector<double> rps_samples;
        std::vector<double> latency_samples;
        std::vector<double> throughput_samples;
        double error_rate;
    };

    template<typename BackendFunc>
    Measurements MeasureAtLoad(BackendFunc backend_call, int target_rps, int duration_sec) {
        Measurements m;
        
        int errors = 0;
        int total = 0;
        
        auto start = std::chrono::steady_clock::now();
        int requests_in_window = 0;
        auto window_start = start;
        
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(duration_sec)) {
            auto req_start = std::chrono::high_resolution_clock::now();
            
            Backends::InferenceRequest req;
            req.model = config_.model;
            req.prompt = config_.prompt;
            req.temperature = config_.temperature;
            req.max_tokens = config_.max_tokens;
            
            auto result = backend_call(req);
            
            auto req_end = std::chrono::high_resolution_clock::now();
            double latency_ms = std::chrono::duration<double, std::milli>(
                req_end - req_start).count();
            
            if (result.success) {
                m.latency_samples.push_back(latency_ms);
                m.throughput_samples.push_back(result.tokens_per_second);
            } else {
                errors++;
            }
            total++;
            requests_in_window++;
            
            // Calculate RPS every second
            auto now = std::chrono::steady_clock::now();
            if (now - window_start >= std::chrono::seconds(1)) {
                m.rps_samples.push_back(requests_in_window);
                requests_in_window = 0;
                window_start = now;
            }
            
            // Rate limiting to target
            double target_interval_ms = 1000.0 / target_rps;
            std::this_thread::sleep_for(
                std::chrono::milliseconds(static_cast<int>(target_interval_ms)));
        }
        
        m.error_rate = total > 0 ? static_cast<double>(errors) / total : 0.0;
        return m;
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

void RunDegradationCurveBenchmark(const std::string& backend = "sovereign") {
    DegradationCurveBenchmark benchmark;
    
    DegradationCurveBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else {
        std::cout << "Degradation curve requires Sovereign backend\n";
        return;
    }
    
    DegradationCurveBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
