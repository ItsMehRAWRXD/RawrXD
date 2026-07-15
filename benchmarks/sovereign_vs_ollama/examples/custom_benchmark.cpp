// custom_benchmark.cpp
// Batch 7: Example Custom Benchmark Implementation
//
// This example demonstrates how to create a custom benchmark
// following the RawrXD benchmark framework patterns.

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <numeric>
#include <algorithm>

namespace Benchmark {

// ============================================================================
// Example: Custom Latency Distribution Benchmark
// ============================================================================
// This benchmark measures the distribution of inference latencies
// and reports detailed statistics including histogram data.

class LatencyDistributionBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string prompt = "Explain the concept of neural networks in simple terms.";
        int max_tokens = 128;
        float temperature = 0.0f;
        int seed = 42;
        int warmup_runs = 5;
        int measured_runs = 100;  // More samples for distribution analysis
        int histogram_buckets = 10;
    };

    struct HistogramBucket {
        double min_ms;
        double max_ms;
        int count;
        double percentage;
    };

    struct Results {
        StatisticalSummary latency_ms;
        std::vector<HistogramBucket> histogram;
        double cv;  // Coefficient of variation (std_dev / mean)
        double skewness;
        double kurtosis;
        bool success = false;
    };

    explicit LatencyDistributionBenchmark(const Config& config = Config())
        : config_(config) {}

    // Run against Sovereign backend
    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[LatencyDistribution] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            std::cerr << "  ERROR: Sovereign backend not available\n";
            return results;
        }

        return RunBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    // Run against Ollama backend
    Results RunOllama(const std::string& base_url = "http://localhost:11434") {
        std::cout << "[LatencyDistribution] Testing Ollama backend...\n";
        
        Backends::OllamaAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            std::cerr << "  ERROR: Ollama backend not available\n";
            return results;
        }

        return RunBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    // Print formatted results
    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "Latency Distribution Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        // Summary statistics
        std::cout << "Summary Statistics:\n";
        std::cout << std::string(50, '-') << "\n";
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "  Mean:      " << std::setw(10) << results.latency_ms.mean << " ms\n";
        std::cout << "  Median:    " << std::setw(10) << results.latency_ms.median << " ms\n";
        std::cout << "  Std Dev:   " << std::setw(10) << results.latency_ms.std_dev << " ms\n";
        std::cout << "  Min:       " << std::setw(10) << results.latency_ms.min << " ms\n";
        std::cout << "  Max:       " << std::setw(10) << results.latency_ms.max << " ms\n";
        std::cout << "  P95:       " << std::setw(10) << results.latency_ms.p95 << " ms\n";
        std::cout << "  95% CI:    " << std::setw(10) << results.latency_ms.ci_half_width << " ms\n";
        std::cout << "\n";

        // Distribution shape
        std::cout << "Distribution Shape:\n";
        std::cout << std::string(50, '-') << "\n";
        std::cout << "  CV:        " << std::setw(10) << results.cv << "\n";
        std::cout << "  Skewness:  " << std::setw(10) << results.skewness << "\n";
        std::cout << "  Kurtosis:  " << std::setw(10) << results.kurtosis << "\n";
        std::cout << "\n";

        // Histogram
        std::cout << "Latency Histogram:\n";
        std::cout << std::string(50, '-') << "\n";
        std::cout << std::left << std::setw(15) << "Range (ms)" 
                  << std::setw(10) << "Count" 
                  << std::setw(15) << "Percentage" << "\n";
        std::cout << std::string(50, '-') << "\n";
        
        for (const auto& bucket : results.histogram) {
            std::cout << std::left << std::setw(15) 
                      << (std::to_string(static_cast<int>(bucket.min_ms)) + "-" + 
                          std::to_string(static_cast<int>(bucket.max_ms)))
                      << std::setw(10) << bucket.count
                      << std::setw(14) << std::fixed << std::setprecision(1) 
                      << bucket.percentage << "%";
            
            // Simple ASCII bar
            int bar_length = static_cast<int>(bucket.percentage / 2);
            std::cout << " " << std::string(bar_length, '#') << "\n";
        }
        std::cout << std::string(50, '-') << "\n";
    }

private:
    Config config_;

    template<typename BackendFunc>
    Results RunBenchmark(BackendFunc backend_call) {
        Results results;
        std::vector<double> samples;
        
        // Warmup phase
        std::cout << "  Warmup phase (" << config_.warmup_runs << " runs)...\n";
        for (int i = 0; i < config_.warmup_runs; ++i) {
            RunSingleIteration(backend_call);
        }
        
        // Measurement phase
        std::cout << "  Measurement phase (" << config_.measured_runs << " runs)...\n";
        for (int i = 0; i < config_.measured_runs; ++i) {
            auto iteration_result = RunSingleIteration(backend_call);
            
            if (iteration_result.success) {
                samples.push_back(iteration_result.latency_ms);
            }
            
            // Progress indicator
            if ((i + 1) % 20 == 0) {
                std::cout << "    Progress: " << (i + 1) << "/" << config_.measured_runs << "\n";
            }
        }
        
        if (samples.empty()) {
            std::cerr << "  ERROR: No successful iterations\n";
            return results;
        }
        
        // Calculate statistics
        results.latency_ms = CalculateStatistics(samples);
        results.histogram = CalculateHistogram(samples, config_.histogram_buckets);
        results.cv = results.latency_ms.std_dev / results.latency_ms.mean;
        results.skewness = CalculateSkewness(samples, results.latency_ms.mean, 
                                             results.latency_ms.std_dev);
        results.kurtosis = CalculateKurtosis(samples, results.latency_ms.mean, 
                                               results.latency_ms.std_dev);
        results.success = true;
        
        return results;
    }

    struct IterationResult {
        bool success = false;
        double latency_ms = 0.0;
    };

    template<typename BackendFunc>
    IterationResult RunSingleIteration(BackendFunc backend_call) {
        IterationResult result;
        
        Backends::InferenceRequest req;
        req.model = config_.model;
        req.prompt = config_.prompt;
        req.temperature = config_.temperature;
        req.max_tokens = config_.max_tokens;
        req.seed = config_.seed;
        
        auto start = std::chrono::high_resolution_clock::now();
        auto inference_result = backend_call(req);
        auto end = std::chrono::high_resolution_clock::now();
        
        if (inference_result.success) {
            result.success = true;
            result.latency_ms = std::chrono::duration<double, std::milli>(
                end - start).count();
        }
        
        return result;
    }

    StatisticalSummary CalculateStatistics(const std::vector<double>& samples) {
        StatisticalSummary summary;
        if (samples.empty()) return summary;
        
        summary.sample_count = static_cast<uint32_t>(samples.size());
        summary.mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        
        auto [min_it, max_it] = std::minmax_element(samples.begin(), samples.end());
        summary.min = *min_it;
        summary.max = *max_it;
        
        // Standard deviation
        double variance = 0.0;
        for (double s : samples) {
            variance += (s - summary.mean) * (s - summary.mean);
        }
        variance /= samples.size();
        summary.std_dev = std::sqrt(variance);
        
        // Percentiles
        std::vector<double> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        summary.median = sorted[sorted.size() / 2];
        summary.p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
        summary.p99 = sorted[static_cast<size_t>(sorted.size() * 0.99)];
        
        // 95% CI using t-distribution
        double t_value = 2.045;  // For 30+ samples
        summary.ci_half_width = t_value * (summary.std_dev / std::sqrt(samples.size()));
        
        return summary;
    }

    std::vector<HistogramBucket> CalculateHistogram(const std::vector<double>& samples, 
                                                     int num_buckets) {
        std::vector<HistogramBucket> histogram;
        if (samples.empty()) return histogram;
        
        auto [min_it, max_it] = std::minmax_element(samples.begin(), samples.end());
        double min_val = *min_it;
        double max_val = *max_it;
        double range = max_val - min_val;
        double bucket_size = range / num_buckets;
        
        // Initialize buckets
        for (int i = 0; i < num_buckets; ++i) {
            HistogramBucket bucket;
            bucket.min_ms = min_val + i * bucket_size;
            bucket.max_ms = min_val + (i + 1) * bucket_size;
            bucket.count = 0;
            bucket.percentage = 0.0;
            histogram.push_back(bucket);
        }
        
        // Count samples in each bucket
        for (double sample : samples) {
            int bucket_idx = static_cast<int>((sample - min_val) / bucket_size);
            if (bucket_idx >= num_buckets) bucket_idx = num_buckets - 1;
            histogram[bucket_idx].count++;
        }
        
        // Calculate percentages
        for (auto& bucket : histogram) {
            bucket.percentage = (100.0 * bucket.count) / samples.size();
        }
        
        return histogram;
    }

    double CalculateSkewness(const std::vector<double>& samples, double mean, double std_dev) {
        if (samples.size() < 3 || std_dev == 0) return 0.0;
        
        double sum_cubed = 0.0;
        for (double s : samples) {
            double diff = s - mean;
            sum_cubed += diff * diff * diff;
        }
        
        double n = static_cast<double>(samples.size());
        return (sum_cubed / n) / (std_dev * std_dev * std_dev);
    }

    double CalculateKurtosis(const std::vector<double>& samples, double mean, double std_dev) {
        if (samples.size() < 4 || std_dev == 0) return 0.0;
        
        double sum_fourth = 0.0;
        for (double s : samples) {
            double diff = s - mean;
            sum_fourth += diff * diff * diff * diff;
        }
        
        double n = static_cast<double>(samples.size());
        return (sum_fourth / n) / (std_dev * std_dev * std_dev * std_dev) - 3.0;
    }
};

// ============================================================================
// Example Usage
// ============================================================================

void RunExampleBenchmark(const std::string& backend = "sovereign") {
    std::cout << "Running Latency Distribution Example Benchmark\n";
    std::cout << "=============================================\n\n";
    
    // Configure the benchmark
    LatencyDistributionBenchmark::Config config;
    config.model = "phi-4";
    config.prompt = "What is the capital of France?";
    config.max_tokens = 64;
    config.measured_runs = 50;  // Reduce for example
    config.histogram_buckets = 8;
    
    LatencyDistributionBenchmark benchmark(config);
    
    // Run the benchmark
    LatencyDistributionBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else if (backend == "ollama") {
        results = benchmark.RunOllama();
    } else {
        std::cerr << "Unknown backend: " << backend << "\n";
        return;
    }
    
    // Print results
    LatencyDistributionBenchmark::PrintResults(results, backend);
    
    // Example: Access results programmatically
    if (results.success) {
        std::cout << "\nProgrammatic Access Example:\n";
        std::cout << "  Mean latency: " << results.latency_ms.mean << " ms\n";
        std::cout << "  CV: " << results.cv << " (lower is more consistent)\n";
        std::cout << "  Distribution is " 
                  << (results.skewness > 0 ? "right" : "left") 
                  << "-skewed\n";
    }
}

} // namespace Benchmark

// ============================================================================
// Main Entry Point (for standalone execution)
// ============================================================================

int main(int argc, char* argv[]) {
    std::string backend = "sovereign";
    
    if (argc > 1) {
        backend = argv[1];
    }
    
    Benchmark::RunExampleBenchmark(backend);
    
    return 0;
}
