#pragma once
// ============================================================================
// Performance Benchmark Suite
// ============================================================================
// Data-driven optimization through comprehensive metrics
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <chrono>
#include <map>

namespace SEG {

// ============================================================================
// Benchmark Configuration
// ============================================================================

struct BenchmarkConfig {
    // Model configuration
    std::string model_path = "d:/models/ministral3_q4_0.gguf";
    
    // Test prompts
    std::vector<std::string> test_prompts = {
        "Hello",
        "The quick brown fox",
        "In the year 2026, artificial intelligence",
        "Once upon a time in a land far away"
    };
    
    // Generation settings
    size_t max_tokens = 20;
    size_t warmup_tokens = 5;  // Warmup before measurement
    
    // Sampling
    float temperature = 0.8f;
    int top_k = 40;
    float top_p = 0.95f;
    
    // Measurement
    size_t iterations = 3;  // Average over N runs
    bool enable_telemetry = true;
    bool enable_cpu_profiling = true;
    
    // Components to benchmark
    bool benchmark_embedding = true;
    bool benchmark_attention = true;
    bool benchmark_ffn = true;
    bool benchmark_sampling = true;
    bool benchmark_end_to_end = true;
};

// ============================================================================
// Performance Metrics
// ============================================================================

struct LayerMetrics {
    std::string layer_name;
    double avg_time_ms = 0.0;
    double min_time_ms = 0.0;
    double max_time_ms = 0.0;
    uint64_t cycles = 0;
    double gflops = 0.0;
    double memory_mb = 0.0;
};

struct ComponentMetrics {
    std::string component_name;
    double avg_time_ms = 0.0;
    double throughput = 0.0;  // ops/sec or tokens/sec
    double utilization = 0.0;  // CPU utilization %
    std::vector<LayerMetrics> layers;
};

struct BenchmarkResults {
    // Overall metrics
    double tokens_per_sec = 0.0;
    double time_to_first_token_ms = 0.0;
    double avg_token_latency_ms = 0.0;
    double total_time_ms = 0.0;
    
    // Component breakdown
    ComponentMetrics embedding;
    ComponentMetrics attention;
    ComponentMetrics ffn;
    ComponentMetrics sampling;
    ComponentMetrics end_to_end;
    
    // Per-layer breakdown
    std::vector<LayerMetrics> layer_breakdown;
    
    // System metrics
    double peak_memory_mb = 0.0;
    double avg_cpu_usage = 0.0;
    
    // Comparison baseline
    double vs_llamacpp_ratio = 0.0;  // Our perf / llama.cpp perf
};

// ============================================================================
// Benchmark Runner
// ============================================================================

class BenchmarkRunner {
public:
    explicit BenchmarkRunner(const BenchmarkConfig& config);
    
    // Run full benchmark suite
    BenchmarkResults Run();
    
    // Individual component benchmarks
    ComponentMetrics BenchmarkEmbedding();
    ComponentMetrics BenchmarkAttention();
    ComponentMetrics BenchmarkFFN();
    ComponentMetrics BenchmarkSampling();
    ComponentMetrics BenchmarkEndToEnd();
    
    // Export results
    void ExportCSV(const std::string& filename);
    void ExportJSON(const std::string& filename);
    void PrintReport();
    
    // Calculate overall metrics
    void CalculateOverallMetrics();
    
private:
    BenchmarkConfig config_;
    BenchmarkResults results_;
    
    // Timing utilities
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = Clock::time_point;
    
    struct Timer {
        TimePoint start;
        std::vector<double> measurements;
        
        void Start() { start = Clock::now(); }
        double Stop() {
            auto end = Clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            double ms = duration.count() / 1000.0;
            measurements.push_back(ms);
            return ms;
        }
        double Average() const {
            if (measurements.empty()) return 0.0;
            double sum = 0.0;
            for (double m : measurements) sum += m;
            return sum / measurements.size();
        }
    };
    
    // CPU profiling
    double GetCurrentCPUUsage();
    double GetPeakMemoryUsage();
    
    // Calculate GFLOPS for operations
    double CalculateMatMulGFLOPS(size_t M, size_t N, size_t K, double time_ms);
    double CalculateAttentionGFLOPS(size_t seq_len, size_t head_dim, double time_ms);
};

// ============================================================================
// Quick Benchmark
// ============================================================================

// Run quick benchmark with default settings
BenchmarkResults QuickBenchmark(const std::string& model_path);

// Compare implementations
void CompareImplementations(const std::string& model_path);

// ============================================================================
// Baseline Reference
// ============================================================================

// Expected llama.cpp performance for comparison
struct ReferencePerformance {
    static constexpr double LLAMACPP_TOKENS_PER_SEC = 30.0;
    static constexpr double LLAMACPP_LATENCY_MS = 33.0;  // 1000/30
    static constexpr double LLAMACPP_MEMORY_EFFICIENCY = 0.8;  // 80% of model size
};

} // namespace SEG
