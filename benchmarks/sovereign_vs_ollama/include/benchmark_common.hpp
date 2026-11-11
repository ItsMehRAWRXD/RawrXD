// Sovereign vs Ollama Benchmark Suite - Common Definitions
// Copyright (c) 2026 RawrXD Team
// Licensed under MIT

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <optional>
#include <functional>
#include <memory>

namespace rawrxd::benchmark {

// ============================================================================
// Version and Constants
// ============================================================================
constexpr const char* BENCHMARK_SUITE_VERSION = "1.0.0";
constexpr const char* BENCHMARK_SUITE_NAME = "Sovereign vs Ollama Agentic Benchmark";
constexpr int DEFAULT_SWARM_SIZE = 16;
constexpr int WARMUP_RUNS = 10;
constexpr int MEASURED_RUNS = 50;

// ============================================================================
// Backend Types
// ============================================================================
enum class BackendType {
    UNKNOWN = 0,
    SOVEREIGN = 1,      // RawrXD Sovereign Runtime
    OLLAMA = 2,         // Ollama HTTP API
    LLAMA_CPP = 3,      // Direct llama.cpp
    LLAMA_CPP_SERVER = 4 // llama.cpp server mode
};

inline const char* BackendTypeToString(BackendType type) {
    switch (type) {
        case BackendType::SOVEREIGN: return "sovereign";
        case BackendType::OLLAMA: return "ollama";
        case BackendType::LLAMA_CPP: return "llama_cpp";
        case BackendType::LLAMA_CPP_SERVER: return "llama_cpp_server";
        default: return "unknown";
    }
}

// ============================================================================
// Benchmark Categories
// ============================================================================
enum class BenchmarkCategory {
    INFERENCE = 0,
    AGENT_SPAWN = 1,
    SWARM = 2,
    SEG_EXECUTION = 3,
    DECISION_MAKING = 4,
    SELF_CORRECTION = 5,
    RESPONSE_QUALITY = 6,
    CONTEXT_HANDLING = 7,
    AUTONOMOUS_RUNTIME = 8,
    RESOURCE_USAGE = 9
};

inline const char* CategoryToString(BenchmarkCategory cat) {
    switch (cat) {
        case BenchmarkCategory::INFERENCE: return "inference";
        case BenchmarkCategory::AGENT_SPAWN: return "agent_spawn";
        case BenchmarkCategory::SWARM: return "swarm";
        case BenchmarkCategory::SEG_EXECUTION: return "seg_execution";
        case BenchmarkCategory::DECISION_MAKING: return "decision_making";
        case BenchmarkCategory::SELF_CORRECTION: return "self_correction";
        case BenchmarkCategory::RESPONSE_QUALITY: return "response_quality";
        case BenchmarkCategory::CONTEXT_HANDLING: return "context_handling";
        case BenchmarkCategory::AUTONOMOUS_RUNTIME: return "autonomous_runtime";
        case BenchmarkCategory::RESOURCE_USAGE: return "resource_usage";
        default: return "unknown";
    }
}

// ============================================================================
// Timing Utilities
// ============================================================================
using Clock = std::chrono::high_resolution_clock;
using TimePoint = std::chrono::time_point<Clock>;
using Duration = std::chrono::nanoseconds;

struct Timer {
    TimePoint start;
    TimePoint end;
    bool running = false;
    
    void Start() {
        start = Clock::now();
        running = true;
    }
    
    void Stop() {
        end = Clock::now();
        running = false;
    }
    
    double ElapsedMs() const {
        auto duration = running ? (Clock::now() - start) : (end - start);
        return std::chrono::duration<double, std::milli>(duration).count();
    }
    
    double ElapsedUs() const {
        auto duration = running ? (Clock::now() - start) : (end - start);
        return std::chrono::duration<double, std::micro>(duration).count();
    }
    
    double ElapsedNs() const {
        auto duration = running ? (Clock::now() - start) : (end - start);
        return static_cast<double>(duration.count());
    }
};

// ============================================================================
// Confidence Interval
// ============================================================================
struct ConfidenceInterval {
    double lower = 0.0;      // Lower bound
    double upper = 0.0;      // Upper bound
    double confidence = 0.95; // Confidence level (e.g., 0.95 for 95%)
    double margin_of_error = 0.0; // ± margin
    
    bool Contains(double value) const {
        return value >= lower && value <= upper;
    }
    
    double Width() const {
        return upper - lower;
    }
    
    std::string ToString() const {
        char buf[128];
        snprintf(buf, sizeof(buf), "[%.3f, %.3f] (%.0f%% CI, ±%.3f)",
                 lower, upper, confidence * 100, margin_of_error);
        return std::string(buf);
    }
};

// ============================================================================
// Statistical Metrics with Confidence Intervals
// ============================================================================
struct StatisticalMetrics {
    double mean = 0.0;
    double median = 0.0;
    double stddev = 0.0;
    double min = 0.0;
    double max = 0.0;
    double p95 = 0.0;
    double p99 = 0.0;
    int sample_count = 0;
    
    // Confidence intervals
    ConfidenceInterval mean_ci;      // CI for the mean
    ConfidenceInterval median_ci;    // CI for the median (percentile bootstrap)
    ConfidenceInterval stddev_ci;    // CI for standard deviation (chi-square)
    
    static StatisticalMetrics Calculate(const std::vector<double>& samples);
    static StatisticalMetrics CalculateWithCI(const std::vector<double>& samples, 
                                               double confidence = 0.95);
    
    // Calculate confidence interval for mean using t-distribution
    static ConfidenceInterval CalculateMeanCI(const std::vector<double>& samples, 
                                               double confidence = 0.95);
    
    // Calculate confidence interval for median using percentile bootstrap
    static ConfidenceInterval CalculateMedianCI(const std::vector<double>& samples, 
                                                 double confidence = 0.95,
                                                 int bootstrap_iterations = 1000);
    
    // Calculate confidence interval for standard deviation using chi-square
    static ConfidenceInterval CalculateStdDevCI(const std::vector<double>& samples,
                                               double confidence = 0.95);
    
    // Check if two metrics are statistically different (non-overlapping CIs)
    bool IsSignificantlyDifferent(const StatisticalMetrics& other, 
                                   double confidence = 0.95) const;
    
    // Calculate effect size (Cohen's d)
    double EffectSize(const StatisticalMetrics& other) const;
};

// ============================================================================
// Benchmark Configuration
// ============================================================================
struct BenchmarkConfig {
    BackendType backend = BackendType::SOVEREIGN;
    std::string model_path;
    std::string model_name = "phi-3-mini-Q4";
    int swarm_size = DEFAULT_SWARM_SIZE;
    int context_length = 4096;
    int max_tokens = 512;
    float temperature = 0.7f;
    std::string gpu_backend = "vulkan"; // vulkan, cuda, metal, cpu
    int gpu_layers = 99;
    int threads = 16;
    
    // Ollama specific
    std::string ollama_url = "http://localhost:11434";
    std::string ollama_model = "phi3:mini";
    
    // Sovereign specific
    std::string sovereign_endpoint = "http://localhost:8080";
    bool enable_seg = true;
    bool enable_learning = true;
    bool enable_telemetry = true;
    
    // Benchmark control
    int warmup_runs = WARMUP_RUNS;
    int measured_runs = MEASURED_RUNS;
    bool verbose = false;
    std::string output_dir = "reports";
};

// ============================================================================
// Resource Metrics
// ============================================================================
struct ResourceMetrics {
    double cpu_percent = 0.0;
    double memory_mb = 0.0;
    double vram_mb = 0.0;
    double gpu_percent = 0.0;
    double power_watts = 0.0;
    
    static ResourceMetrics Sample();
};

// ============================================================================
// Response Quality Metrics
// ============================================================================
struct QualityMetrics {
    double structure_score = 0.0;      // 0-100, headings, lists, code blocks
    double correctness_score = 0.0;      // 0-100, factual accuracy
    double depth_score = 0.0;            // 0-100, reasoning depth
    double coherence_score = 0.0;        // 0-100, logical flow
    double actionability_score = 0.0;    // 0-100, concrete steps
    double overall_score = 0.0;          // weighted average
};

// ============================================================================
// Benchmark Result
// ============================================================================
struct BenchmarkResult {
    std::string benchmark_id;
    std::string benchmark_name;
    BenchmarkCategory category;
    BackendType backend;
    std::string timestamp;
    std::string model_name;
    
    // Timing
    double total_time_ms = 0.0;
    double warmup_time_ms = 0.0;
    StatisticalMetrics latency;
    StatisticalMetrics throughput;
    
    // Success/Quality
    double success_rate = 0.0;
    QualityMetrics quality;
    
    // Resources
    ResourceMetrics resources;
    
    // Custom metrics
    std::map<std::string, double> custom_metrics;
    
    // Raw samples (optional, for debugging)
    std::vector<double> raw_latencies;
    
    std::string ToJson() const;
    static BenchmarkResult FromJson(const std::string& json);
};

// ============================================================================
// Benchmark Base Class
// ============================================================================
class Benchmark {
public:
    virtual ~Benchmark() = default;
    
    virtual const char* GetName() const = 0;
    virtual BenchmarkCategory GetCategory() const = 0;
    virtual BenchmarkResult Run(const BenchmarkConfig& config) = 0;
    
protected:
    void Warmup(const BenchmarkConfig& config);
    void ReportProgress(const std::string& message);
};

// ============================================================================
// Backend Adapter Interface
// ============================================================================
class BackendAdapter {
public:
    virtual ~BackendAdapter() = default;
    
    virtual bool Initialize(const BenchmarkConfig& config) = 0;
    virtual void Shutdown() = 0;
    
    // Core inference
    virtual std::string Generate(const std::string& prompt, int max_tokens) = 0;
    virtual double GetLastLatencyMs() const = 0;
    virtual double GetLastTokensPerSec() const = 0;
    
    // Agent operations
    virtual std::string SpawnAgent(const std::string& role, const std::string& context) = 0;
    virtual bool DestroyAgent(const std::string& agent_id) = 0;
    virtual std::vector<std::string> ListAgents() = 0;
    
    // Swarm operations
    virtual std::vector<std::string> SpawnSwarm(int count, const std::string& task) = 0;
    virtual std::vector<std::string> ExecuteSwarm(const std::vector<std::string>& agents, 
                                                   const std::string& task) = 0;
    
    // SEG operations (Sovereign only, no-op for others)
    virtual bool SupportsSEG() const { return false; }
    virtual std::string CreateExecutionGraph(const std::string& plan) = 0;
    virtual bool ExecuteGraph(const std::string& graph_id) = 0;
    
    // Decision operations
    virtual std::string MakeDecision(const std::string& context, 
                                      const std::vector<std::string>& options) = 0;
    
    // Resource sampling
    virtual ResourceMetrics GetResourceUsage() = 0;
};

// Factory function
std::unique_ptr<BackendAdapter> CreateBackendAdapter(BackendType type);

} // namespace rawrxd::benchmark
