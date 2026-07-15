#pragma once
// ============================================================================
// End-to-End Benchmark Harness for RawrXD Inference Stack
// ============================================================================
// Runs real GGUF models through the complete pipeline:
// Tokenizer → SEG → AVX512 Kernels → FlashAttention → C8 Speculative Decoding
// ============================================================================

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Benchmark {

// ============================================================================
// Benchmark Configuration
// ============================================================================
struct BenchmarkConfig {
    // Model configuration
    std::string model_path;           // Path to GGUF model
    std::string tokenizer_path;       // Path to tokenizer
    
    // Inference configuration
    uint32_t max_tokens = 256;        // Max tokens to generate
    uint32_t prompt_tokens = 32;      // Number of prompt tokens
    float temperature = 0.8f;         // Sampling temperature
    uint32_t top_k = 40;              // Top-k sampling
    float top_p = 0.95f;              // Top-p sampling
    
    // Speculative decoding configuration
    bool use_speculative = true;      // Enable C8 speculative decoding
    uint32_t draft_tokens = 4;        // Number of draft tokens
    float min_accept_prob = 0.6f;     // Minimum acceptance probability
    
    // Benchmark configuration
    uint32_t warmup_iterations = 3;   // Warmup runs
    uint32_t benchmark_iterations = 10; // Benchmark runs
    bool enable_telemetry = true;     // Enable MASM telemetry
    bool save_detailed_log = true;    // Save per-layer logs
    
    // Hardware configuration
    uint32_t num_threads = 0;         // 0 = auto-detect
    bool pin_threads = false;         // Pin threads to cores
};

// ============================================================================
// Benchmark Results
// ============================================================================
struct TokenMetrics {
    uint32_t token_id;
    float latency_ms;                 // Time to generate this token
    float tokens_per_sec;             // Instantaneous throughput
    bool is_draft;                    // Was this a draft token?
    bool accepted;                    // Was it accepted (for draft)?
    uint64_t cycles;                  // CPU cycles (if telemetry enabled)
};

struct LayerMetrics {
    std::string layer_name;
    float time_ms;
    uint64_t cycles;
    float percent_of_total;
};

struct BenchmarkResults {
    // Overall metrics
    float total_time_ms;
    float tokens_per_sec;
    float time_to_first_token_ms;
    float avg_latency_per_token_ms;
    float peak_memory_mb;
    float cpu_usage_percent;
    
    // Token-level metrics
    std::vector<TokenMetrics> token_metrics;
    
    // Layer-level metrics (if telemetry enabled)
    std::vector<LayerMetrics> layer_metrics;
    
    // Speculative decoding metrics (if enabled)
    uint32_t total_draft_tokens = 0;
    uint32_t accepted_draft_tokens = 0;
    float draft_acceptance_rate = 0.0f;
    float speculative_speedup = 1.0f;
    
    // Hardware metrics
    float avg_cpu_freq_ghz;
    uint32_t threads_used;
    
    // Configuration used
    BenchmarkConfig config;
    
    // Export to JSON
    std::string ToJson() const;
    
    // Export to CSV (for spreadsheet analysis)
    std::string ToCsv() const;
    
    // Human-readable summary
    std::string Summary() const;
};

// ============================================================================
// Benchmark Harness
// ============================================================================
class EndToEndBenchmark {
public:
    EndToEndBenchmark();
    ~EndToEndBenchmark();
    
    // Initialize with configuration
    bool Initialize(const BenchmarkConfig& config);
    
    // Run the benchmark
    BenchmarkResults Run();
    
    // Run with custom prompt
    BenchmarkResults RunWithPrompt(const std::string& prompt);
    
    // Get last error
    std::string GetLastError() const;
    
    // Progress callback
    using ProgressCallback = std::function<void(uint32_t tokens_generated, uint32_t total_tokens)>;
    void SetProgressCallback(ProgressCallback callback);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Utility Functions
// ============================================================================

// Detect hardware capabilities
struct HardwareInfo {
    std::string cpu_name;
    uint32_t num_cores;
    uint32_t num_threads;
    bool has_avx512;
    bool has_avx2;
    bool has_fma;
    float estimated_max_gflops;
    size_t l1_cache_size;
    size_t l2_cache_size;
    size_t l3_cache_size;
    size_t memory_size;
};

HardwareInfo DetectHardware();

// Estimate theoretical max throughput
float EstimateTheoreticalThroughput(const HardwareInfo& hw, 
                                     uint32_t hidden_size,
                                     uint32_t num_layers,
                                     uint32_t num_heads);

// Compare results against theoretical max
struct PerformanceAnalysis {
    float achieved_vs_theoretical_percent;
    std::string bottleneck_analysis;
    std::vector<std::string> recommendations;
};

PerformanceAnalysis AnalyzePerformance(const BenchmarkResults& results,
                                        const HardwareInfo& hw);

} // namespace Benchmark
} // namespace RawrXD
