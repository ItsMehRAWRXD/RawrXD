//============================================================================
// nevm_benchmark.hpp
// RawrXD N-EVM Validation and Benchmark Suite
// Compare NEVM vs traditional execution
//============================================================================

#pragma once

#include "nevm_v2.hpp"
#include "nevm_transformer_engine.hpp"
#include <chrono>
#include <vector>
#include <string>

namespace RawrXD {
namespace NEVM {
namespace Benchmark {

//============================================================================
// Benchmark Configuration
//============================================================================

struct BenchmarkConfig {
    // Model
    std::wstring model_path;
    std::string model_format;  // "gguf", "safetensors", etc.
    
    // Test parameters
    uint32_t num_warmup_iterations;
    uint32_t num_benchmark_iterations;
    uint32_t batch_size;
    uint32_t sequence_lengths[5];  // Test multiple lengths
    
    // NEVM settings
    bool use_adaptive_precision;
    bool use_prefetch;
    BlockGranularity precision_granularity;
    
    // Baseline settings
    bool run_baseline;  // Compare against llama.cpp style
    std::string baseline_command;  // External command to run baseline
};

//============================================================================
// Metrics Collection
//============================================================================

struct TokenMetrics {
    uint64_t timestamp_us;
    uint32_t token_id;
    float latency_ms;
    PrecisionMode precision_used;
    bool cache_hit;
    bool precision_switched;
};

struct LayerMetrics {
    uint32_t layer_id;
    float latency_ms;
    uint32_t precision_switches;
    size_t memory_accessed_bytes;
    size_t working_set_bytes;
};

struct MemoryMetrics {
    uint64_t timestamp_us;
    size_t vram_used;
    size_t ram_used;
    size_t cache_used;
    size_t working_set_bytes;
    float memory_pressure;
};

//============================================================================
// Benchmark Results
//============================================================================

struct BenchmarkResults {
    // Configuration
    std::string model_name;
    uint32_t num_layers;
    uint32_t hidden_dim;
    uint32_t num_heads;
    
    // Throughput
    struct {
        float tokens_per_sec_mean;
        float tokens_per_sec_p50;
        float tokens_per_sec_p99;
        float prefill_tokens_per_sec;
        float decode_tokens_per_sec;
    } throughput;
    
    // Latency
    struct {
        float time_to_first_token_ms;
        float inter_token_latency_mean_ms;
        float inter_token_latency_p50_ms;
        float inter_token_latency_p99_ms;
    } latency;
    
    // Memory
    struct {
        size_t peak_vram_bytes;
        size_t peak_ram_bytes;
        size_t avg_working_set_bytes;
        float memory_efficiency;  // tokens/sec per GB
    } memory;
    
    // NEVM-specific
    struct {
        float prefetch_hit_rate;
        uint32_t precision_transitions_per_token;
        uint32_t stall_cycles;
        float stall_percentage;
        float avg_effective_bits;
        std::map<PrecisionMode, float> precision_distribution;
    } nevm_specific;
    
    // Comparison (if baseline run)
    struct {
        float speedup_vs_baseline;
        float memory_reduction_vs_baseline;
        float quality_score_vs_baseline;  // Perplexity comparison
    } comparison;
    
    // Raw data for analysis
    std::vector<TokenMetrics> token_metrics;
    std::vector<LayerMetrics> layer_metrics;
    std::vector<MemoryMetrics> memory_timeline;
};

//============================================================================
// Benchmark Runner
//============================================================================

class BenchmarkRunner {
public:
    explicit BenchmarkRunner(const BenchmarkConfig& config);
    ~BenchmarkRunner();
    
    // Initialize NEVM and load model
    bool Initialize();
    
    // Run complete benchmark suite
    BenchmarkResults RunBenchmark();
    
    // Run specific tests
    BenchmarkResults RunPrefillTest(uint32_t seq_len);
    BenchmarkResults RunDecodeTest(uint32_t num_tokens);
    BenchmarkResults RunEndToEndTest(uint32_t prompt_len, uint32_t generation_len);
    
    // Export results
    bool ExportJSON(const std::string& path, const BenchmarkResults& results);
    bool ExportCSV(const std::string& path, const BenchmarkResults& results);
    bool ExportReport(const std::string& path, const BenchmarkResults& results);
    
private:
    BenchmarkConfig config_;
    
    std::unique_ptr<NEVM_v2> vm_;
    std::unique_ptr<TransformerEngine> engine_;
    std::unique_ptr<GGUF_PassthroughLoader> loader_;
    
    // Metrics collection
    std::vector<TokenMetrics> token_metrics_;
    std::vector<LayerMetrics> layer_metrics_;
    std::vector<MemoryMetrics> memory_timeline_;
    
    // Timing
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = std::chrono::time_point<Clock>;
    
    // Private methods
    void Warmup();
    void CollectMetrics();
    void RecordToken(uint32_t token_id, float latency_ms);
    void RecordLayer(uint32_t layer_id, float latency_ms);
    void RecordMemory();
    
    BenchmarkResults AnalyzeResults();
    float CalculatePercentile(const std::vector<float>& values, float percentile);
};

//============================================================================
// Validation Suite
// Prove NEVM executes correctly
//============================================================================

class ValidationSuite {
public:
    struct TestResult {
        std::string test_name;
        bool passed;
        std::string error_message;
        float execution_time_ms;
    };
    
    // Run all validation tests
    static std::vector<TestResult> RunAllTests(NEVM_v2* vm, 
                                                 GGUF_PassthroughLoader* loader);
    
    // Individual tests
    static TestResult TestVirtualABI(NEVM_v2* vm);
    static TestResult TestMMUTranslation(NEVM_v2* vm);
    static TestResult TestPrecisionTransitions(NEVM_v2* vm);
    static TestResult TestPrefetchOverlap(NEVM_v2* vm);
    static TestResult TestResidencyStates(NEVM_v2* vm);
    static TestResult TestBlockGranularPrecision(NEVM_v2* vm);
    static TestResult TestKVCacheManagement(NEVM_v2* vm);
    static TestResult TestNumericalAccuracy(NEVM_v2* vm, GGUF_PassthroughLoader* loader);
    
    // Generate validation report
    static bool GenerateReport(const std::string& path, 
                                const std::vector<TestResult>& results);
};

//============================================================================
// Comparison: NEVM vs llama.cpp
//============================================================================

class LlamaCppComparison {
public:
    struct ComparisonConfig {
        std::wstring model_path;
        std::string llama_cpp_path;  // Path to llama-cli executable
        uint32_t num_tokens;
        std::string prompt;
    };
    
    struct ComparisonResult {
        // NEVM results
        float nevms_time_ms;
        size_t nevms_vram_bytes;
        size_t nevms_ram_bytes;
        
        // llama.cpp results
        float llama_time_ms;
        size_t llama_vram_bytes;
        size_t llama_ram_bytes;
        
        // Comparison
        float speedup;
        float memory_reduction;
        float quality_ratio;  // Perplexity NEVM / llama.cpp
    };
    
    // Run comparison
    static ComparisonResult Compare(const ComparisonConfig& config);
    
    // Generate comparison report
    static bool GenerateReport(const std::string& path, 
                                const ComparisonResult& result);
};

//============================================================================
// Profiling Tools
// Detailed performance analysis
//============================================================================

class Profiler {
public:
    // CPU profiling
    struct CPUSample {
        uint64_t timestamp;
        uint64_t cycles;
        const char* function_name;
        uint32_t line_number;
    };
    
    // Memory profiling
    struct MemorySample {
        uint64_t timestamp;
        size_t allocation_size;
        const char* allocation_site;
        bool is_allocation;  // true=alloc, false=free
    };
    
    // GPU profiling (if applicable)
    struct GPUSample {
        uint64_t timestamp;
        uint64_t gpu_cycles;
        const char* kernel_name;
        size_t bytes_transferred;
    };
    
    void BeginProfiling();
    void EndProfiling();
    
    void RecordCPUSample(const char* function, uint32_t line);
    void RecordMemorySample(size_t size, const char* site, bool is_alloc);
    void RecordGPUSample(const char* kernel, size_t bytes);
    
    // Generate flame graph data
    bool ExportFlameGraph(const std::string& path);
    
    // Generate memory timeline
    bool ExportMemoryTimeline(const std::string& path);
    
private:
    std::vector<CPUSample> cpu_samples_;
    std::vector<MemorySample> memory_samples_;
    std::vector<GPUSample> gpu_samples_;
    
    std::mutex mutex_;
    bool profiling_;
};

//============================================================================
// C API for Benchmarking
//============================================================================

extern "C" {
    // Run benchmark
    NEVM_EXPORT int NEVM_Benchmark_Run(const char* config_json, 
                                        const char* output_path);
    
    // Run validation
    NEVM_EXPORT int NEVM_Validation_Run(const char* model_path,
                                          const char* report_path);
    
    // Compare with llama.cpp
    NEVM_EXPORT int NEVM_Compare_LlamaCpp(const char* model_path,
                                           const char* llama_cpp_path,
                                           const char* output_path);
}

} // namespace Benchmark
} // namespace NEVM
} // namespace RawrXD
