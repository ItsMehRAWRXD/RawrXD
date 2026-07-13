#pragma once

#include "../sovereign_vs_ollama/include/benchmark_common.hpp"
#include <vector>
#include <string>
#include <functional>
#include <chrono>

namespace rawrxd {
namespace benchmarks {

/**
 * Hotpatch TPS Benchmark
 * 
 * Measures actual token throughput improvement when applying
 * runtime MASM hotpatches to a live inference pipeline.
 * 
 * This benchmark answers: "Does hotpatching measurably increase TPS?"
 */

// Patch types that can be applied
enum class HotpatchType {
    SCHEDULER_OPTIMIZATION,      // Task scheduler tuning
    KERNEL_GEMM_REPLACE,         // GEMM kernel replacement
    KERNEL_ATTENTION_REPLACE,    // Attention kernel replacement
    MEMORY_ALLOCATOR_PATCH,      // Memory allocation strategy
    SIMD_PATH_SELECTION,         // AVX-512/AVX2 path selection
    KV_CACHE_POLICY,             // KV cache management policy
    BATCHING_STRATEGY,         // Dynamic batching adjustment
    THREAD_AFFINITY_PATCH,      // CPU thread pinning optimization
    QUANTIZATION_KERNEL,         // Quantized kernel path
    ROPE_KERNEL_REPLACE          // RoPE embedding optimization
};

std::string HotpatchTypeToString(HotpatchType type);

// Patch application result
struct HotpatchResult {
    bool success = false;
    std::chrono::microseconds application_time{0};
    std::string patch_version;
    std::string error_message;
    
    // Validation
    bool checksum_verified = false;
    bool signature_valid = false;
    bool rollback_available = false;
};

// TPS measurement sample
struct TPSMeasurement {
    double timestamp_seconds;      // Time from benchmark start
    double prompt_tps;           // Prompt processing tokens/sec
    double generation_tps;       // Generation tokens/sec
    double batch_tps;            // Batched throughput
    double memory_usage_mb;      // Memory at sample time
    double gpu_utilization;      // GPU % (if applicable)
    
    // Latency metrics
    double ttft_ms;              // Time to first token
    double token_latency_ms;     // Per-token latency
    double p95_latency_ms;
    double p99_latency_ms;
};

// Phase of the benchmark
enum class BenchmarkPhase {
    WARMUP,
    BASELINE_SAMPLING,
    PATCH_APPLICATION,
    POST_PATCH_SAMPLING,
    COOLDOWN
};

// Configuration for hotpatch TPS benchmark
struct HotpatchTPSConfig {
    // Model configuration
    std::string model_path;
    std::string model_name;
    int context_length = 4096;
    int batch_size = 1;
    
    // Sampling configuration
    int warmup_seconds = 30;
    int baseline_sampling_seconds = 120;
    int post_patch_sampling_seconds = 120;
    int cooldown_seconds = 30;
    double sampling_interval_ms = 100.0;  // Sample every 100ms
    
    // Patch configuration
    HotpatchType patch_type = HotpatchType::KERNEL_GEMM_REPLACE;
    std::string patch_path;  // Path to .masm patch file
    
    // Statistical configuration
    double confidence_level = 0.95;
    int min_samples_required = 100;
    
    // Stability checks
    bool verify_stability_envelope = true;
    bool verify_safety_gate = true;
    bool verify_rollback_engine = true;
    
    // Test prompts
    std::vector<std::string> test_prompts;
    
    // Hardware isolation
    bool lock_cpu_affinity = true;
    bool disable_turbo_boost = true;
    bool isolate_gpu = true;
};

// Results from a single phase
struct PhaseResults {
    std::vector<TPSMeasurement> samples;
    StatisticalMetrics prompt_tps_stats;
    StatisticalMetrics generation_tps_stats;
    StatisticalMetrics latency_stats;
    
    // Derived metrics
    double mean_power_efficiency;  // tokens/joule (if power monitoring available)
    double stability_score;        // Variance-based stability metric
};

// Complete benchmark results
struct HotpatchTPSResults {
    // Configuration
    HotpatchTPSConfig config;
    BenchmarkManifest manifest;
    
    // Phase results
    PhaseResults warmup;
    PhaseResults baseline;
    PhaseResults post_patch;
    
    // Patch metadata
    HotpatchResult patch_result;
    std::chrono::milliseconds patch_application_time{0};
    
    // Comparison
    StatisticalComparison prompt_tps_comparison;
    StatisticalComparison generation_tps_comparison;
    StatisticalComparison latency_comparison;
    
    // Effect sizes
    double prompt_tps_effect_size;      // Cohen's d
    double generation_tps_effect_size;
    double latency_effect_size;
    
    // Significance
    bool prompt_tps_significant;
    bool generation_tps_significant;
    bool latency_significant;
    
    // Stability envelope
    bool stability_maintained;
    int safety_violations;
    int oscillation_events;
    bool rollback_triggered;
    
    // Overall verdict
    double improvement_percent;
    std::string verdict;  // "SIGNIFICANT_IMPROVEMENT", "NO_CHANGE", "REGRESSION"
    
    // Export methods
    std::string ToJson() const;
    std::string ToMarkdown() const;
    std::string ToCsv() const;
};

// Main benchmark class
class HotpatchTPSBenchmark {
public:
    explicit HotpatchTPSBenchmark(const HotpatchTPSConfig& config);
    
    // Run the complete benchmark
    HotpatchTPSResults Run();
    
    // Individual phases (for debugging/testing)
    PhaseResults RunWarmup();
    PhaseResults RunBaselineSampling();
    HotpatchResult ApplyPatch();
    PhaseResults RunPostPatchSampling();
    
    // Callbacks for progress reporting
    using ProgressCallback = std::function<void(BenchmarkPhase, double progress)>;
    using SampleCallback = std::function<void(const TPSMeasurement&)>;
    
    void SetProgressCallback(ProgressCallback callback);
    void SetSampleCallback(SampleCallback callback);

private:
    HotpatchTPSConfig config_;
    ProgressCallback progress_callback_;
    SampleCallback sample_callback_;
    
    // Internal methods
    PhaseResults SamplePhase(int duration_seconds, BenchmarkPhase phase);
    TPSMeasurement TakeSample();
    StatisticalComparison ComparePhases(const PhaseResults& baseline, 
                                        const PhaseResults& post_patch,
                                        const std::string& metric_name);
    double CalculateEffectSize(const StatisticalMetrics& baseline,
                               const StatisticalMetrics& post_patch);
    bool CheckStabilityEnvelope(const PhaseResults& results);
    
    // Patch application (simulated for benchmark - real implementation would call MASM layer)
    HotpatchResult ApplyMASMHotpatch();
    
    // Hardware isolation
    void LockCPUAffinity();
    void DisableTurboBoost();
    void IsolateGPU();
    void RestoreSystemState();
};

// Factory function
std::unique_ptr<HotpatchTPSBenchmark> CreateHotpatchTPSBenchmark(
    const HotpatchTPSConfig& config);

// Predefined benchmark configurations
HotpatchTPSConfig GetSmallModelConfig();   // 3B-7B models
HotpatchTPSConfig GetMediumModelConfig(); // 13B-34B models
HotpatchTPSConfig GetLargeModelConfig();   // 70B+ models

// Comparison utilities
struct HotpatchComparison {
    std::string model_category;
    double baseline_prompt_tps;
    double hotpatched_prompt_tps;
    double improvement_percent;
    double effect_size;
    bool statistically_significant;
    std::string patch_type_used;
};

std::vector<HotpatchComparison> RunHotpatchMatrixBenchmark();

} // namespace benchmarks
} // namespace rawrxd
