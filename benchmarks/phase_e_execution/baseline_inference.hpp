#pragma once

#include "../hotpatch_tps/hotpatch_tps_benchmark.hpp"
#include "hardware_calibration.hpp"
#include <vector>
#include <map>
#include <functional>

namespace rawrxd {
namespace benchmarks {

/**
 * Phase E.1 Batch 2/5: Baseline Inference Measurements
 * 
 * Captures pre-hotpatch performance metrics for comparison.
 * Establishes the control group for all hotpatch experiments.
 */

// Model configuration for baseline
struct BaselineModelConfig {
    std::string model_name;
    std::string model_path;
    std::string quantization;  // Q4, Q5, Q8, FP16
    int context_length;
    int batch_size;
    std::vector<std::string> test_prompts;
    int warmup_tokens;
    int measurement_tokens;
};

// Baseline measurement results
struct BaselineMeasurement {
    std::string model_name;
    std::string quantization;
    int context_length;
    
    // TPS metrics
    double prompt_tps_mean;
    double prompt_tps_stddev;
    double generation_tps_mean;
    double generation_tps_stddev;
    double batch_tps_mean;
    
    // Latency metrics
    double ttft_ms_mean;
    double ttft_ms_p95;
    double ttft_ms_p99;
    double token_latency_ms_mean;
    double token_latency_ms_p95;
    double token_latency_ms_p99;
    
    // Resource metrics
    double peak_memory_mb;
    double avg_memory_mb;
    double peak_gpu_utilization;
    double avg_gpu_utilization;
    double kv_cache_usage_percent;
    double power_draw_watts;
    
    // Statistical confidence
    StatisticalMetrics prompt_tps_stats;
    StatisticalMetrics generation_tps_stats;
    int sample_count;
    double confidence_level;
    
    // Metadata
    std::string hardware_profile_id;
    std::chrono::system_clock::time_point timestamp;
    int repetition_number;
};

// Complete baseline results for a model
struct ModelBaselineResults {
    BaselineModelConfig config;
    std::vector<BaselineMeasurement> repetitions;
    
    // Aggregated statistics
    StatisticalMetrics aggregated_prompt_tps;
    StatisticalMetrics aggregated_generation_tps;
    StatisticalMetrics aggregated_ttft;
    StatisticalMetrics aggregated_latency;
    
    // Validation
    bool is_stable;  // Coefficient of variation < threshold
    double stability_score;
    std::vector<std::string> warnings;
};

// Baseline benchmark configuration
struct BaselineBenchmarkConfig {
    // Repetition settings
    int min_repetitions = 30;
    int max_repetitions = 50;
    double target_cv_threshold = 0.05;  // Stop when CV < 5%
    
    // Measurement settings
    int warmup_tokens = 512;
    int measurement_tokens = 2048;
    double measurement_duration_min = 2.0;
    
    // Statistical settings
    double confidence_level = 0.95;
    int min_samples_for_ci = 30;
    
    // Stability requirements
    double max_acceptable_cv = 0.10;  // 10% coefficient of variation
    int stability_check_window = 10;
    
    // Hardware reference
    HardwareProfile hardware_profile;
};

// Baseline inference benchmark
class BaselineInferenceBenchmark {
public:
    explicit BaselineInferenceBenchmark(const BaselineBenchmarkConfig& config);
    
    // Run complete baseline for a model
    ModelBaselineResults RunModelBaseline(const BaselineModelConfig& model_config);
    
    // Run multiple models
    std::vector<ModelBaselineResults> RunModelMatrix(
        const std::vector<BaselineModelConfig>& models);
    
    // Individual measurement
    BaselineMeasurement RunSingleMeasurement(const BaselineModelConfig& model_config);
    
    // Predefined model configs
    static BaselineModelConfig GetPhi3MiniConfig();
    static BaselineModelConfig GetMistral7BConfig();
    static BaselineModelConfig GetLlama3_8BConfig();
    static BaselineModelConfig GetCodestral22BConfig();
    
    // Export
    std::string ExportToJson(const std::vector<ModelBaselineResults>& results);
    std::string ExportToMarkdown(const std::vector<ModelBaselineResults>& results);
    std::string ExportToCsv(const std::vector<ModelBaselineResults>& results);

private:
    BaselineBenchmarkConfig config_;
    
    // Internal methods
    bool CheckStability(const std::vector<BaselineMeasurement>& measurements);
    StatisticalMetrics AggregateMeasurements(
        const std::vector<BaselineMeasurement>& measurements,
        std::function<double(const BaselineMeasurement&)> extractor);
    double CalculateCV(const StatisticalMetrics& stats);
    
    // Platform-specific measurement
    BaselineMeasurement MeasureInference(const BaselineModelConfig& model_config);
    void WarmupModel(const BaselineModelConfig& model_config);
};

// Predefined benchmark matrices
std::vector<BaselineModelConfig> GetSmallModelMatrix();   // 3B-7B models
std::vector<BaselineModelConfig> GetMediumModelMatrix();  // 13B-34B models
std::vector<BaselineModelConfig> GetLargeModelMatrix();   // 70B+ models
std::vector<BaselineModelConfig> GetFullValidationMatrix(); // All models

// Comparison utilities
struct BaselineComparison {
    std::string model_name;
    double rawrxd_baseline_tps;
    double ollama_baseline_tps;  // If available
    double rawrxd_vs_ollama_percent;
};

// Validation report
struct BaselineValidationReport {
    std::vector<ModelBaselineResults> results;
    HardwareProfile hardware;
    bool all_models_stable;
    int total_models_tested;
    int stable_models;
    std::vector<std::string> unstable_models;
    
    std::string ToMarkdown() const;
    std::string ToJson() const;
};

BaselineValidationReport GenerateBaselineReport(
    const std::vector<ModelBaselineResults>& results,
    const HardwareProfile& hardware);

} // namespace benchmarks
} // namespace rawrxd
