#pragma once

#include "../intelligence/SovereignPredictiveAutoscaling.hpp"
#include "../intelligence/SovereignAnomalyDetection.hpp"
#include "../intelligence/SovereignPerformanceAnalytics.hpp"
#include "../intelligence/SovereignAutomatedRemediation.hpp"
#include "StabilityBenchmarkIntegration.hpp"
#include <memory>
#include <functional>

namespace rawrxd {
namespace integration {

/**
 * Phase G.1 Batch 2/5: Intelligent Ops Telemetry Integration
 * 
 * Connects D.6 Intelligent Operations into benchmark execution:
 * - Predictive autoscaling with load forecasting
 * - Real-time anomaly detection during benchmarks
 * - Performance analytics with bottleneck classification
 * - Automated remediation trigger validation
 * - Distributed tracing and flame graph generation
 */

// Telemetry sample from benchmark execution
struct BenchmarkTelemetrySample {
    uint64_t timestamp_ms;
    uint64_t sample_number;
    
    // Performance metrics
    double tokens_per_second;
    double prompt_tps;
    double generation_tps;
    double latency_ms;
    double ttft_ms;
    double token_latency_ms;
    
    // Resource metrics
    double gpu_utilization_percent;
    double gpu_temperature_c;
    double gpu_power_w;
    double gpu_clock_mhz;
    double vram_usage_mb;
    double vram_bandwidth_gbps;
    
    double cpu_utilization_percent;
    double cpu_temperature_c;
    double memory_usage_mb;
    double memory_bandwidth_gbps;
    
    // AI-specific metrics
    size_t kv_cache_size_mb;
    double kv_cache_hit_rate;
    int active_contexts;
    int batch_size;
    
    // Stability metrics (from Batch 1)
    double stability_score;
    std::string stability_state;
    int oscillation_count;
    
    // Configuration state
    std::string active_patch;
    std::string model_name;
    std::string quantization;
    int context_length;
    std::string execution_phase;  // warmup, baseline, hotpatched, recovery
    
    // Derived metrics
    double throughput_efficiency;  // actual / theoretical max
    double power_efficiency;     // tokens per joule
    double memory_efficiency;    // tokens per MB
};

// Forecast result for benchmark prediction
struct BenchmarkForecast {
    std::string metric;  // tps, latency, temperature, etc.
    double current_value;
    double predicted_value_1min;
    double predicted_value_5min;
    double predicted_value_30min;
    double confidence_interval_95;
    double forecast_accuracy;  // historical accuracy of this model
    std::string trend;  // increasing, decreasing, stable
    std::string recommendation;
};

// Anomaly detected during benchmark
struct BenchmarkAnomaly {
    uint64_t timestamp_ms;
    uint64_t sample_number;
    AnomalyType type;
    std::string description;
    double severity;  // 0.0 - 1.0
    double expected_value;
    double actual_value;
    double deviation_percent;
    std::vector<std::string> possible_causes;
    std::string recommended_action;
    bool auto_remediated;
    std::string remediation_action;
    bool recovered;
    double recovery_time_ms;
};

// Bottleneck analysis result
struct BenchmarkBottleneck {
    BottleneckType type;
    double confidence;
    std::vector<std::string> evidence;
    std::string recommendation;
    std::vector<std::string> suggested_patches;
    double expected_improvement_percent;
};

// Performance trace span
struct BenchmarkTraceSpan {
    std::string operation;  // tokenize, attention, matmul, sampling, etc.
    uint64_t start_time_ms;
    uint64_t end_time_ms;
    uint64_t duration_us;
    std::string parent_span_id;
    std::string span_id;
    std::map<std::string, std::string> attributes;
    std::vector<BenchmarkTraceSpan> child_spans;
};

// Complete benchmark trace
struct BenchmarkTrace {
    std::string trace_id;
    std::string benchmark_name;
    uint64_t start_time_ms;
    uint64_t end_time_ms;
    std::vector<BenchmarkTraceSpan> spans;
    std::map<std::string, double> metrics;
};

// Flame graph data
struct FlameGraphNode {
    std::string function_name;
    std::string module;
    uint64_t samples;
    double total_percent;
    double self_percent;
    std::vector<FlameGraphNode> children;
};

// Remediation event
struct BenchmarkRemediation {
    uint64_t timestamp_ms;
    std::string trigger;  // anomaly, forecast, manual
    RemediationType action;
    std::string description;
    double confidence;
    bool approved;
    std::string approver;  // auto, safety_gate, human
    bool executed;
    bool successful;
    double execution_time_ms;
    double improvement_percent;
};

// Configuration for intelligent ops integration
struct IntelligentOpsConfig {
    // Forecasting
    bool enable_forecasting = true;
    int forecast_horizon_minutes = 30;
    ForecastingModel forecasting_model = ForecastingModel::ENSEMBLE;
    double forecast_confidence_threshold = 0.85;
    
    // Anomaly detection
    bool enable_anomaly_detection = true;
    DetectionAlgorithm anomaly_algorithm = DetectionAlgorithm::ENSEMBLE;
    double anomaly_sensitivity = 0.95;
    double anomaly_specificity = 0.99;
    bool auto_remediate_anomalies = true;
    
    // Performance analytics
    bool enable_tracing = true;
    double tracing_sampling_rate = 1.0;  // 100% for benchmarks
    bool enable_flame_graphs = true;
    bool enable_bottleneck_detection = true;
    
    // Remediation
    bool enable_auto_remediation = true;
    double remediation_confidence_threshold = 0.80;
    int max_concurrent_remediations = 2;
    std::chrono::seconds remediation_cooldown{30};
    
    // Telemetry
    bool export_telemetry = true;
    std::string telemetry_output_path = "./intelligent_ops_telemetry.json";
    int telemetry_flush_interval_seconds = 10;
};

// Complete intelligent ops context for a benchmark
struct IntelligentOpsContext {
    // Configuration
    IntelligentOpsConfig config;
    
    // Subsystems
    std::unique_ptr<SovereignPredictiveAutoscaling> forecaster;
    std::unique_ptr<SovereignAnomalyDetection> anomaly_detector;
    std::unique_ptr<SovereignPerformanceAnalytics> analytics;
    std::unique_ptr<SovereignAutomatedRemediation> remediation;
    
    // State
    std::vector<BenchmarkTelemetrySample> telemetry_samples;
    std::vector<BenchmarkForecast> forecasts;
    std::vector<BenchmarkAnomaly> anomalies;
    std::vector<BenchmarkBottleneck> bottlenecks;
    std::vector<BenchmarkTrace> traces;
    std::vector<BenchmarkRemediation> remediations;
    
    // Current trace
    std::unique_ptr<BenchmarkTrace> active_trace;
    std::vector<BenchmarkTraceSpan*> span_stack;
    
    // Metrics
    double forecast_accuracy = 0.0;
    int anomaly_true_positives = 0;
    int anomaly_false_positives = 0;
    int remediation_successes = 0;
    int remediation_failures = 0;
};

// Intelligent ops integrated benchmark runner
class IntelligentOpsBenchmarkRunner {
public:
    explicit IntelligentOpsBenchmarkRunner(const IntelligentOpsConfig& config);
    
    // Initialize for benchmark run
    void InitializeBenchmark(const std::string& benchmark_name, 
                             const std::string& model_name);
    
    // Telemetry collection
    void RecordTelemetrySample(const BenchmarkTelemetrySample& sample);
    void RecordTraceSpan(const std::string& operation,
                         std::function<void()> code);
    void StartSpan(const std::string& operation);
    void EndSpan();
    
    // Forecasting
    std::vector<BenchmarkForecast> GenerateForecasts();
    bool ShouldPreemptivelyScale();
    std::string GetScalingRecommendation();
    
    // Anomaly detection
    std::vector<BenchmarkAnomaly> DetectAnomalies();
    void HandleAnomaly(const BenchmarkAnomaly& anomaly);
    
    // Performance analytics
    std::vector<BenchmarkBottleneck> AnalyzeBottlenecks();
    FlameGraphNode GenerateFlameGraph();
    std::string GenerateLatencyBreakdown();
    
    // Remediation
    bool TriggerRemediation(const BenchmarkAnomaly& anomaly);
    bool ValidateRemediation(const BenchmarkRemediation& remediation);
    
    // Integration with stability (Batch 1)
    void IntegrateWithStabilityRunner(StabilityBenchmarkRunner* stability_runner);
    
    // Export
    std::string ExportTelemetryReport();
    std::string ExportForecastReport();
    std::string ExportAnomalyReport();
    std::string ExportBottleneckReport();
    std::string ExportRemediationReport();
    std::string ExportTraceReport();
    std::string ExportCompleteReport();
    
    // Finalize
    void FinalizeBenchmark();
    IntelligentOpsContext GetContext() const;

private:
    IntelligentOpsContext context_;
    std::string current_benchmark_name_;
    std::string current_model_name_;
    uint64_t benchmark_start_time_ms_;
    
    // Internal methods
    void InitializeSubsystems();
    void FlushTelemetry();
    double CalculateForecastAccuracy();
    void UpdateAnomalyMetrics(const BenchmarkAnomaly& anomaly, bool true_positive);
    BenchmarkRemediation CreateRemediation(const BenchmarkAnomaly& anomaly);
};

// Result wrapper with intelligent ops metadata
template<typename T>
struct IntelligentOpsBenchmarkResult {
    T benchmark_result;
    
    // Intelligent ops metadata
    std::vector<BenchmarkForecast> forecasts;
    std::vector<BenchmarkAnomaly> anomalies;
    std::vector<BenchmarkBottleneck> bottlenecks;
    std::vector<BenchmarkRemediation> remediations;
    BenchmarkTrace trace;
    FlameGraphNode flame_graph;
    
    // Metrics
    double forecast_accuracy;
    double anomaly_detection_precision;
    double anomaly_detection_recall;
    double remediation_success_rate;
    double bottleneck_detection_accuracy;
    
    // Verdict
    std::string verdict;
    bool benchmark_valid;
    std::vector<std::string> optimization_recommendations;
};

// Factory
std::unique_ptr<IntelligentOpsBenchmarkRunner> CreateIntelligentOpsBenchmarkRunner(
    const IntelligentOpsConfig& config = IntelligentOpsConfig());

// Predefined configurations
IntelligentOpsConfig GetStandardIntelligentOpsConfig();
IntelligentOpsConfig GetMinimalOverheadConfig();  // For performance-sensitive benchmarks
IntelligentOpsConfig GetMaximumInsightConfig();   // For deep analysis

// Integration helpers
void WireIntelligentOpsToBenchmarkOrchestrator(IntelligentOpsBenchmarkRunner* runner);
void WireIntelligentOpsToHotpatchBenchmark(IntelligentOpsBenchmarkRunner* runner);
void WireIntelligentOpsToStabilityRunner(IntelligentOpsBenchmarkRunner* iops_runner,
                                        StabilityBenchmarkRunner* stability_runner);

} // namespace integration
} // namespace rawrxd
