// expanded_benchmark_suite.hpp
// Phase D.5 — Verification & Performance
// Comprehensive benchmark suite for empirical validation

#ifndef EXPANDED_BENCHMARK_SUITE_HPP
#define EXPANDED_BENCHMARK_SUITE_HPP

#include "benchmark_runner.hpp"
#include <vector>
#include <map>
#include <chrono>

namespace Benchmark {

// ============================================================================
// Expanded Metric Categories
// ============================================================================

struct InferenceMetricsExpanded {
    // Core metrics
    double prompt_tps;
    double generation_tps;
    double ttft_ms;
    double end_to_end_latency_ms;
    
    // Scaling metrics
    double tps_1k_context;
    double tps_4k_context;
    double tps_16k_context;
    double tps_64k_context;
    double tps_128k_context;
    
    // Quality metrics
    double perplexity;
    double coherence_score;
    uint32_t tokens_generated;
    
    // Resource metrics
    double peak_memory_mb;
    double avg_memory_mb;
    double gpu_utilization_percent;
    double cpu_utilization_percent;
    double power_consumption_watts;
    
    // Stability metrics
    double latency_variance;
    double tps_consistency;
    uint32_t timeout_count;
    uint32_t error_count;
    
    InferenceMetricsExpanded()
        : prompt_tps(0.0), generation_tps(0.0), ttft_ms(0.0)
        , end_to_end_latency_ms(0.0), tps_1k_context(0.0)
        , tps_4k_context(0.0), tps_16k_context(0.0)
        , tps_64k_context(0.0), tps_128k_context(0.0)
        , perplexity(0.0), coherence_score(0.0)
        , tokens_generated(0), peak_memory_mb(0.0)
        , avg_memory_mb(0.0), gpu_utilization_percent(0.0)
        , cpu_utilization_percent(0.0), power_consumption_watts(0.0)
        , latency_variance(0.0), tps_consistency(0.0)
        , timeout_count(0), error_count(0)
    {}
};

struct SwarmMetricsExpanded {
    // Throughput metrics
    double agents_per_second;
    double tasks_completed_per_second;
    double consensus_time_ms;
    double coordination_overhead_ms;
    
    // Scaling metrics
    double efficiency_2_agents;
    double efficiency_4_agents;
    double efficiency_8_agents;
    double efficiency_16_agents;
    double efficiency_32_agents;
    
    // Quality metrics
    double consensus_accuracy;
    double conflict_resolution_time_ms;
    uint32_t consensus_failures;
    
    // Resource metrics
    double memory_per_agent_mb;
    double cpu_overhead_percent;
    double network_bytes_exchanged;
    
    SwarmMetricsExpanded()
        : agents_per_second(0.0), tasks_completed_per_second(0.0)
        , consensus_time_ms(0.0), coordination_overhead_ms(0.0)
        , efficiency_2_agents(0.0), efficiency_4_agents(0.0)
        , efficiency_8_agents(0.0), efficiency_16_agents(0.0)
        , efficiency_32_agents(0.0), consensus_accuracy(0.0)
        , conflict_resolution_time_ms(0.0), consensus_failures(0)
        , memory_per_agent_mb(0.0), cpu_overhead_percent(0.0)
        , network_bytes_exchanged(0.0)
    {}
};

struct PlannerMetrics {
    // Build metrics
    double seg_build_time_ms;
    double plan_complexity;
    uint32_t nodes_in_graph;
    uint32_t edges_in_graph;
    
    // Execution metrics
    double planning_latency_ms;
    double replanning_latency_ms;
    double adaptation_time_ms;
    
    // Quality metrics
    double plan_success_rate;
    double goal_achievement_rate;
    double optimality_score;
    
    // Resource metrics
    double memory_during_planning_mb;
    double cpu_during_planning_percent;
    
    PlannerMetrics()
        : seg_build_time_ms(0.0), plan_complexity(0.0)
        , nodes_in_graph(0), edges_in_graph(0)
        , planning_latency_ms(0.0), replanning_latency_ms(0.0)
        , adaptation_time_ms(0.0), plan_success_rate(0.0)
        , goal_achievement_rate(0.0), optimality_score(0.0)
        , memory_during_planning_mb(0.0)
        , cpu_during_planning_percent(0.0)
    {}
};

struct AutonomyMetricsExpanded {
    // Decision metrics
    double decisions_per_second;
    double decision_latency_ms;
    double decision_quality_score;
    
    // Learning metrics
    double learning_convergence_time_ms;
    double policy_improvement_rate;
    double exploration_exploitation_ratio;
    
    // Self-correction metrics
    double error_detection_time_ms;
    double correction_latency_ms;
    double self_correction_success_rate;
    
    // Emergence metrics
    double pattern_recognition_accuracy;
    double role_assignment_efficiency;
    double intent_alignment_score;
    
    AutonomyMetricsExpanded()
        : decisions_per_second(0.0), decision_latency_ms(0.0)
        , decision_quality_score(0.0), learning_convergence_time_ms(0.0)
        , policy_improvement_rate(0.0), exploration_exploitation_ratio(0.0)
        , error_detection_time_ms(0.0), correction_latency_ms(0.0)
        , self_correction_success_rate(0.0)
        , pattern_recognition_accuracy(0.0)
        , role_assignment_efficiency(0.0), intent_alignment_score(0.0)
    {}
};

struct RecoveryMetricsExpanded {
    // Detection metrics
    double failure_detection_time_ms;
    double false_positive_rate;
    double detection_accuracy;
    
    // Recovery metrics
    double rollback_time_ms;
    double checkpoint_restore_time_ms;
    double state_reconstruction_time_ms;
    
    // Success metrics
    double recovery_success_rate;
    double data_loss_bytes;
    double recovery_fidelity_score;
    
    // Stability metrics
    double time_to_stabilize_ms;
    uint32_t cascading_failures_prevented;
    
    RecoveryMetricsExpanded()
        : failure_detection_time_ms(0.0), false_positive_rate(0.0)
        , detection_accuracy(0.0), rollback_time_ms(0.0)
        , checkpoint_restore_time_ms(0.0)
        , state_reconstruction_time_ms(0.0)
        , recovery_success_rate(0.0), data_loss_bytes(0.0)
        , recovery_fidelity_score(0.0), time_to_stabilize_ms(0.0)
        , cascading_failures_prevented(0)
    {}
};

struct StabilityMetrics {
    // Oscillation metrics
    double oscillation_frequency;
    double oscillation_amplitude;
    double damping_ratio;
    
    // Safety metrics
    double safety_violations_per_hour;
    double safety_envelope_breaches;
    double graceful_degradation_score;
    
    // Long-run metrics
    double uptime_percent;
    double mean_time_between_failures_hours;
    double availability_score;
    
    // Determinism metrics
    double output_variance;
    double repeatability_score;
    uint32_t deterministic_runs;
    
    StabilityMetrics()
        : oscillation_frequency(0.0), oscillation_amplitude(0.0)
        , damping_ratio(0.0), safety_violations_per_hour(0.0)
        , safety_envelope_breaches(0.0), graceful_degradation_score(0.0)
        , uptime_percent(0.0), mean_time_between_failures_hours(0.0)
        , availability_score(0.0), output_variance(0.0)
        , repeatability_score(0.0), deterministic_runs(0)
    {}
};

// ============================================================================
// Expanded Benchmark Configuration
// ============================================================================

struct ExpandedBenchmarkConfig {
    // Test duration
    std::chrono::seconds warmup_duration;
    std::chrono::seconds measurement_duration;
    std::chrono::seconds stability_test_duration;
    
    // Scaling parameters
    std::vector<uint32_t> context_lengths;
    std::vector<uint32_t> swarm_sizes;
    std::vector<uint32_t> agent_counts;
    
    // Load parameters
    uint32_t concurrent_requests;
    double target_qps;
    
    // Quality thresholds
    double min_acceptable_tps;
    double max_acceptable_latency_ms;
    double min_acceptable_quality_score;
    
    // Determinism
    uint32_t repeat_count;
    uint32_t seed;
    bool require_deterministic;
    
    ExpandedBenchmarkConfig()
        : warmup_duration(std::chrono::seconds(30))
        , measurement_duration(std::chrono::seconds(300))
        , stability_test_duration(std::chrono::seconds(3600))
        , context_lengths({1024, 4096, 16384, 65536, 131072})
        , swarm_sizes({2, 4, 8, 16, 32})
        , agent_counts({1, 4, 16, 64})
        , concurrent_requests(16)
        , target_qps(10.0)
        , min_acceptable_tps(50.0)
        , max_acceptable_latency_ms(1000.0)
        , min_acceptable_quality_score(0.8)
        , repeat_count(5)
        , seed(42)
        , require_deterministic(true)
    {}
};

// ============================================================================
// Expanded Benchmark Runner
// ============================================================================

class ExpandedBenchmarkRunner {
public:
    ExpandedBenchmarkRunner();
    ~ExpandedBenchmarkRunner();
    
    // Configuration
    void SetConfig(const ExpandedBenchmarkConfig& config);
    
    // Inference benchmarks
    InferenceMetricsExpanded RunInferenceBenchmark(BenchmarkTarget target);
    std::map<uint32_t, InferenceMetricsExpanded> RunContextScalingBenchmark(
        BenchmarkTarget target);
    
    // Swarm benchmarks
    SwarmMetricsExpanded RunSwarmBenchmark(BenchmarkTarget target);
    std::map<uint32_t, SwarmMetricsExpanded> RunSwarmScalingBenchmark(
        BenchmarkTarget target);
    
    // Planner benchmarks
    PlannerMetrics RunPlannerBenchmark(BenchmarkTarget target);
    
    // Autonomy benchmarks
    AutonomyMetricsExpanded RunAutonomyBenchmark(BenchmarkTarget target);
    
    // Recovery benchmarks
    RecoveryMetricsExpanded RunRecoveryBenchmark(BenchmarkTarget target);
    
    // Stability benchmarks
    StabilityMetrics RunStabilityBenchmark(BenchmarkTarget target);
    
    // Comparative analysis
    struct ComparisonResult {
        std::string metric_name;
        double sovereign_value;
        double ollama_value;
        double improvement_factor;
        bool sovereign_wins;
        bool statistically_significant;
        double p_value;
    };
    
    std::vector<ComparisonResult> CompareResults(
        const InferenceMetricsExpanded& sovereign,
        const InferenceMetricsExpanded& ollama);
    
    // Regression detection
    struct RegressionResult {
        std::string metric_name;
        double baseline_value;
        double current_value;
        double percent_change;
        bool is_regression;
        Severity severity;
    };
    
    std::vector<RegressionResult> DetectRegressions(
        const std::map<std::string, double>& baseline,
        const std::map<std::string, double>& current);
    
    // Report generation
    void GenerateHTMLReport(const std::string& path);
    void GenerateJSONReport(const std::string& path);
    void GenerateCIReport(const std::string& path);
    
private:
    ExpandedBenchmarkConfig config_;
    
    // Statistical helpers
    double CalculateMean(const std::vector<double>& values);
    double CalculateStdDev(const std::vector<double>& values);
    double CalculatePValue(const std::vector<double>& sample1,
                           const std::vector<double>& sample2);
    bool IsStatisticallySignificant(double p_value);
    
    // Resource monitoring
    double MeasureMemoryUsage();
    double MeasureCPUUsage();
    double MeasureGPUUsage();
    double MeasurePowerConsumption();
};

// ============================================================================
// CI Performance Regression Framework
// ============================================================================

class CIRegressionFramework {
public:
    CIRegressionFramework();
    ~CIRegressionFramework();
    
    // Configuration
    void SetBaselinePath(const std::string& path);
    void SetOutputPath(const std::string& path);
    void SetThresholds(double critical_threshold,
                       double warning_threshold);
    
    // Execution
    bool RunRegressionCheck();
    
    // Results
    struct RegressionCheckResult {
        bool passed;
        uint32_t critical_regressions;
        uint32_t warning_regressions;
        uint32_t improvements;
        std::vector<std::string> details;
        std::string summary;
    };
    
    RegressionCheckResult GetResult() const;
    
    // GitHub Actions integration
    void GenerateGitHubActionsOutput();
    void PostGitHubComment(const std::string& pr_number);
    
private:
    std::string baseline_path_;
    std::string output_path_;
    double critical_threshold_;
    double warning_threshold_;
    RegressionCheckResult last_result_;
};

} // namespace Benchmark

#endif // EXPANDED_BENCHMARK_SUITE_HPP
