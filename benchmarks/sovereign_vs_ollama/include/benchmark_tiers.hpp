// benchmark_tiers.hpp
// Phase D.5 Refined — 4-Tier Benchmark Structure with Statistical Rigor
//
// TIER 1: Runtime Performance (apples-to-apples comparisons)
// TIER 2: Agentic Capability (comparable features)
// TIER 3: Sovereign-Only Features (unique capabilities)
// TIER 4: Long-Term Reliability (soak tests)

#ifndef BENCHMARK_TIERS_HPP
#define BENCHMARK_TIERS_HPP

#include <vector>
#include <string>
#include <chrono>
#include <optional>
#include <map>

namespace Benchmark {

// ============================================================================
// Statistical Foundation
// ============================================================================

struct StatisticalSummary {
    double mean;
    double std_dev;
    double min;
    double max;
    double median;
    double p95;
    double p99;
    
    // Confidence interval (95%)
    double ci_lower;
    double ci_upper;
    double ci_half_width;
    
    // Sample info
    uint32_t sample_count;
    uint32_t warmup_runs;
    uint32_t measured_runs;
    
    StatisticalSummary()
        : mean(0.0), std_dev(0.0), min(0.0), max(0.0)
        , median(0.0), p95(0.0), p99(0.0)
        , ci_lower(0.0), ci_upper(0.0), ci_half_width(0.0)
        , sample_count(0), warmup_runs(0), measured_runs(0)
    {}
};

struct BenchmarkSample {
    double value;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, double> context;  // e.g., memory, cpu at sample time
};

// ============================================================================
// TIER 1: Runtime Performance (Apples-to-Apples)
// Both Sovereign and Ollama perform the same inference work
// ============================================================================

struct Tier1RuntimeMetrics {
    // Throughput
    StatisticalSummary prompt_tps;           // Tokens/second during prompt processing
    StatisticalSummary decode_tps;           // Tokens/second during generation
    StatisticalSummary total_tokens_per_sec; // Combined throughput
    
    // Latency
    StatisticalSummary ttft_ms;              // Time to first token
    StatisticalSummary end_to_end_latency_ms; // Full request latency
    StatisticalSummary inter_token_latency_ms; // Time between tokens
    
    // Percentiles
    StatisticalSummary latency_p50_ms;
    StatisticalSummary latency_p95_ms;
    StatisticalSummary latency_p99_ms;
    
    // Context scaling (1K -> 128K)
    struct ContextScalingPoint {
        uint32_t context_length;
        StatisticalSummary tps;
        StatisticalSummary latency_ms;
        double memory_mb;
    };
    std::vector<ContextScalingPoint> context_scaling;
    
    // Concurrent load
    struct LoadPoint {
        uint32_t concurrent_requests;
        StatisticalSummary tps;
        StatisticalSummary latency_ms;
        double error_rate;
    };
    std::vector<LoadPoint> load_scaling;
    
    // Resource utilization
    StatisticalSummary memory_peak_mb;
    StatisticalSummary memory_avg_mb;
    StatisticalSummary cpu_percent;
    StatisticalSummary gpu_percent;
    StatisticalSummary power_watts;
    
    // Test metadata
    std::string model_name;
    std::string quantization;
    uint32_t sequence_length;
    std::chrono::system_clock::time_point test_timestamp;
};

// ============================================================================
// TIER 2: Agentic Capability (Comparable Features)
// Features both systems can reasonably perform
// ============================================================================

struct Tier2AgenticMetrics {
    // Multi-step planning
    struct PlanningTask {
        std::string task_name;
        StatisticalSummary completion_time_ms;
        StatisticalSummary steps_taken;
        double success_rate;
        double plan_optimality_score;  // 0-1, how optimal was the plan
    };
    std::vector<PlanningTask> planning_tasks;
    
    // Tool use
    struct ToolUseTask {
        std::string tool_name;
        StatisticalSummary execution_time_ms;
        double success_rate;
        double correct_usage_rate;  // Did it use the tool correctly
    };
    std::vector<ToolUseTask> tool_use_tasks;
    
    // Structured output
    struct StructuredOutputTask {
        std::string format;  // "json", "xml", "yaml"
        StatisticalSummary generation_time_ms;
        double parse_success_rate;
        double schema_compliance_rate;
        double semantic_correctness_rate;
    };
    std::vector<StructuredOutputTask> structured_output_tasks;
    
    // Code generation
    struct CodeGenTask {
        std::string language;
        std::string task_description;
        StatisticalSummary generation_time_ms;
        double compilation_success_rate;
        double test_pass_rate;
        double benchmark_completion_rate;
    };
    std::vector<CodeGenTask> code_gen_tasks;
    
    // Overall agentic score
    double overall_agentic_score;  // Weighted composite
};

// ============================================================================
// TIER 3: Sovereign-Only Features (Unique Capabilities)
// Demonstrates capabilities unique to Sovereign runtime
// NOT "wins over Ollama" — self-contained demonstrations
// ============================================================================

struct Tier3SovereignMetrics {
    // SEG (Self-Evolving Graph) operations
    struct SEGMetrics {
        StatisticalSummary mutation_latency_ms;
        StatisticalSummary node_addition_time_ms;
        StatisticalSummary edge_modification_time_ms;
        StatisticalSummary graph_query_time_ms;
        uint32_t nodes_at_start;
        uint32_t nodes_at_end;
        uint32_t mutations_performed;
        double consistency_score;  // Graph remained valid throughout
    };
    SEGMetrics seg_metrics;
    
    // Rollback capabilities
    struct RollbackMetrics {
        StatisticalSummary checkpoint_creation_time_ms;
        StatisticalSummary rollback_time_ms;
        StatisticalSummary state_reconstruction_time_ms;
        double fidelity_score;  // How accurately was state restored
        uint32_t checkpoints_created;
        uint32_t rollbacks_performed;
    };
    RollbackMetrics rollback_metrics;
    
    // Swarm coordination (Sovereign-specific)
    struct SwarmMetrics {
        StatisticalSummary agent_spawn_time_ms;
        StatisticalSummary consensus_time_ms;
        StatisticalSummary coordination_overhead_ms;
        
        // Efficiency at different scales
        struct EfficiencyPoint {
            uint32_t agent_count;
            double efficiency;  // 0-1, ideal parallelism
            StatisticalSummary task_completion_time_ms;
        };
        std::vector<EfficiencyPoint> efficiency_scaling;
        
        double overall_efficiency_16_agents;  // The "Phi test"
        double consensus_accuracy;
    };
    SwarmMetrics swarm_metrics;
    
    // Autonomous recovery
    struct RecoveryMetrics {
        StatisticalSummary failure_detection_time_ms;
        StatisticalSummary autonomous_recovery_time_ms;
        double detection_accuracy;
        double false_positive_rate;
        double recovery_success_rate;
        uint32_t failures_injected;
        uint32_t failures_recovered;
    };
    RecoveryMetrics recovery_metrics;
    
    // Oscillation detection
    struct OscillationMetrics {
        StatisticalSummary detection_latency_ms;
        double damping_effectiveness;
        uint32_t oscillations_detected;
        uint32_t oscillations_damped;
        double stability_improvement;  // Before vs after
    };
    OscillationMetrics oscillation_metrics;
    
    // Decision quality
    struct DecisionMetrics {
        StatisticalSummary decision_latency_ms;
        double decision_quality_score;  // 0-1
        double learning_convergence_rate;
        double self_correction_rate;
        uint32_t decisions_made;
        uint32_t corrections_performed;
    };
    DecisionMetrics decision_metrics;
};

// ============================================================================
// TIER 4: Long-Term Reliability (Soak Tests)
// Run for hours/days, measure drift and stability
// ============================================================================

struct Tier4ReliabilityMetrics {
    // Test duration
    std::chrono::seconds duration;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    
    // Memory behavior
    struct MemoryMetrics {
        double initial_mb;
        double final_mb;
        double peak_mb;
        double growth_rate_mb_per_hour;
        double leak_score;  // 0-1, 1 = no leak detected
        std::vector<std::pair<double, double>> time_series;  // (hours, memory_mb)
    };
    MemoryMetrics memory;
    
    // Performance drift
    struct DriftMetrics {
        StatisticalSummary initial_tps;
        StatisticalSummary final_tps;
        double tps_drift_percent;  // Negative = degradation
        
        StatisticalSummary initial_latency_ms;
        StatisticalSummary final_latency_ms;
        double latency_drift_percent;  // Positive = degradation
        
        std::vector<std::pair<double, double>> tps_time_series;
        std::vector<std::pair<double, double>> latency_time_series;
    };
    DriftMetrics drift;
    
    // Stability
    struct StabilityMetrics {
        uint32_t total_requests;
        uint32_t successful_requests;
        uint32_t failed_requests;
        uint32_t timeout_requests;
        double success_rate;
        double error_rate;
        
        // Failure patterns
        uint32_t crashes;
        uint32_t recoveries;
        uint32_t unrecoverable_failures;
        
        // Availability
        double uptime_percent;
        double availability_percent;  // Excluding planned downtime
        double mtbf_hours;  // Mean time between failures
        double mttr_seconds;  // Mean time to recovery
    };
    StabilityMetrics stability;
    
    // Determinism
    struct DeterminismMetrics {
        uint32_t identical_runs;
        uint32_t divergent_runs;
        double repeatability_score;  // 0-1
        StatisticalSummary output_variance;
        bool deterministic_under_test_conditions;
    };
    DeterminismMetrics determinism;
    
    // Resource efficiency over time
    struct EfficiencyMetrics {
        double avg_cpu_percent;
        double avg_gpu_percent;
        double avg_power_watts;
        double total_energy_kwh;
        double efficiency_score;  // Work done per watt
    };
    EfficiencyMetrics efficiency;
};

// ============================================================================
// NEW: Developer Workflow Benchmark
// End-to-end tasks that mirror real usage
// ============================================================================

struct DeveloperWorkflowMetrics {
    struct WorkflowTask {
        std::string task_name;
        std::string description;
        
        // Timing
        StatisticalSummary wall_clock_time_ms;
        StatisticalSummary model_time_ms;  // Time spent in model inference
        StatisticalSummary tool_time_ms;   // Time spent in tool execution
        
        // Iterations
        uint32_t iterations_required;
        uint32_t max_iterations_allowed;
        double iteration_efficiency;  // iterations_required / max_iterations
        
        // Tool usage
        uint32_t tool_calls_made;
        uint32_t tool_calls_successful;
        double tool_success_rate;
        
        // Completion
        bool completed_successfully;
        double completion_quality_score;  // 0-1, how well was task completed
        uint32_t human_interventions_required;
        
        // Correctness
        double correctness_score;  // Did it produce correct output
        std::vector<std::string> verification_checks_passed;
        std::vector<std::string> verification_checks_failed;
    };
    
    // Standard workflow tasks
    WorkflowTask explain_repository;
    WorkflowTask locate_bug;
    WorkflowTask generate_patch;
    WorkflowTask compile_code;
    WorkflowTask run_tests;
    WorkflowTask produce_summary;
    
    // Composite metrics
    StatisticalSummary total_workflow_time_ms;
    double overall_success_rate;
    double overall_quality_score;
    double overall_correctness_score;
    uint32_t total_human_interventions;
    
    // Comparison to baseline
    double time_vs_baseline_percent;  // Negative = faster than baseline
    double quality_vs_baseline_percent;
};

// ============================================================================
// Baseline Management
// ============================================================================

struct BaselineRecord {
    std::string benchmark_name;
    std::string version;  // RawrXD version
    std::string git_commit;
    std::chrono::system_clock::time_point recorded_at;
    std::string hardware_fingerprint;
    
    // Stored metrics (serialized)
    std::string tier1_json;
    std::string tier2_json;
    std::string tier3_json;
    std::string tier4_json;
    std::string workflow_json;
};

class BaselineManager {
public:
    BaselineManager(const std::string& storage_path);
    
    // Save current results as new baseline
    void SaveBaseline(const std::string& name, 
                      const Tier1RuntimeMetrics& tier1,
                      const Tier2AgenticMetrics& tier2,
                      const Tier3SovereignMetrics& tier3,
                      const Tier4ReliabilityMetrics& tier4,
                      const DeveloperWorkflowMetrics& workflow);
    
    // Load baseline for comparison
    bool LoadBaseline(const std::string& name,
                      Tier1RuntimeMetrics& tier1,
                      Tier2AgenticMetrics& tier2,
                      Tier3SovereignMetrics& tier3,
                      Tier4ReliabilityMetrics& tier4,
                      DeveloperWorkflowMetrics& workflow);
    
    // List available baselines
    std::vector<std::string> ListBaselines();
    
    // Get default baseline (most recent stable)
    std::string GetDefaultBaseline();
    
private:
    std::string storage_path_;
};

// ============================================================================
// Comparison Results
// ============================================================================

struct TierComparisonResult {
    std::string metric_name;
    double current_mean;
    double baseline_mean;
    double percent_change;  // Positive = improvement (for throughput), negative = improvement (for latency)
    bool is_improvement;
    bool is_regression;
    bool is_significant;  // Statistically significant
    double confidence_level;  // e.g., 0.95 for 95%
    
    // Classification
    enum class Severity { NONE, INFO, WARNING, CRITICAL };
    Severity severity;
    
    // Trend (if historical data available)
    std::optional<double> trend_slope;  // Change per commit
    std::optional<std::string> trend_visualization;  // ASCII sparkline
};

struct FullComparisonReport {
    std::string baseline_version;
    std::string current_version;
    std::chrono::system_clock::time_point comparison_time;
    
    std::vector<TierComparisonResult> tier1_results;
    std::vector<TierComparisonResult> tier2_results;
    std::vector<TierComparisonResult> tier3_results;
    std::vector<TierComparisonResult> tier4_results;
    std::vector<TierComparisonResult> workflow_results;
    
    // Summary
    uint32_t total_improvements;
    uint32_t total_regressions;
    uint32_t critical_regressions;
    uint32_t warning_regressions;
    
    double overall_score_change;  // Weighted composite
    bool passes_regression_gates;
    
    // Qualification
    struct QualificationStatus {
        double overall_score;
        bool passed;
        std::map<std::string, double> category_scores;
    };
    QualificationStatus qualification;
};

// ============================================================================
// Configuration
// ============================================================================

struct RefinedBenchmarkConfig {
    // Statistical rigor
    uint32_t warmup_runs = 5;
    uint32_t measured_runs = 30;
    uint32_t random_seed = 42;
    double temperature = 0.0;  // Deterministic
    bool pin_cpu_affinity = true;
    bool lock_gpu_clocks = false;  // If supported
    double confidence_level = 0.95;  // 95% CI
    
    // Tier 1: Runtime
    std::vector<uint32_t> context_lengths = {1024, 4096, 16384, 65536, 131072};
    std::vector<uint32_t> concurrent_loads = {1, 4, 8, 16, 32};
    std::string model_name = "phi-4";
    std::string quantization = "Q4_K_M";
    
    // Tier 2: Agentic
    std::vector<std::string> planning_task_names = {
        "simple_sequence", "parallel_tasks", "conditional_branching", "error_recovery"
    };
    std::vector<std::string> tool_names = {
        "file_read", "file_write", "shell_exec", "grep_search", "semantic_search"
    };
    std::vector<std::string> output_formats = {"json", "xml"};
    std::vector<std::string> code_languages = {"python", "cpp", "rust"};
    
    // Tier 3: Sovereign
    std::vector<uint32_t> swarm_sizes = {2, 4, 8, 16, 32};
    uint32_t seg_mutation_count = 100;
    uint32_t rollback_test_count = 50;
    
    // Tier 4: Reliability
    std::vector<std::chrono::seconds> soak_durations = {
        std::chrono::hours(1),
        std::chrono::hours(6),
        std::chrono::hours(24)
    };
    std::chrono::seconds sampling_interval = std::chrono::seconds(60);
    
    // Regression thresholds
    double critical_regression_threshold = 0.20;  // 20% regression = block
    double warning_regression_threshold = 0.10;  // 10% regression = warn
    double improvement_celebration_threshold = 0.10;  // 10% improvement = celebrate
};

// ============================================================================
// Refined Benchmark Runner
// ============================================================================

class RefinedBenchmarkRunner {
public:
    RefinedBenchmarkRunner();
    ~RefinedBenchmarkRunner();
    
    void SetConfig(const RefinedBenchmarkConfig& config);
    void SetBaselineManager(BaselineManager* baseline);
    
    // Tier 1: Runtime Performance
    Tier1RuntimeMetrics RunTier1Benchmarks();
    
    // Tier 2: Agentic Capability
    Tier2AgenticMetrics RunTier2Benchmarks();
    
    // Tier 3: Sovereign-Only Features
    Tier3SovereignMetrics RunTier3Benchmarks();
    
    // Tier 4: Long-Term Reliability
    Tier4ReliabilityMetrics RunTier4Benchmarks(std::chrono::seconds duration);
    
    // Developer Workflow
    DeveloperWorkflowMetrics RunDeveloperWorkflowBenchmarks();
    
    // Full suite
    void RunFullBenchmarkSuite();
    
    // Comparison
    FullComparisonReport CompareAgainstBaseline(const std::string& baseline_name);
    FullComparisonReport CompareAgainstOllama();
    
    // Reporting
    void GenerateHTMLReport(const std::string& path);
    void GenerateJSONReport(const std::string& path);
    void GenerateMarkdownReport(const std::string& path);
    void GenerateCIReport(const std::string& path);  // GitHub Actions format
    
private:
    RefinedBenchmarkConfig config_;
    BaselineManager* baseline_;
    
    // Statistical helpers
    StatisticalSummary CalculateStatistics(const std::vector<double>& samples);
    double CalculateConfidenceInterval(const std::vector<double>& samples, double confidence);
    bool IsStatisticallySignificant(const StatisticalSummary& current,
                                    const StatisticalSummary& baseline);
    
    // Resource monitoring
    double MeasureMemoryUsageMB();
    double MeasureCPUPercent();
    double MeasureGPUPercent();
    double MeasurePowerWatts();
};

// ============================================================================
// CI Integration
// ============================================================================

class CIRegressionChecker {
public:
    CIRegressionChecker(const RefinedBenchmarkConfig& config);
    
    // Run check and return pass/fail
    bool RunCheck(const FullComparisonReport& report);
    
    // Generate GitHub Actions output
    void GenerateGitHubActionsOutput(const FullComparisonReport& report);
    
    // Generate PR comment
    std::string GeneratePRComment(const FullComparisonReport& report);
    
    // Generate trend visualization
    std::string GenerateTrendSparkline(const std::vector<double>& historical_values);
    
private:
    RefinedBenchmarkConfig config_;
};

// ============================================================================
// Qualification Scoring
// ============================================================================

struct QualificationCategory {
    std::string name;
    double score;  // 0-100
    double weight;
    bool passed;
    std::string status_icon;  // ✓, ⚠, ✗
};

class QualificationScorer {
public:
    QualificationScorer();
    
    // Calculate qualification scores from metrics
    std::vector<QualificationCategory> CalculateQualification(
        const Tier1RuntimeMetrics& tier1,
        const Tier2AgenticMetrics& tier2,
        const Tier3SovereignMetrics& tier3,
        const Tier4ReliabilityMetrics& tier4,
        const DeveloperWorkflowMetrics& workflow);
    
    // Overall qualification
    struct OverallQualification {
        double total_score;
        bool passed;
        std::vector<QualificationCategory> categories;
        std::vector<std::string> recommendations;
    };
    
    OverallQualification CalculateOverall(
        const std::vector<QualificationCategory>& categories);
    
    // Generate qualification dashboard data
    std::string GenerateDashboardJSON(const OverallQualification& qual);
};

} // namespace Benchmark

#endif // BENCHMARK_TIERS_HPP
