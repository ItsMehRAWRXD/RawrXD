// Hotpatch Benchmark Suite
// Measures RawrXD's native x64 MASM hotpatch capabilities
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <chrono>
#include <functional>
#include <map>

namespace RawrXD {
namespace Benchmark {

// ============================================================================
// Hotpatch Benchmark Types
// ============================================================================

enum class HotpatchType {
    KERNEL_OPTIMIZATION = 0,    // matmul, attention, etc.
    SCHEDULER_POLICY = 1,       // scheduling algorithm
    MEMORY_MANAGER = 2,         // allocator, cache policy
    SAFETY_ENVELOPE = 3,      // stability thresholds
    TELEMETRY_FILTER = 4,     // metrics collection
    DECISION_SCORER = 5,       // risk calculation
    CUSTOM = 6
};

enum class PatchComplexity {
    SIMPLE = 0,      // Single function replacement
    MODERATE = 1,  // Multi-function, same module
    COMPLEX = 2,   // Cross-module, stateful
    CRITICAL = 3   // Core runtime modification
};

struct HotpatchMetrics {
    // Timing
    double patch_load_time_ms = 0.0;
    double patch_activation_time_ms = 0.0;
    double total_deployment_time_ms = 0.0;
    double rollback_time_ms = 0.0;
    
    // Disruption
    double inference_interruption_tokens = 0.0;
    double thread_pause_duration_ms = 0.0;
    double cache_invalidation_percent = 0.0;
    
    // Safety
    bool atomic_application = false;
    bool rollback_successful = false;
    bool state_preserved = false;
    
    // Performance delta
    double tps_before = 0.0;
    double tps_after = 0.0;
    double latency_before_ms = 0.0;
    double latency_after_ms = 0.0;
    double memory_delta_mb = 0.0;
};

struct HotpatchBenchmarkResult {
    std::string benchmark_id;
    std::string patch_name;
    HotpatchType patch_type;
    PatchComplexity complexity;
    
    HotpatchMetrics metrics;
    
    // Statistical confidence
    double confidence_interval_95 = 0.0;
    int sample_count = 0;
    
    // Comparison
    double improvement_percent = 0.0;
    double effect_size_cohens_d = 0.0;
    bool statistically_significant = false;
    
    // Metadata
    std::chrono::steady_clock::time_point timestamp;
    std::string git_commit;
    std::string hardware_fingerprint;
};

// ============================================================================
// Hotpatch Benchmark Scenarios
// ============================================================================

class HotpatchBenchmark {
public:
    struct Config {
        // Test parameters
        int warmup_iterations = 10;
        int measurement_iterations = 50;
        double confidence_level = 0.95;
        
        // Workload
        std::string model_path;
        int prompt_tokens = 512;
        int generation_tokens = 256;
        int batch_size = 1;
        
        // Patch parameters
        bool verify_rollback = true;
        bool measure_disruption = true;
        bool profile_memory = true;
        
        // Safety
        double max_acceptable_disruption_ms = 100.0;
        double min_improvement_threshold_percent = 5.0;
    };
    
    explicit HotpatchBenchmark(const Config& config);
    ~HotpatchBenchmark();
    
    // Core benchmark methods
    HotpatchBenchmarkResult RunPatchApplicationBenchmark(
        const std::string& patch_path,
        HotpatchType type,
        PatchComplexity complexity
    );
    
    HotpatchBenchmarkResult RunPerformanceDeltaBenchmark(
        const std::string& baseline_kernel,
        const std::string& patched_kernel,
        const std::string& workload_type
    );
    
    HotpatchBenchmarkResult RunOptimizationLoopBenchmark(
        const std::vector<std::string>& patch_sequence,
        int iterations_per_patch
    );
    
    HotpatchBenchmarkResult RunFaultRecoveryBenchmark(
        const std::string& fault_type,
        const std::string& recovery_patch
    );
    
    HotpatchBenchmarkResult RunBinaryIndependenceBenchmark();
    
    // Comparison benchmarks
    std::vector<HotpatchBenchmarkResult> RunComparisonMatrix(
        const std::vector<std::string>& patch_set
    );
    
    // Long-running stability
    HotpatchBenchmarkResult RunLongRunStabilityBenchmark(
        int duration_hours,
        int patch_events_per_hour
    );
    
private:
    Config config_;
    
    // Measurement helpers
    double MeasurePatchLoadTime(const std::string& patch_path);
    double MeasurePatchActivationTime();
    double MeasureInferenceDisruption();
    
    // Workload execution
    double RunInferenceWorkload(int iterations);
    double MeasureTPS();
    double MeasureLatency();
    
    // Statistical analysis
    double CalculateImprovement(double before, double after);
    double CalculateEffectSize(
        const std::vector<double>& baseline,
        const std::vector<double>& patched
    );
    bool CheckStatisticalSignificance(
        const std::vector<double>& baseline,
        const std::vector<double>& patched
    );
    
    // Safety checks
    bool ValidatePatchIntegrity(const std::string& patch_path);
    bool VerifyRollbackCapability();
    bool CheckStatePreservation();
};

// ============================================================================
// Hotpatch vs Rebuild Comparison
// ============================================================================

struct DeploymentComparison {
    // Traditional deployment
    double traditional_stop_time_ms = 0.0;
    double traditional_build_time_ms = 0.0;
    double traditional_deploy_time_ms = 0.0;
    double traditional_restart_time_ms = 0.0;
    double traditional_warmup_time_ms = 0.0;
    double traditional_total_downtime_ms = 0.0;
    bool traditional_cache_loss = true;
    int traditional_operator_actions = 5;
    
    // Hotpatch deployment
    double hotpatch_detection_time_ms = 0.0;
    double hotpatch_generation_time_ms = 0.0;
    double hotpatch_application_time_ms = 0.0;
    double hotpatch_total_time_ms = 0.0;
    bool hotpatch_cache_loss = false;
    int hotpatch_operator_actions = 1;
    
    // Comparison
    double time_improvement_factor = 0.0;
    double downtime_reduction_percent = 0.0;
    int operator_effort_reduction = 0;
};

class DeploymentBenchmark {
public:
    DeploymentComparison RunDeploymentComparison(
        const std::string& bug_scenario,
        const std::string& fix_patch
    );
    
    std::vector<DeploymentComparison> RunScenarioMatrix(
        const std::vector<std::string>& scenarios
    );
};

// ============================================================================
// Results Aggregation
// ============================================================================

class HotpatchResultsAggregator {
public:
    struct AggregatedResults {
        // Summary statistics
        double mean_patch_time_ms = 0.0;
        double p95_patch_time_ms = 0.0;
        double mean_improvement_percent = 0.0;
        double mean_effect_size = 0.0;
        
        // Success rates
        double patch_success_rate = 0.0;
        double rollback_success_rate = 0.0;
        double atomic_application_rate = 0.0;
        
        // Comparison vs traditional
        double avg_deployment_speedup = 0.0;
        double avg_downtime_reduction = 0.0;
        
        // By complexity
        std::map<PatchComplexity, double> complexity_success_rates;
        std::map<PatchComplexity, double> complexity_patch_times;
        
        // By type
        std::map<HotpatchType, double> type_improvements;
    };
    
    AggregatedResults Aggregate(
        const std::vector<HotpatchBenchmarkResult>& results
    );
    
    void ExportToJson(
        const AggregatedResults& results,
        const std::string& output_path
    );
    
    void ExportToMarkdown(
        const AggregatedResults& results,
        const std::string& output_path
    );
    
    void GenerateComparisonReport(
        const AggregatedResults& hotpatch_results,
        const std::vector<DeploymentComparison>& deployment_results,
        const std::string& output_path
    );
};

// ============================================================================
// CLI Entry Point
// ============================================================================

int RunHotpatchBenchmarkMain(int argc, char* argv[]);

} // namespace Benchmark
} // namespace RawrXD
