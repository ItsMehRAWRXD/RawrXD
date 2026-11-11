#pragma once

#include "baseline_inference.hpp"
#include "../hotpatch_tps/hotpatch_tps_benchmark.hpp"
#include <chrono>
#include <vector>

namespace rawrxd {
namespace benchmarks {

/**
 * Phase E.1 Batch 3/5: Hotpatch Intervention
 * 
 * Applies runtime hotpatches and measures immediate effects.
 * Captures the critical moment of patch application and recovery.
 */

// Patch application event
struct PatchApplicationEvent {
    std::chrono::system_clock::time_point timestamp;
    HotpatchType patch_type;
    std::string patch_version;
    std::chrono::microseconds activation_time;
    bool cache_preserved;
    int tokens_lost;
    bool rollback_available;
    std::string checksum_verified;
    bool signature_valid;
    
    // System state at application
    double gpu_temperature_c;
    double gpu_utilization_percent;
    double memory_usage_mb;
    double system_load;
};

// Transition metrics (baseline → hotpatched)
struct TransitionMetrics {
    // Timing
    std::chrono::milliseconds time_to_apply;
    std::chrono::milliseconds time_to_resume;
    std::chrono::milliseconds total_interruption;
    
    // Performance delta
    double tps_before;
    double tps_immediate_after;  // First 10 seconds
    double tps_stabilized_after; // After 60 seconds
    double tps_improvement_percent;
    
    // Stability
    double variance_before;
    double variance_after;
    bool variance_increased;
    
    // Recovery quality
    int oscillation_events;
    bool safety_gate_triggered;
    bool rollback_engine_activated;
    double stability_score;
};

// Complete hotpatch intervention result
struct HotpatchInterventionResult {
    // Configuration
    std::string model_name;
    std::string baseline_measurement_id;
    HotpatchType patch_type;
    std::string patch_path;
    
    // Events
    PatchApplicationEvent application_event;
    TransitionMetrics transition;
    
    // Post-patch measurements
    std::vector<TPSMeasurement> post_patch_samples;
    StatisticalMetrics post_patch_prompt_tps;
    StatisticalMetrics post_patch_generation_tps;
    StatisticalMetrics post_patch_latency;
    
    // Comparison to baseline
    double prompt_tps_improvement_percent;
    double generation_tps_improvement_percent;
    double latency_improvement_percent;
    double effect_size_cohens_d;
    bool statistically_significant;
    double p_value_estimate;
    
    // Validation
    bool no_regression;
    bool stability_maintained;
    bool safety_maintained;
    std::string verdict;  // "ACCEPT", "REJECT", "ROLLBACK"
    
    // Metadata
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::chrono::seconds total_duration;
    std::string hardware_profile_id;
};

// Patch composition test (do patches stack?)
struct PatchCompositionTest {
    std::string model_name;
    std::vector<HotpatchType> patch_sequence;
    
    // Expected vs actual
    double expected_combined_improvement;  // Multiplicative
    double actual_combined_improvement;
    double composition_efficiency;  // actual / expected
    
    // Individual results
    std::vector<HotpatchInterventionResult> individual_results;
    HotpatchInterventionResult combined_result;
    
    // Analysis
    bool patches_stack_linearly;
    bool patches_interfere;
    std::vector<std::string> interference_notes;
};

// Intervention configuration
struct InterventionConfig {
    // Timing
    std::chrono::seconds baseline_duration{120};
    std::chrono::seconds post_patch_duration{120};
    std::chrono::seconds stabilization_wait{10};
    
    // Sampling
    double sample_interval_ms{100.0};
    int min_post_patch_samples{100};
    
    // Patch validation
    bool verify_checksum{true};
    bool verify_signature{true};
    bool require_rollback_available{true};
    int max_acceptable_tokens_lost{0};
    
    // Safety checks
    bool enable_safety_gate{true};
    bool enable_rollback_on_regression{true};
    double regression_threshold_percent{-5.0};  // Negative = regression
    
    // Stability requirements
    double max_acceptable_variance_increase{0.20};  // 20%
    int max_oscillation_events{3};
};

// Hotpatch intervention controller
class HotpatchInterventionController {
public:
    explicit HotpatchInterventionController(const InterventionConfig& config);
    
    // Main intervention routine
    HotpatchInterventionResult ExecuteIntervention(
        const BaselineMeasurement& baseline,
        HotpatchType patch_type,
        const std::string& patch_path);
    
    // Patch composition test
    PatchCompositionTest ExecuteCompositionTest(
        const BaselineMeasurement& baseline,
        const std::vector<HotpatchType>& patch_sequence);
    
    // Individual phases
    PatchApplicationEvent ApplyPatch(
        const std::string& model_name,
        HotpatchType patch_type,
        const std::string& patch_path);
    
    TransitionMetrics MeasureTransition(
        const BaselineMeasurement& baseline,
        const PatchApplicationEvent& event);
    
    std::vector<TPSMeasurement> CollectPostPatchSamples(
        const std::string& model_name,
        std::chrono::seconds duration);
    
    // Validation
    bool ValidateNoRegression(
        const BaselineMeasurement& baseline,
        const std::vector<TPSMeasurement>& post_patch);
    
    bool ValidateStability(
        const std::vector<TPSMeasurement>& samples);
    
    bool ValidateSafety(
        const PatchApplicationEvent& event,
        const TransitionMetrics& transition);
    
    // Decision
    std::string MakeVerdict(
        const BaselineMeasurement& baseline,
        const HotpatchInterventionResult& result);
    
    // Rollback
    bool ExecuteRollback(const std::string& patch_id);
    
    // Export
    std::string ExportToJson(const HotpatchInterventionResult& result);
    std::string ExportToMarkdown(const HotpatchInterventionResult& result);

private:
    InterventionConfig config_;
    
    // Internal state tracking
    std::chrono::system_clock::time_point intervention_start_;
    std::vector<TPSMeasurement> baseline_samples_;
    
    // Platform-specific implementations
    PatchApplicationEvent ApplyMASMHotpatchInternal(
        HotpatchType type,
        const std::string& path);
    
    bool VerifyPatchChecksum(const std::string& patch_path);
    bool VerifyPatchSignature(const std::string& patch_path);
    bool PreserveCache();
    bool RestoreCache();
};

// Predefined intervention scenarios
struct InterventionScenario {
    std::string name;
    std::string description;
    std::vector<HotpatchType> patch_sequence;
    std::string expected_outcome;
    double expected_improvement_min;
    double expected_improvement_max;
};

std::vector<InterventionScenario> GetPredefinedScenarios();

// Scenario: Single kernel replacement
InterventionScenario GetKernelReplacementScenario();

// Scenario: Scheduler optimization
InterventionScenario GetSchedulerOptimizationScenario();

// Scenario: Memory optimization
InterventionScenario GetMemoryOptimizationScenario();

// Scenario: Full optimization stack
InterventionScenario GetFullOptimizationScenario();

// Factory
std::unique_ptr<HotpatchInterventionController> CreateInterventionController(
    const InterventionConfig& config = InterventionConfig());

// No-regression gate
struct RegressionGate {
    static bool Check(const BaselineMeasurement& baseline,
                      const StatisticalMetrics& post_patch,
                      double threshold_percent = -5.0);
    
    static std::string Explain(const BaselineMeasurement& baseline,
                               const StatisticalMetrics& post_patch);
};

} // namespace benchmarks
} // namespace rawrxd
