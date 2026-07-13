#pragma once

#include "../autonomy/StabilityValidator.hpp"
#include "../benchmarks/phase_e_execution/baseline_inference.hpp"
#include "../benchmarks/hotpatch_tps/hotpatch_tps_benchmark.hpp"
#include <functional>
#include <memory>

namespace rawrxd {
namespace integration {

/**
 * Phase G.1 Batch 1/5: Stability Envelope Integration
 * 
 * Wires the C.4 Stability Envelope (oscillation dampening, rollback, 
 * 3-sigma governance) directly into benchmark execution for real-time
 * stability validation during performance measurement.
 */

// Stability context during benchmark execution
struct BenchmarkStabilityContext {
    // Current stability state
    StabilityState stability_state;
    double current_stability_score;
    double stability_threshold;
    
    // Oscillation tracking
    OscillationMetrics oscillation_metrics;
    int oscillation_events_detected;
    int oscillation_events_dampened;
    
    // Rollback status
    bool rollback_available;
    std::chrono::milliseconds time_since_last_rollback;
    int rollback_count;
    
    // Safety gate
    bool safety_gate_active;
    int safety_violations_blocked;
    
    // 3-sigma governance
    double sigma_threshold;
    bool sigma_breach_detected;
    std::vector<SigmaBreachEvent> sigma_breaches;
    
    // Real-time metrics
    double current_tps;
    double tps_variance;
    double latency_variance;
    double memory_pressure;
};

// Stability-aware benchmark configuration
struct StabilityBenchmarkConfig {
    // Enable stability monitoring
    bool enable_stability_monitoring = true;
    bool enable_oscillation_detection = true;
    bool enable_rollback_on_instability = true;
    bool enable_safety_gating = true;
    bool enable_3sigma_governance = true;
    
    // Thresholds
    double min_stability_score = 0.80;  // 80% stability required
    double max_oscillation_frequency = 2.0;  // 2 oscillations/minute max
    double max_sigma_breach_rate = 0.05;  // 5% of samples
    
    // Chaos injection settings
    bool enable_chaos_injection = false;
    double chaos_injection_probability = 0.01;  // 1% chance per sample
    std::vector<ChaosScenario> chaos_scenarios;
    
    // Recovery settings
    bool auto_rollback_on_instability = true;
    int max_rollbacks_per_benchmark = 3;
    std::chrono::seconds rollback_cooldown{30};
    
    // Telemetry
    bool export_stability_telemetry = true;
    std::string telemetry_output_path = "./stability_telemetry.json";
};

// Chaos scenario for stability testing
struct ChaosScenario {
    std::string name;
    std::string description;
    ChaosType type;
    double severity;  // 0.0 - 1.0
    std::chrono::milliseconds duration;
    std::function<void()> inject;
    std::function<bool()> validate_recovery;
};

enum class ChaosType {
    MEMORY_PRESSURE,      // Sudden memory allocation spike
    CPU_THROTTLE,         // CPU frequency reduction
    GPU_THERMAL,          // GPU thermal throttling simulation
    NETWORK_LATENCY,        // Network delay injection
    DISK_IO_SATURATION,   // Disk I/O bottleneck
    CONTEXT_SWITCH_STORM, // Excessive context switches
    CACHE_INVALIDATION,   // Cache flush
    SCHEDULER_PREEMPTION  // Forced scheduler intervention
};

// Stability-integrated benchmark runner
class StabilityBenchmarkRunner {
public:
    explicit StabilityBenchmarkRunner(const StabilityBenchmarkConfig& config);
    
    // Wrap any benchmark with stability monitoring
    template<typename BenchmarkFunc, typename ResultType>
    StabilityBenchmarkResult<ResultType> RunWithStability(
        const std::string& benchmark_name,
        BenchmarkFunc benchmark,
        const BenchmarkStabilityContext& initial_context);
    
    // Specific integrations
    StabilityBenchmarkResult<HotpatchTPSResults> RunHotpatchBenchmark(
        const HotpatchTPSConfig& config);
    
    StabilityBenchmarkResult<ModelBaselineResults> RunBaselineBenchmark(
        const BaselineModelConfig& config);
    
    StabilityBenchmarkResult<std::vector<HotpatchComparison>> RunMatrixBenchmark(
        const std::vector<HotpatchTPSConfig>& configs);
    
    // Chaos injection
    void InjectChaos(const ChaosScenario& scenario);
    void InjectRandomChaos();
    
    // Stability queries
    bool IsSystemStable() const;
    double GetCurrentStabilityScore() const;
    std::vector<StabilityEvent> GetStabilityHistory() const;
    
    // Recovery
    bool TriggerRollback();
    bool ValidateRecovery();
    
    // Export
    std::string ExportStabilityReport() const;
    std::string ExportChaosReport() const;

private:
    StabilityBenchmarkConfig config_;
    std::unique_ptr<StabilityValidator> stability_validator_;
    std::unique_ptr<OscillationManager> oscillation_manager_;
    std::unique_ptr<RollbackEngine> rollback_engine_;
    std::unique_ptr<SafetyGate> safety_gate_;
    
    // State tracking
    BenchmarkStabilityContext current_context_;
    std::vector<StabilityEvent> stability_history_;
    std::vector<ChaosEvent> chaos_history_;
    int rollback_count_ = 0;
    std::chrono::system_clock::time_point last_rollback_time_;
    
    // Internal methods
    void InitializeStabilitySystems();
    void MonitorStability();
    void HandleInstability(const StabilityEvent& event);
    void HandleOscillation(const OscillationEvent& event);
    void HandleSigmaBreach(const SigmaBreachEvent& event);
    bool ShouldInjectChaos();
    ChaosScenario SelectChaosScenario();
    void RecordTelemetry();
};

// Result wrapper with stability metadata
template<typename T>
struct StabilityBenchmarkResult {
    T benchmark_result;
    
    // Stability metadata
    bool stability_maintained;
    double final_stability_score;
    int oscillation_events;
    int rollback_count;
    int safety_violations_blocked;
    int sigma_breaches;
    
    // Chaos metadata (if enabled)
    int chaos_injections;
    int successful_recovery_from_chaos;
    std::vector<ChaosEvent> chaos_events;
    
    // Timing
    std::chrono::milliseconds stability_check_duration;
    std::chrono::milliseconds recovery_duration;
    
    // Verdict
    std::string verdict;  // "STABLE", "OSCILLATION_DETECTED", "ROLLBACK_TRIGGERED", "CHAOS_RECOVERED"
    bool benchmark_valid;   // True if results are valid despite stability events
};

// Stability event types
struct StabilityEvent {
    std::chrono::system_clock::time_point timestamp;
    StabilityEventType type;
    std::string description;
    double severity;  // 0.0 - 1.0
    std::string action_taken;
    bool resolved;
};

enum class StabilityEventType {
    OSCILLATION_DETECTED,
    OSCILLATION_DAMPENED,
    SIGMA_BREACH,
    SAFETY_VIOLATION_BLOCKED,
    ROLLBACK_TRIGGERED,
    ROLLBACK_SUCCESSFUL,
    ROLLBACK_FAILED,
    CHAOS_INJECTED,
    CHAOS_RECOVERED,
    STABILITY_RESTORED
};

// Chaos event
struct ChaosEvent {
    std::chrono::system_clock::time_point timestamp;
    ChaosScenario scenario;
    double impact_score;
    std::chrono::milliseconds recovery_time;
    bool recovered;
    std::string recovery_method;
};

// Factory
std::unique_ptr<StabilityBenchmarkRunner> CreateStabilityBenchmarkRunner(
    const StabilityBenchmarkConfig& config = StabilityBenchmarkConfig());

// Predefined chaos scenarios
std::vector<ChaosScenario> GetStandardChaosScenarios();
ChaosScenario GetMemoryPressureScenario(int mb_allocation = 1024);
ChaosScenario GetCPUThrottleScenario(double throttle_percent = 0.5);
ChaosScenario GetCacheInvalidationScenario();
ChaosScenario GetSchedulerInterferenceScenario();

// Integration helpers
void WireStabilityToBenchmarkOrchestrator(StabilityBenchmarkRunner* runner);
void WireStabilityToHotpatchBenchmark(StabilityBenchmarkRunner* runner);
void WireStabilityToInferenceBenchmark(StabilityBenchmarkRunner* runner);

} // namespace integration
} // namespace rawrxd
