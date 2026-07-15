// Phase G.1 Batch 4/5: Chaos Engineering Integration
// Controlled failure injection and resilience validation
//
// This header provides C++ integration for chaos engineering experiments,
// enabling systematic validation of system resilience through controlled
// fault injection and automatic recovery testing.
//
// Dependencies: Phase G.1 Batch 1 (Stability), Batch 2 (Intelligent Ops)

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <chrono>
#include <atomic>

// Forward declarations
namespace RawrXD {
    namespace Stability {
        class StabilityEnvelope;
    }
    namespace Intelligence {
        class AnomalyDetector;
    }
}

namespace RawrXD {
namespace Chaos {

// ============================================================================
// Type Definitions
// ============================================================================

/// Types of chaos experiments
enum class ExperimentType : uint8_t {
    NETWORK_PARTITION = 0,
    MEMORY_PRESSURE = 1,
    CPU_THROTTLING = 2,
    DISK_IO_FAILURE = 3,
    GPU_MEMORY_EXHAUSTION = 4,
    LATENCY_INJECTION = 5,
    PACKET_LOSS = 6,
    SERVICE_KILL = 7,
    CLOCK_SKEW = 8,
    DNS_FAILURE = 9,
    COUNT = 10
};

/// Fault severity levels
enum class FaultSeverity : uint8_t {
    INFO = 0,       // Informational, no impact
    WARNING = 1,    // Degraded performance
    ERROR = 2,      // Significant impact
    CRITICAL = 3,   // Service-threatening
    CATASTROPHIC = 4 // System failure
};

/// Experiment status
enum class ExperimentStatus : uint8_t {
    PENDING = 0,
    RUNNING = 1,
    PAUSED = 2,
    COMPLETED = 3,
    FAILED = 4,
    ROLLED_BACK = 5
};

/// Recovery strategy
enum class RecoveryStrategy : uint8_t {
    NONE = 0,           // No automatic recovery
    IMMEDIATE = 1,      // Immediate rollback
    GRADUAL = 2,        // Gradual restoration
    ADAPTIVE = 3,       // ML-driven recovery
    CIRCUIT_BREAKER = 4 // Circuit breaker pattern
};

/// Fault injection event
struct FaultEvent {
    uint64_t timestamp_us;
    uint32_t fault_id;
    ExperimentType type;
    FaultSeverity severity;
    std::string description;
    double impact_tps_percent;
    double impact_latency_percent;
    bool recovered;
    uint64_t recovery_timestamp_us;
    std::string recovery_action;
};

/// Recovery event
struct RecoveryEvent {
    uint64_t timestamp_us;
    uint32_t fault_id;
    RecoveryStrategy strategy;
    std::string action_taken;
    uint32_t recovery_time_ms;
    bool successful;
    double stability_restored_percent;
};

/// Experiment metrics
struct ExperimentMetrics {
    uint32_t faults_injected;
    uint32_t faults_recovered;
    double recovery_rate_percent;
    double avg_recovery_time_ms;
    double min_availability_percent;
    double avg_availability_percent;
    double max_stability_degradation_percent;
    double avg_stability_degradation_percent;
    double resilience_score;
};

/// Experiment configuration
struct ExperimentConfig {
    ExperimentType type;
    uint32_t duration_seconds;
    double intensity;  // 0.0-1.0
    RecoveryStrategy recovery_strategy;
    bool enable_telemetry;
    uint32_t sample_interval_ms;
    double abort_threshold_stability;  // Abort if stability drops below
    double abort_threshold_availability; // Abort if availability drops below
};

/// Experiment result
struct ExperimentResult {
    uint32_t experiment_id;
    ExperimentType type;
    ExperimentStatus status;
    ExperimentMetrics metrics;
    std::vector<FaultEvent> faults;
    std::vector<RecoveryEvent> recoveries;
    uint64_t start_timestamp_us;
    uint64_t end_timestamp_us;
    bool aborted;
    std::string abort_reason;
};

/// System state snapshot
struct SystemState {
    uint64_t timestamp_us;
    double tokens_per_second;
    double stability_score;
    double availability_percent;
    double error_rate_percent;
    double latency_p99_ms;
    uint32_t active_faults;
    uint32_t pending_recoveries;
};

/// Resilience threshold
struct ResilienceThreshold {
    double min_availability_percent;
    double max_recovery_time_ms;
    double min_recovery_rate_percent;
    double max_stability_degradation_percent;
};

// ============================================================================
// Fault Injector
// ============================================================================

/// Injects controlled faults into the system
class FaultInjector {
public:
    FaultInjector();
    ~FaultInjector();

    // Non-copyable
    FaultInjector(const FaultInjector&) = delete;
    FaultInjector& operator=(const FaultInjector&) = delete;

    /// Initialize fault injector
    bool Initialize();

    /// Shutdown
    void Shutdown();

    /// Inject a specific fault
    bool InjectFault(const ExperimentType& type, 
                     FaultSeverity severity,
                     double intensity,
                     FaultEvent* out_event);

    /// Inject network partition
    bool InjectNetworkPartition(double packet_loss_percent,
                                uint32_t duration_ms,
                                FaultEvent* out_event);

    /// Inject memory pressure
    bool InjectMemoryPressure(double pressure_percent,
                              uint32_t duration_ms,
                              FaultEvent* out_event);

    /// Inject CPU throttling
    bool InjectCpuThrottling(double throttle_percent,
                             uint32_t duration_ms,
                             FaultEvent* out_event);

    /// Inject disk I/O latency
    bool InjectDiskLatency(double latency_ms,
                           uint32_t duration_ms,
                           FaultEvent* out_event);

    /// Inject GPU memory pressure
    bool InjectGpuMemoryPressure(double pressure_percent,
                                 uint32_t duration_ms,
                                 FaultEvent* out_event);

    /// Clear all active faults
    void ClearAllFaults();

    /// Get active fault count
    uint32_t GetActiveFaultCount() const;

    /// Get fault history
    std::vector<FaultEvent> GetFaultHistory(uint32_t max_events = 100) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Recovery Orchestrator
// ============================================================================

/// Orchestrates automatic recovery from faults
class RecoveryOrchestrator {
public:
    RecoveryOrchestrator();
    ~RecoveryOrchestrator();

    /// Initialize orchestrator
    bool Initialize(RawrXD::Stability::StabilityEnvelope* stability = nullptr);

    /// Shutdown
    void Shutdown();

    /// Attempt recovery from a fault
    bool AttemptRecovery(const FaultEvent& fault,
                         RecoveryStrategy strategy,
                         RecoveryEvent* out_event);

    /// Set recovery strategy for fault type
    void SetStrategy(ExperimentType type, RecoveryStrategy strategy);

    /// Get strategy for fault type
    RecoveryStrategy GetStrategy(ExperimentType type) const;

    /// Enable/disable automatic recovery
    void SetAutoRecovery(bool enabled);

    /// Check if auto-recovery is enabled
    bool IsAutoRecoveryEnabled() const;

    /// Get recovery statistics
    struct RecoveryStats {
        uint32_t total_attempts;
        uint32_t successful_recoveries;
        uint32_t failed_recoveries;
        double avg_recovery_time_ms;
        double success_rate_percent;
    };
    RecoveryStats GetStats() const;

    /// Reset statistics
    void ResetStats();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Chaos Experiment Runner
// ============================================================================

/// Runs chaos engineering experiments
class ChaosExperimentRunner {
public:
    ChaosExperimentRunner();
    ~ChaosExperimentRunner();

    /// Initialize runner
    bool Initialize(
        FaultInjector* injector,
        RecoveryOrchestrator* orchestrator,
        RawrXD::Stability::StabilityEnvelope* stability = nullptr,
        RawrXD::Intelligence::AnomalyDetector* detector = nullptr
    );

    /// Shutdown
    void Shutdown();

    /// Run a single experiment
    bool RunExperiment(const ExperimentConfig& config, 
                       ExperimentResult* out_result);

    /// Run multiple experiments in sequence
    bool RunExperimentSeries(const std::vector<ExperimentConfig>& configs,
                             std::vector<ExperimentResult>* out_results);

    /// Run experiments in parallel
    bool RunParallelExperiments(const std::vector<ExperimentConfig>& configs,
                                uint32_t max_parallel,
                                std::vector<ExperimentResult>* out_results);

    /// Abort running experiment
    bool AbortExperiment(uint32_t experiment_id, const std::string& reason);

    /// Pause running experiment
    bool PauseExperiment(uint32_t experiment_id);

    /// Resume paused experiment
    bool ResumeExperiment(uint32_t experiment_id);

    /// Get current system state
    bool GetSystemState(SystemState* out_state) const;

    /// Set progress callback
    void SetProgressCallback(std::function<void(uint32_t experiment_id,
                                                  uint32_t elapsed_seconds,
                                                  uint32_t total_seconds,
                                                  const std::string& phase)> callback);

    /// Set state change callback
    void SetStateCallback(std::function<void(const SystemState& state)> callback);

    /// Validate experiment configuration
    bool ValidateConfig(const ExperimentConfig& config) const;

    /// Calculate resilience score
    double CalculateResilienceScore(const ExperimentResult& result) const;

    /// Check if result meets thresholds
    bool MeetsThresholds(const ExperimentResult& result,
                         const ResilienceThreshold& thresholds) const;

    /// Generate experiment report
    std::string GenerateReport(const ExperimentResult& result) const;

    /// Export results to JSON
    bool ExportToJson(const std::vector<ExperimentResult>& results,
                      const std::string& filepath) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Resilience Validator
// ============================================================================

/// Validates system resilience against defined thresholds
class ResilienceValidator {
public:
    ResilienceValidator();
    ~ResilienceValidator();

    /// Set validation thresholds
    void SetThresholds(const ResilienceThreshold& thresholds);

    /// Get current thresholds
    ResilienceThreshold GetThresholds() const;

    /// Validate single experiment result
    bool Validate(const ExperimentResult& result) const;

    /// Validate series of results
    bool ValidateSeries(const std::vector<ExperimentResult>& results) const;

    /// Get validation report
    std::string GetValidationReport(const ExperimentResult& result) const;

    /// Calculate overall resilience grade (A-F)
    char CalculateGrade(const std::vector<ExperimentResult>& results) const;

    /// Check production readiness
    bool IsProductionReady(const std::vector<ExperimentResult>& results) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert experiment type to string
const char* ExperimentTypeToString(ExperimentType type);

/// Convert string to experiment type
ExperimentType StringToExperimentType(const std::string& str);

/// Convert severity to string
const char* FaultSeverityToString(FaultSeverity severity);

/// Convert status to string
const char* ExperimentStatusToString(ExperimentStatus status);

/// Convert recovery strategy to string
const char* RecoveryStrategyToString(RecoveryStrategy strategy);

/// Calculate availability from samples
double CalculateAvailability(const std::vector<SystemState>& states);

/// Calculate stability degradation
double CalculateStabilityDegradation(double baseline, double current);

/// Calculate recovery rate
double CalculateRecoveryRate(uint32_t recovered, uint32_t total);

/// Check if fault is recoverable
bool IsRecoverable(const FaultEvent& fault);

/// Estimate fault impact
double EstimateFaultImpact(const FaultEvent& fault);

// ============================================================================
// Constants
// ============================================================================

constexpr uint32_t DEFAULT_EXPERIMENT_DURATION_SECONDS = 60;
constexpr double DEFAULT_EXPERIMENT_INTENSITY = 0.5;
constexpr uint32_t DEFAULT_SAMPLE_INTERVAL_MS = 1000;
constexpr double DEFAULT_ABORT_THRESHOLD_STABILITY = 0.5;
constexpr double DEFAULT_ABORT_THRESHOLD_AVAILABILITY = 80.0;

constexpr double DEFAULT_MIN_AVAILABILITY_PERCENT = 99.9;
constexpr double DEFAULT_MAX_RECOVERY_TIME_MS = 5000.0;
constexpr double DEFAULT_MIN_RECOVERY_RATE_PERCENT = 95.0;
constexpr double DEFAULT_MAX_STABILITY_DEGRADATION_PERCENT = 20.0;

constexpr uint32_t MAX_CONCURRENT_EXPERIMENTS = 4;
constexpr uint32_t MAX_FAULT_HISTORY = 10000;
constexpr uint32_t MAX_RECOVERY_HISTORY = 10000;

} // namespace Chaos
} // namespace RawrXD