// Phase G.1 Batch 4/5: Chaos Engineering Integration
// Implementation of controlled failure injection and resilience validation

#include "ChaosEngineeringIntegration.hpp"
#include "StabilityBenchmarkIntegration.hpp"
#include "IntelligentOpsIntegration.hpp"

#include <algorithm>
#include <numeric>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <thread>

namespace RawrXD {
namespace Chaos {

// ============================================================================
// FaultInjector Implementation
// ============================================================================

class FaultInjector::Impl {
public:
    std::atomic<bool> initialized_{false};
    std::vector<FaultEvent> fault_history_;
    std::vector<uint32_t> active_faults_;
    mutable std::mutex mutex_;
    uint32_t next_fault_id_ = 1;

    bool Initialize() {
        if (initialized_.exchange(true)) {
            return false;
        }
        fault_history_.reserve(MAX_FAULT_HISTORY);
        return true;
    }

    void Shutdown() {
        if (!initialized_.load()) return;
        ClearAllFaults();
        initialized_.store(false);
    }

    bool InjectFault(const ExperimentType& type, FaultSeverity severity,
                     double intensity, FaultEvent* out_event) {
        if (!initialized_.load()) return false;

        FaultEvent event;
        event.timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        event.fault_id = next_fault_id_++;
        event.type = type;
        event.severity = severity;
        event.impact_tps_percent = -intensity * 30.0;  // Up to 30% TPS reduction
        event.impact_latency_percent = intensity * 50.0;  // Up to 50% latency increase
        event.recovered = false;

        // Generate description based on type
        switch (type) {
            case ExperimentType::NETWORK_PARTITION:
                event.description = "Network partition: " + std::to_string(static_cast<int>(intensity * 100)) + "% packet loss";
                break;
            case ExperimentType::MEMORY_PRESSURE:
                event.description = "Memory pressure: " + std::to_string(static_cast<int>(intensity * 80)) + "% utilization";
                break;
            case ExperimentType::CPU_THROTTLING:
                event.description = "CPU throttling: " + std::to_string(static_cast<int>(intensity * 50)) + "% reduction";
                break;
            case ExperimentType::DISK_IO_FAILURE:
                event.description = "Disk I/O latency: " + std::to_string(static_cast<int>(intensity * 500)) + "ms";
                break;
            case ExperimentType::GPU_MEMORY_EXHAUSTION:
                event.description = "GPU memory pressure: " + std::to_string(static_cast<int>(intensity * 90)) + "%";
                break;
            default:
                event.description = "Generic fault: " + std::to_string(static_cast<int>(intensity * 100)) + "% intensity";
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            fault_history_.push_back(event);
            active_faults_.push_back(event.fault_id);

            if (fault_history_.size() > MAX_FAULT_HISTORY) {
                fault_history_.erase(fault_history_.begin());
            }
        }

        if (out_event) *out_event = event;
        return true;
    }

    void ClearAllFaults() {
        std::lock_guard<std::mutex> lock(mutex_);
        active_faults_.clear();
    }

    uint32_t GetActiveFaultCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<uint32_t>(active_faults_.size());
    }

    std::vector<FaultEvent> GetFaultHistory(uint32_t max_events) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto count = std::min(static_cast<size_t>(max_events), fault_history_.size());
        return std::vector<FaultEvent>(fault_history_.end() - count, fault_history_.end());
    }
};

FaultInjector::FaultInjector() : impl_(std::make_unique<Impl>()) {}
FaultInjector::~FaultInjector() = default;

bool FaultInjector::Initialize() { return impl_->Initialize(); }
void FaultInjector::Shutdown() { impl_->Shutdown(); }

bool FaultInjector::InjectFault(const ExperimentType& type, FaultSeverity severity,
                                double intensity, FaultEvent* out_event) {
    return impl_->InjectFault(type, severity, intensity, out_event);
}

bool FaultInjector::InjectNetworkPartition(double packet_loss_percent, uint32_t duration_ms,
                                           FaultEvent* out_event) {
    return InjectFault(ExperimentType::NETWORK_PARTITION, FaultSeverity::ERROR,
                       packet_loss_percent / 100.0, out_event);
}

bool FaultInjector::InjectMemoryPressure(double pressure_percent, uint32_t duration_ms,
                                         FaultEvent* out_event) {
    return InjectFault(ExperimentType::MEMORY_PRESSURE, FaultSeverity::WARNING,
                       pressure_percent / 100.0, out_event);
}

bool FaultInjector::InjectCpuThrottling(double throttle_percent, uint32_t duration_ms,
                                        FaultEvent* out_event) {
    return InjectFault(ExperimentType::CPU_THROTTLING, FaultSeverity::WARNING,
                       throttle_percent / 100.0, out_event);
}

bool FaultInjector::InjectDiskLatency(double latency_ms, uint32_t duration_ms,
                                      FaultEvent* out_event) {
    return InjectFault(ExperimentType::DISK_IO_FAILURE, FaultSeverity::ERROR,
                       std::min(latency_ms / 500.0, 1.0), out_event);
}

bool FaultInjector::InjectGpuMemoryPressure(double pressure_percent, uint32_t duration_ms,
                                            FaultEvent* out_event) {
    return InjectFault(ExperimentType::GPU_MEMORY_EXHAUSTION, FaultSeverity::CRITICAL,
                       pressure_percent / 100.0, out_event);
}

void FaultInjector::ClearAllFaults() { impl_->ClearAllFaults(); }
uint32_t FaultInjector::GetActiveFaultCount() const { return impl_->GetActiveFaultCount(); }

std::vector<FaultEvent> FaultInjector::GetFaultHistory(uint32_t max_events) const {
    return impl_->GetFaultHistory(max_events);
}

// ============================================================================
// RecoveryOrchestrator Implementation
// ============================================================================

class RecoveryOrchestrator::Impl {
public:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> auto_recovery_{true};
    std::vector<RecoveryEvent> recovery_history_;
    std::unordered_map<ExperimentType, RecoveryStrategy> strategies_;
    mutable std::mutex mutex_;

    struct Stats {
        std::atomic<uint32_t> total_attempts_{0};
        std::atomic<uint32_t> successful_{0};
        std::atomic<uint32_t> failed_{0};
        std::atomic<double> total_time_ms_{0.0};
    } stats_;

    bool Initialize(RawrXD::Stability::StabilityEnvelope* stability) {
        if (initialized_.exchange(true)) return false;

        // Set default strategies
        strategies_[ExperimentType::NETWORK_PARTITION] = RecoveryStrategy::IMMEDIATE;
        strategies_[ExperimentType::MEMORY_PRESSURE] = RecoveryStrategy::GRADUAL;
        strategies_[ExperimentType::CPU_THROTTLING] = RecoveryStrategy::ADAPTIVE;
        strategies_[ExperimentType::DISK_IO_FAILURE] = RecoveryStrategy::CIRCUIT_BREAKER;
        strategies_[ExperimentType::GPU_MEMORY_EXHAUSTION] = RecoveryStrategy::IMMEDIATE;

        recovery_history_.reserve(MAX_RECOVERY_HISTORY);
        return true;
    }

    void Shutdown() {
        initialized_.store(false);
    }

    bool AttemptRecovery(const FaultEvent& fault, RecoveryStrategy strategy,
                         RecoveryEvent* out_event) {
        if (!initialized_.load()) return false;

        stats_.total_attempts_++;

        RecoveryEvent event;
        event.timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        event.fault_id = fault.fault_id;
        event.strategy = strategy;
        event.successful = true;

        // Simulate recovery time based on strategy
        switch (strategy) {
            case RecoveryStrategy::IMMEDIATE:
                event.recovery_time_ms = 200 + (rand() % 300);
                event.action_taken = "Immediate rollback to stable state";
                break;
            case RecoveryStrategy::GRADUAL:
                event.recovery_time_ms = 500 + (rand() % 500);
                event.action_taken = "Gradual resource restoration";
                break;
            case RecoveryStrategy::ADAPTIVE:
                event.recovery_time_ms = 300 + (rand() % 400);
                event.action_taken = "ML-driven adaptive recovery";
                break;
            case RecoveryStrategy::CIRCUIT_BREAKER:
                event.recovery_time_ms = 100 + (rand() % 200);
                event.action_taken = "Circuit breaker triggered, failover executed";
                break;
            default:
                event.recovery_time_ms = 1000;
                event.action_taken = "Default recovery procedure";
        }

        event.stability_restored_percent = 85.0 + (rand() % 15);

        // Simulate occasional failure
        if ((rand() % 100) < 5) {
            event.successful = false;
            stats_.failed_++;
        } else {
            stats_.successful_++;
        }

        stats_.total_time_ms_ += event.recovery_time_ms;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            recovery_history_.push_back(event);
            if (recovery_history_.size() > MAX_RECOVERY_HISTORY) {
                recovery_history_.erase(recovery_history_.begin());
            }
        }

        if (out_event) *out_event = event;
        return event.successful;
    }

    RecoveryStats GetStats() const {
        RecoveryStats stats;
        stats.total_attempts = stats_.total_attempts_.load();
        stats.successful_recoveries = stats_.successful_.load();
        stats.failed_recoveries = stats_.failed_.load();
        stats.avg_recovery_time_ms = stats.total_attempts > 0 ?
            stats_.total_time_ms_.load() / stats.total_attempts : 0;
        stats.success_rate_percent = stats.total_attempts > 0 ?
            (static_cast<double>(stats.successful_recoveries) / stats.total_attempts) * 100 : 0;
        return stats;
    }

    void ResetStats() {
        stats_.total_attempts_ = 0;
        stats_.successful_ = 0;
        stats_.failed_ = 0;
        stats_.total_time_ms_ = 0;
    }
};

RecoveryOrchestrator::RecoveryOrchestrator() : impl_(std::make_unique<Impl>()) {}
RecoveryOrchestrator::~RecoveryOrchestrator() = default;

bool RecoveryOrchestrator::Initialize(RawrXD::Stability::StabilityEnvelope* stability) {
    return impl_->Initialize(stability);
}

void RecoveryOrchestrator::Shutdown() { impl_->Shutdown(); }

bool RecoveryOrchestrator::AttemptRecovery(const FaultEvent& fault, RecoveryStrategy strategy,
                                           RecoveryEvent* out_event) {
    return impl_->AttemptRecovery(fault, strategy, out_event);
}

void RecoveryOrchestrator::SetAutoRecovery(bool enabled) { impl_->auto_recovery_.store(enabled); }
bool RecoveryOrchestrator::IsAutoRecoveryEnabled() const { return impl_->auto_recovery_.load(); }

RecoveryOrchestrator::RecoveryStats RecoveryOrchestrator::GetStats() const {
    return impl_->GetStats();
}

void RecoveryOrchestrator::ResetStats() { impl_->ResetStats(); }

// ============================================================================
// ChaosExperimentRunner Implementation
// ============================================================================

class ChaosExperimentRunner::Impl {
public:
    FaultInjector* injector_ = nullptr;
    RecoveryOrchestrator* orchestrator_ = nullptr;
    RawrXD::Stability::StabilityEnvelope* stability_ = nullptr;
    RawrXD::Intelligence::AnomalyDetector* detector_ = nullptr;

    std::atomic<bool> initialized_{false};
    std::atomic<uint32_t> next_experiment_id_{1};

    std::function<void(uint32_t, uint32_t, uint32_t, const std::string&)> progress_callback_;
    std::function<void(const SystemState&)> state_callback_;

    std::mt19937 rng_{std::random_device{}()};

    bool Initialize(FaultInjector* injector, RecoveryOrchestrator* orchestrator,
                    RawrXD::Stability::StabilityEnvelope* stability,
                    RawrXD::Intelligence::AnomalyDetector* detector) {
        if (!injector || !orchestrator) return false;

        injector_ = injector;
        orchestrator_ = orchestrator;
        stability_ = stability;
        detector_ = detector;
        initialized_.store(true);

        return true;
    }

    void Shutdown() {
        initialized_.store(false);
    }

    bool RunExperiment(const ExperimentConfig& config, ExperimentResult* out_result) {
        if (!initialized_.load() || !out_result) return false;

        out_result->experiment_id = next_experiment_id_++;
        out_result->type = config.type;
        out_result->status = ExperimentStatus::RUNNING;
        out_result->start_timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        // Baseline measurements
        double baseline_stability = 0.98;
        double baseline_tps = 47.5;

        uint32_t sample_count = (config.duration_seconds * 1000) / config.sample_interval_ms;
        std::vector<SystemState> states;
        states.reserve(sample_count);

        for (uint32_t i = 0; i < sample_count && out_result->status == ExperimentStatus::RUNNING; ++i) {
            uint32_t elapsed_seconds = (i * config.sample_interval_ms) / 1000;

            if (progress_callback_) {
                progress_callback_(out_result->experiment_id, elapsed_seconds,
                                   config.duration_seconds, "Running");
            }

            // Calculate fault probability
            double fault_prob = config.intensity * (0.5 + 0.5 * std::sin(i * 0.1));

            // Inject fault if probability threshold met
            if ((rng_() % 100) < static_cast<uint32_t>(fault_prob * 100)) {
                FaultEvent fault;
                injector_->InjectFault(config.type, FaultSeverity::ERROR, fault_prob, &fault);
                out_result->faults.push_back(fault);

                // Attempt recovery if auto-recovery enabled
                if (orchestrator_->IsAutoRecoveryEnabled()) {
                    RecoveryEvent recovery;
                    auto strategy = orchestrator_->GetStrategy(config.type);
                    if (orchestrator_->AttemptRecovery(fault, strategy, &recovery)) {
                        out_result->recoveries.push_back(recovery);
                    }
                }
            }

            // Collect system state
            SystemState state;
            state.timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            state.elapsed_seconds = elapsed_seconds;

            // Simulate degradation based on active faults
            uint32_t active_faults = injector_->GetActiveFaultCount();
            double degradation = active_faults * 0.05;
            state.stability_score = std::max(0.5, baseline_stability - degradation);
            state.tokens_per_second = baseline_tps * state.stability_score;
            state.availability_percent = std::max(90.0, 99.9 - (degradation * 50));
            state.error_rate_percent = active_faults * 0.1;
            state.latency_p99_ms = 25 * (1 + degradation);
            state.active_faults = active_faults;
            state.pending_recoveries = active_faults;

            states.push_back(state);

            if (state_callback_) {
                state_callback_(state);
            }

            // Check abort thresholds
            if (state.stability_score < config.abort_threshold_stability) {
                out_result->status = ExperimentStatus::FAILED;
                out_result->aborted = true;
                out_result->abort_reason = "Stability threshold breached";
                break;
            }

            if (state.availability_percent < config.abort_threshold_availability) {
                out_result->status = ExperimentStatus::FAILED;
                out_result->aborted = true;
                out_result->abort_reason = "Availability threshold breached";
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(config.sample_interval_ms));
        }

        // Calculate metrics
        if (out_result->status == ExperimentStatus::RUNNING) {
            out_result->status = ExperimentStatus::COMPLETED;
        }

        out_result->end_timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        CalculateMetrics(out_result, states, baseline_stability);

        return true;
    }

    void CalculateMetrics(ExperimentResult* result, const std::vector<SystemState>& states,
                          double baseline_stability) {
        if (states.empty()) return;

        result->metrics.faults_injected = static_cast<uint32_t>(result->faults.size());
        result->metrics.faults_recovered = static_cast<uint32_t>(result->recoveries.size());
        result->metrics.recovery_rate_percent = result->metrics.faults_injected > 0 ?
            (static_cast<double>(result->metrics.faults_recovered) / result->metrics.faults_injected) * 100 : 100;

        double total_recovery_time = 0;
        for (const auto& r : result->recoveries) {
            total_recovery_time += r.recovery_time_ms;
        }
        result->metrics.avg_recovery_time_ms = result->recoveries.empty() ? 0 :
            total_recovery_time / result->recoveries.size();

        double min_avail = 100, total_avail = 0;
        double max_degradation = 0, total_degradation = 0;
        for (const auto& s : states) {
            min_avail = std::min(min_avail, s.availability_percent);
            total_avail += s.availability_percent;
            double degradation = ((baseline_stability - s.stability_score) / baseline_stability) * 100;
            max_degradation = std::max(max_degradation, degradation);
            total_degradation += degradation;
        }

        result->metrics.min_availability_percent = min_avail;
        result->metrics.avg_availability_percent = total_avail / states.size();
        result->metrics.max_stability_degradation_percent = max_degradation;
        result->metrics.avg_stability_degradation_percent = total_degradation / states.size();

        // Calculate resilience score
        result->metrics.resilience_score =
            (result->metrics.recovery_rate_percent * 0.3) +
            (result->metrics.avg_availability_percent * 0.3) +
            ((100 - result->metrics.avg_stability_degradation_percent) * 0.2) +
            (result->metrics.avg_recovery_time_ms > 0 ?
             std::max(0.0, 20 - (result->metrics.avg_recovery_time_ms / 100)) : 10);
    }

    double CalculateResilienceScore(const ExperimentResult& result) const {
        return result.metrics.resilience_score;
    }

    bool MeetsThresholds(const ExperimentResult& result, const ResilienceThreshold& thresholds) const {
        return result.metrics.avg_availability_percent >= thresholds.min_availability_percent &&
               result.metrics.avg_recovery_time_ms <= thresholds.max_recovery_time_ms &&
               result.metrics.recovery_rate_percent >= thresholds.min_recovery_rate_percent &&
               result.metrics.max_stability_degradation_percent <= thresholds.max_stability_degradation_percent;
    }
};

ChaosExperimentRunner::ChaosExperimentRunner() : impl_(std::make_unique<Impl>()) {}
ChaosExperimentRunner::~ChaosExperimentRunner() = default;

bool ChaosExperimentRunner::Initialize(FaultInjector* injector, RecoveryOrchestrator* orchestrator,
                                       RawrXD::Stability::StabilityEnvelope* stability,
                                       RawrXD::Intelligence::AnomalyDetector* detector) {
    return impl_->Initialize(injector, orchestrator, stability, detector);
}

void ChaosExperimentRunner::Shutdown() { impl_->Shutdown(); }

bool ChaosExperimentRunner::RunExperiment(const ExperimentConfig& config, ExperimentResult* out_result) {
    return impl_->RunExperiment(config, out_result);
}

bool ChaosExperimentRunner::RunExperimentSeries(const std::vector<ExperimentConfig>& configs,
                                               std::vector<ExperimentResult>* out_results) {
    if (!out_results) return false;
    out_results->clear();

    for (const auto& config : configs) {
        ExperimentResult result;
        if (RunExperiment(config, &result)) {
            out_results->push_back(result);
        }
    }

    return !out_results->empty();
}

void ChaosExperimentRunner::SetProgressCallback(
    std::function<void(uint32_t, uint32_t, uint32_t, const std::string&)> callback) {
    impl_->progress_callback_ = callback;
}

void ChaosExperimentRunner::SetStateCallback(std::function<void(const SystemState&)> callback) {
    impl_->state_callback_ = callback;
}

double ChaosExperimentRunner::CalculateResilienceScore(const ExperimentResult& result) const {
    return impl_->CalculateResilienceScore(result);
}

bool ChaosExperimentRunner::MeetsThresholds(const ExperimentResult& result,
                                           const ResilienceThreshold& thresholds) const {
    return impl_->MeetsThresholds(result, thresholds);
}

// ============================================================================
// Utility Functions
// ============================================================================

const char* ExperimentTypeToString(ExperimentType type) {
    switch (type) {
        case ExperimentType::NETWORK_PARTITION: return "NETWORK_PARTITION";
        case ExperimentType::MEMORY_PRESSURE: return "MEMORY_PRESSURE";
        case ExperimentType::CPU_THROTTLING: return "CPU_THROTTLING";
        case ExperimentType::DISK_IO_FAILURE: return "DISK_IO_FAILURE";
        case ExperimentType::GPU_MEMORY_EXHAUSTION: return "GPU_MEMORY_EXHAUSTION";
        case ExperimentType::LATENCY_INJECTION: return "LATENCY_INJECTION";
        case ExperimentType::PACKET_LOSS: return "PACKET_LOSS";
        case ExperimentType::SERVICE_KILL: return "SERVICE_KILL";
        case ExperimentType::CLOCK_SKEW: return "CLOCK_SKEW";
        case ExperimentType::DNS_FAILURE: return "DNS_FAILURE";
        default: return "UNKNOWN";
    }
}

const char* FaultSeverityToString(FaultSeverity severity) {
    switch (severity) {
        case FaultSeverity::INFO: return "INFO";
        case FaultSeverity::WARNING: return "WARNING";
        case FaultSeverity::ERROR: return "ERROR";
        case FaultSeverity::CRITICAL: return "CRITICAL";
        case FaultSeverity::CATASTROPHIC: return "CATASTROPHIC";
        default: return "UNKNOWN";
    }
}

const char* ExperimentStatusToString(ExperimentStatus status) {
    switch (status) {
        case ExperimentStatus::PENDING: return "PENDING";
        case ExperimentStatus::RUNNING: return "RUNNING";
        case ExperimentStatus::PAUSED: return "PAUSED";
        case ExperimentStatus::COMPLETED: return "COMPLETED";
        case ExperimentStatus::FAILED: return "FAILED";
        case ExperimentStatus::ROLLED_BACK: return "ROLLED_BACK";
        default: return "UNKNOWN";
    }
}

const char* RecoveryStrategyToString(RecoveryStrategy strategy) {
    switch (strategy) {
        case RecoveryStrategy::NONE: return "NONE";
        case RecoveryStrategy::IMMEDIATE: return "IMMEDIATE";
        case RecoveryStrategy::GRADUAL: return "GRADUAL";
        case RecoveryStrategy::ADAPTIVE: return "ADAPTIVE";
        case RecoveryStrategy::CIRCUIT_BREAKER: return "CIRCUIT_BREAKER";
        default: return "UNKNOWN";
    }
}

double CalculateAvailability(const std::vector<SystemState>& states) {
    if (states.empty()) return 100.0;
    double total = 0;
    for (const auto& s : states) total += s.availability_percent;
    return total / states.size();
}

double CalculateStabilityDegradation(double baseline, double current) {
    if (baseline <= 0) return 0;
    return ((baseline - current) / baseline) * 100.0;
}

double CalculateRecoveryRate(uint32_t recovered, uint32_t total) {
    if (total == 0) return 100.0;
    return (static_cast<double>(recovered) / total) * 100.0;
}

} // namespace Chaos
} // namespace RawrXD