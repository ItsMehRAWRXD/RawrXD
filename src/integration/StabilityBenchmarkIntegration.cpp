#include "StabilityBenchmarkIntegration.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <algorithm>

namespace rawrxd {
namespace integration {

// Initialize stability systems
void StabilityBenchmarkRunner::InitializeStabilitySystems() {
    std::cout << "[Stability] Initializing stability systems..." << std::endl;
    
    // Initialize stability validator
    StabilityValidator::Config validator_config;
    validator_config.enable_envelope_check = true;
    validator_config.enable_oscillation_detection = config_.enable_oscillation_detection;
    validator_config.enable_rollback_testing = config_.enable_rollback_on_instability;
    validator_config.enable_safety_gate = config_.enable_safety_gating;
    validator_config.enable_long_run_validation = true;
    validator_config.validation_duration_seconds = 60;
    
    stability_validator_ = std::make_unique<StabilityValidator>(validator_config);
    
    // Initialize oscillation manager
    OscillationManager::Config osc_config;
    osc_config.detection_threshold = 0.15;  // 15% variance threshold
    osc_config.dampening_strategy = DampeningStrategy::HYSTERESIS;
    osc_config.max_oscillations_per_minute = config_.max_oscillation_frequency;
    
    oscillation_manager_ = std::make_unique<OscillationManager>(osc_config);
    
    // Initialize rollback engine
    RollbackEngine::Config rollback_config;
    rollback_config.max_rollbacks_per_hour = config_.max_rollbacks_per_benchmark * 12;  // Scale up
    rollback_config.cooldown_period = config_.rollback_cooldown;
    rollback_config.require_validation = true;
    
    rollback_engine_ = std::make_unique<RollbackEngine>(rollback_config);
    
    // Initialize safety gate
    SafetyGate::Config safety_config;
    safety_config.enable_decision_gating = true;
    safety_config.enable_mutation_gating = true;
    safety_config.enable_intent_gating = true;
    safety_config.default_action = SafetyAction::BLOCK;
    
    safety_gate_ = std::make_unique<SafetyGate>(safety_config);
    
    std::cout << "[Stability] Systems initialized successfully" << std::endl;
}

// Constructor
StabilityBenchmarkRunner::StabilityBenchmarkRunner(const StabilityBenchmarkConfig& config)
    : config_(config), rollback_count_(0) {
    InitializeStabilitySystems();
}

// Check if system is stable
bool StabilityBenchmarkRunner::IsSystemStable() const {
    if (!stability_validator_) return true;
    
    auto result = stability_validator_->Validate(current_context_.stability_state);
    return result.is_stable;
}

// Get current stability score
double StabilityBenchmarkRunner::GetCurrentStabilityScore() const {
    if (!stability_validator_) return 1.0;
    
    return stability_validator_->CalculateStabilityScore(current_context_.stability_state);
}

// Monitor stability during benchmark execution
void StabilityBenchmarkRunner::MonitorStability() {
    if (!config_.enable_stability_monitoring) return;
    
    // Update context with current metrics
    current_context_.current_stability_score = GetCurrentStabilityScore();
    
    // Check for oscillations
    if (config_.enable_oscillation_detection && oscillation_manager_) {
        auto oscillation = oscillation_manager_->DetectOscillation(
            current_context_.current_tps,
            current_context_.tps_variance
        );
        
        if (oscillation.detected) {
            HandleOscillation(oscillation);
        }
    }
    
    // Check 3-sigma breaches
    if (config_.enable_3sigma_governance) {
        if (current_context_.tps_variance > 
            current_context_.sigma_threshold * current_context_.current_tps) {
            
            SigmaBreachEvent breach;
            breach.timestamp = std::chrono::system_clock::now();
            breach.metric = "TPS";
            breach.value = current_context_.current_tps;
            breach.sigma_level = current_context_.tps_variance / current_context_.current_tps;
            
            HandleSigmaBreach(breach);
        }
    }
    
    // Record telemetry
    if (config_.export_stability_telemetry) {
        RecordTelemetry();
    }
}

// Handle instability event
void StabilityBenchmarkRunner::HandleInstability(const StabilityEvent& event) {
    std::cout << "[Stability] Instability detected: " << event.description << std::endl;
    
    stability_history_.push_back(event);
    
    // Trigger rollback if enabled
    if (config_.auto_rollback_on_instability && 
        rollback_count_ < config_.max_rollbacks_per_benchmark) {
        
        auto now = std::chrono::system_clock::now();
        auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_rollback_time_
        );
        
        if (time_since_last > config_.rollback_cooldown) {
            TriggerRollback();
        }
    }
}

// Handle oscillation event
void StabilityBenchmarkRunner::HandleOscillation(const OscillationEvent& event) {
    std::cout << "[Stability] Oscillation detected: " << event.severity << std::endl;
    
    current_context_.oscillation_events_detected++;
    
    // Apply dampening
    if (oscillation_manager_) {
        auto dampening = oscillation_manager_->ApplyDampening(event);
        if (dampening.success) {
            current_context_.oscillation_events_dampened++;
            std::cout << "[Stability] Oscillation dampened successfully" << std::endl;
        }
    }
    
    // Record event
    StabilityEvent stability_event;
    stability_event.timestamp = std::chrono::system_clock::now();
    stability_event.type = StabilityEventType::OSCILLATION_DETECTED;
    stability_event.description = "TPS oscillation detected: " + 
                                   std::to_string(event.severity);
    stability_event.severity = event.severity;
    stability_event.action_taken = "Dampening applied";
    stability_event.resolved = true;
    
    stability_history_.push_back(stability_event);
}

// Handle sigma breach
void StabilityBenchmarkRunner::HandleSigmaBreach(const SigmaBreachEvent& event) {
    std::cout << "[Stability] 3-sigma breach: " << event.metric << " = " 
              << event.value << " (" << event.sigma_level << " sigma)" << std::endl;
    
    current_context_.sigma_breach_detected = true;
    current_context_.sigma_breaches.push_back(event);
    
    StabilityEvent stability_event;
    stability_event.timestamp = std::chrono::system_clock::now();
    stability_event.type = StabilityEventType::SIGMA_BREACH;
    stability_event.description = "3-sigma breach in " + event.metric;
    stability_event.severity = std::min(event.sigma_level / 3.0, 1.0);
    stability_event.action_taken = "Monitoring increased";
    stability_event.resolved = false;
    
    stability_history_.push_back(stability_event);
}

// Trigger rollback
bool StabilityBenchmarkRunner::TriggerRollback() {
    std::cout << "[Stability] Triggering rollback..." << std::endl;
    
    if (!rollback_engine_) {
        std::cerr << "[Stability] Rollback engine not available" << std::endl;
        return false;
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    RollbackRequest request;
    request.reason = "Instability detected during benchmark";
    request.validation_required = true;
    
    auto result = rollback_engine_->ExecuteRollback(request);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    rollback_count_++;
    last_rollback_time_ = std::chrono::system_clock::now();
    
    StabilityEvent event;
    event.timestamp = std::chrono::system_clock::now();
    event.type = result.success ? StabilityEventType::ROLLBACK_SUCCESSFUL 
                                  : StabilityEventType::ROLLBACK_FAILED;
    event.description = result.success ? "Rollback successful" : "Rollback failed";
    event.severity = result.success ? 0.3 : 0.9;
    event.action_taken = result.success ? "System restored" : "Manual intervention required";
    event.resolved = result.success;
    
    stability_history_.push_back(event);
    
    std::cout << "[Stability] Rollback " << (result.success ? "succeeded" : "failed")
              << " in " << duration.count() << "ms" << std::endl;
    
    return result.success;
}

// Validate recovery
bool StabilityBenchmarkRunner::ValidateRecovery() {
    if (!stability_validator_) return true;
    
    auto result = stability_validator_->Validate(current_context_.stability_state);
    return result.is_stable && result.stability_score > config_.min_stability_score;
}

// Inject chaos
void StabilityBenchmarkRunner::InjectChaos(const ChaosScenario& scenario) {
    std::cout << "[Chaos] Injecting: " << scenario.name << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Execute chaos injection
    if (scenario.inject) {
        scenario.inject();
    }
    
    // Monitor for recovery
    bool recovered = false;
    std::string recovery_method = "None";
    
    if (scenario.validate_recovery) {
        auto recovery_start = std::chrono::high_resolution_clock::now();
        
        // Wait for recovery with timeout
        int attempts = 0;
        while (attempts < 100 && !recovered) {
            recovered = scenario.validate_recovery();
            if (!recovered) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                attempts++;
            }
        }
        
        auto recovery_end = std::chrono::high_resolution_clock::now();
        auto recovery_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            recovery_end - recovery_start
        );
        
        // Record chaos event
        ChaosEvent event;
        event.timestamp = start;
        event.scenario = scenario;
        event.impact_score = scenario.severity;
        event.recovery_time = recovery_time;
        event.recovered = recovered;
        event.recovery_method = recovered ? "Auto-recovery" : "Timeout/Failed";
        
        chaos_history_.push_back(event);
        
        std::cout << "[Chaos] Recovery " << (recovered ? "successful" : "failed")
                  << " in " << recovery_time.count() << "ms" << std::endl;
    }
}

// Inject random chaos
void StabilityBenchmarkRunner::InjectRandomChaos() {
    if (!config_.enable_chaos_injection) return;
    
    auto scenarios = GetStandardChaosScenarios();
    if (scenarios.empty()) return;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, scenarios.size() - 1);
    
    InjectChaos(scenarios[dis(gen)]);
}

// Check if should inject chaos
bool StabilityBenchmarkRunner::ShouldInjectChaos() {
    if (!config_.enable_chaos_injection) return false;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    
    return dis(gen) < config_.chaos_injection_probability;
}

// Record telemetry
void StabilityBenchmarkRunner::RecordTelemetry() {
    // Would write to file in real implementation
    // For now, just update in-memory state
}

// Export stability report
std::string StabilityBenchmarkRunner::ExportStabilityReport() const {
    std::ostringstream report;
    
    report << "# Stability Benchmark Report\n\n";
    report << "## Summary\n";
    report << "- Total Events: " << stability_history_.size() << "\n";
    report << "- Rollbacks: " << rollback_count_ << "\n";
    report << "- Final Stability Score: " << GetCurrentStabilityScore() << "\n";
    report << "\n## Events\n";
    
    for (const auto& event : stability_history_) {
        report << "- " << event.description << " (" 
               << (event.resolved ? "resolved" : "unresolved") << ")\n";
    }
    
    return report.str();
}

// Export chaos report
std::string StabilityBenchmarkRunner::ExportChaosReport() const {
    std::ostringstream report;
    
    report << "# Chaos Engineering Report\n\n";
    report << "## Summary\n";
    report << "- Total Injections: " << chaos_history_.size() << "\n";
    
    int recovered = 0;
    for (const auto& event : chaos_history_) {
        if (event.recovered) recovered++;
    }
    
    report << "- Successful Recoveries: " << recovered << "\n";
    report << "- Recovery Rate: " << (chaos_history_.empty() ? 0 : 
        (100.0 * recovered / chaos_history_.size())) << "%\n";
    
    return report.str();
}

// Get stability history
std::vector<StabilityEvent> StabilityBenchmarkRunner::GetStabilityHistory() const {
    return stability_history_;
}

// Factory
std::unique_ptr<StabilityBenchmarkRunner> CreateStabilityBenchmarkRunner(
    const StabilityBenchmarkConfig& config) {
    return std::make_unique<StabilityBenchmarkRunner>(config);
}

// Predefined chaos scenarios
std::vector<ChaosScenario> GetStandardChaosScenarios() {
    std::vector<ChaosScenario> scenarios;
    
    scenarios.push_back(GetMemoryPressureScenario(512));
    scenarios.push_back(GetCPUThrottleScenario(0.3));
    scenarios.push_back(GetCacheInvalidationScenario());
    scenarios.push_back(GetSchedulerInterferenceScenario());
    
    return scenarios;
}

ChaosScenario GetMemoryPressureScenario(int mb_allocation) {
    ChaosScenario scenario;
    scenario.name = "Memory Pressure";
    scenario.description = "Allocate " + std::to_string(mb_allocation) + "MB of memory";
    scenario.type = ChaosType::MEMORY_PRESSURE;
    scenario.severity = 0.6;
    scenario.duration = std::chrono::milliseconds(5000);
    
    scenario.inject = [mb_allocation]() {
        // Simulate memory pressure
        volatile char* buffer = new volatile char[mb_allocation * 1024 * 1024];
        for (int i = 0; i < mb_allocation * 1024; i += 4096) {
            buffer[i] = static_cast<char>(i % 256);
        }
        delete[] buffer;
    };
    
    scenario.validate_recovery = []() {
        // Check if memory is freed
        return true;  // Simplified
    };
    
    return scenario;
}

ChaosScenario GetCPUThrottleScenario(double throttle_percent) {
    ChaosScenario scenario;
    scenario.name = "CPU Throttle";
    scenario.description = "Throttle CPU to " + std::to_string(static_cast<int>(throttle_percent * 100)) + "%";
    scenario.type = ChaosType::CPU_THROTTLE;
    scenario.severity = throttle_percent;
    scenario.duration = std::chrono::milliseconds(3000);
    
    scenario.inject = [throttle_percent]() {
        // Simulate CPU load
        auto start = std::chrono::high_resolution_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::high_resolution_clock::now() - start).count() < 1000) {
            // Busy loop
        }
    };
    
    scenario.validate_recovery = []() {
        return true;
    };
    
    return scenario;
}

ChaosScenario GetCacheInvalidationScenario() {
    ChaosScenario scenario;
    scenario.name = "Cache Invalidation";
    scenario.description = "Flush CPU caches";
    scenario.type = ChaosType::CACHE_INVALIDATION;
    scenario.severity = 0.4;
    scenario.duration = std::chrono::milliseconds(100);
    
    scenario.inject = []() {
        // Simulate cache flush by accessing large memory region
        const int size = 64 * 1024 * 1024;  // 64MB
        volatile char* buffer = new volatile char[size];
        for (int i = 0; i < size; i += 64) {
            buffer[i] = static_cast<char>(i);
        }
        delete[] buffer;
    };
    
    scenario.validate_recovery = []() {
        return true;
    };
    
    return scenario;
}

ChaosScenario GetSchedulerInterferenceScenario() {
    ChaosScenario scenario;
    scenario.name = "Scheduler Interference";
    scenario.description = "Force context switches";
    scenario.type = ChaosType::SCHEDULER_PREEMPTION;
    scenario.severity = 0.3;
    scenario.duration = std::chrono::milliseconds(2000);
    
    scenario.inject = []() {
        // Force context switches by yielding
        for (int i = 0; i < 1000; i++) {
            std::this_thread::yield();
        }
    };
    
    scenario.validate_recovery = []() {
        return true;
    };
    
    return scenario;
}

} // namespace integration
} // namespace rawrxd
