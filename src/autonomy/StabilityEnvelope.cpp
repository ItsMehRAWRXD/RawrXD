// StabilityEnvelope.cpp
// Phase C.4 Batch 1/5 — Autonomous Stability Envelope Implementation

#include "StabilityEnvelope.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace Autonomy {

// ============================================================================
// DecisionRiskProfile Implementation
// ============================================================================

double DecisionRiskProfile::CalculateCompositeRisk(double performance_risk,
                                                     double stability_risk,
                                                     double resource_risk,
                                                     double safety_risk,
                                                     double reversibility_score) const {
    // Convert reversibility score to risk (higher reversibility = lower risk)
    double reversibility_risk = 1.0 - reversibility_score;
    
    // Weighted combination
    double composite = 
        performance_impact_weight * performance_risk +
        stability_impact_weight * stability_risk +
        resource_impact_weight * resource_risk +
        safety_impact_weight * safety_risk +
        reversibility_weight * reversibility_risk;
    
    // Clamp to [0, 1]
    return std::max(0.0, std::min(1.0, composite));
}

// ============================================================================
// StabilityEnvelope Implementation
// ============================================================================

StabilityEnvelope::StabilityEnvelope(const StabilityEnvelopeConfig& config)
    : config_(config)
    , current_state_()
    , stats_{} {}

StabilityEnvelope::~StabilityEnvelope() {
    Shutdown();
}

void StabilityEnvelope::Initialize() {
    // Initialize state for all dimensions
    for (const auto& [dim, threshold] : config_.thresholds) {
        current_state_.current_values[dim] = 0.5; // Start at mid-range
        current_state_.current_severity[dim] = ThresholdSeverity::INFO;
        current_state_.violation_count[dim] = 0;
    }
    
    // Initialize statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_ = StabilityStatistics{};
    }
}

void StabilityEnvelope::Start() {
    running_ = true;
    monitor_thread_ = std::thread(&StabilityEnvelope::MonitorLoop, this);
}

void StabilityEnvelope::Stop() {
    running_ = false;
    
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void StabilityEnvelope::Shutdown() {
    Stop();
}

void StabilityEnvelope::UpdateDimension(StabilityDimension dimension, double value) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    // Update current value
    current_state_.current_values[dimension] = value;
    current_state_.timestamp = std::chrono::steady_clock::now();
    
    // Add to history
    current_state_.history[dimension].push_back(
        {current_state_.timestamp, value});
    
    // Trim history to window
    auto cutoff = current_state_.timestamp - config_.state_history_window;
    auto& hist = current_state_.history[dimension];
    hist.erase(
        std::remove_if(hist.begin(), hist.end(),
            [cutoff](const auto& p) { return p.first < cutoff; }),
        hist.end());
    
    // Evaluate severity
    auto new_severity = EvaluateThreshold(dimension, value);
    auto old_severity = current_state_.current_severity[dimension];
    current_state_.current_severity[dimension] = new_severity;
    
    // Track violations
    if (new_severity == ThresholdSeverity::VIOLATION) {
        if (old_severity != ThresholdSeverity::VIOLATION) {
            current_state_.violation_start_time[dimension] = current_state_.timestamp;
        }
    } else {
        current_state_.violation_start_time.erase(dimension);
    }
    
    // Update overall stability
    current_state_.overall_stability_score = CalculateOverallStability();
    current_state_.overall_severity = ThresholdSeverity::INFO;
    for (const auto& [dim, sev] : current_state_.current_severity) {
        if (StabilityUtils::IsMoreSevere(sev, current_state_.overall_severity)) {
            current_state_.overall_severity = sev;
        }
    }
    current_state_.envelope_violated = (current_state_.overall_severity == ThresholdSeverity::VIOLATION);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.total_updates++;
        
        if (new_severity == ThresholdSeverity::WARNING) {
            stats_.warning_count++;
        } else if (new_severity == ThresholdSeverity::CRITICAL) {
            stats_.critical_count++;
        } else if (new_severity == ThresholdSeverity::VIOLATION) {
            stats_.violation_count++;
            stats_.last_violation = current_state_.timestamp;
        }
    }
    
    // Check for alerts
    if (new_severity != ThresholdSeverity::INFO && 
        StabilityUtils::IsMoreSevere(new_severity, old_severity)) {
        auto it = config_.thresholds.find(dimension);
        if (it != config_.thresholds.end()) {
            double threshold_val = (new_severity == ThresholdSeverity::WARNING) ? 
                it->second.warning_max : 
                (new_severity == ThresholdSeverity::CRITICAL) ? 
                    it->second.critical_max : it->second.nominal_max;
            GenerateAlert(dimension, new_severity, value, threshold_val);
        }
    }
}

void StabilityEnvelope::UpdateResourceState(const ResourceSafetyLimits& current_usage) {
    // Calculate resource utilization ratios
    double cpu_util = current_usage.cpu_utilization_max;
    double mem_util = static_cast<double>(current_usage.memory_usage_max_bytes) / 
                      static_cast<double>(config_.resource_limits.memory_usage_max_bytes);
    double gpu_util = current_usage.gpu_utilization_max;
    
    // Update resource dimension
    double resource_score = std::max({cpu_util, mem_util, gpu_util});
    UpdateDimension(StabilityDimension::RESOURCE, resource_score);
}

void StabilityEnvelope::UpdatePerformanceMetrics(double tps, double latency_ms, double throughput) {
    // Calculate performance score (normalized)
    // Lower latency = higher score, higher TPS = higher score
    double latency_score = std::max(0.0, 1.0 - (latency_ms / 1000.0)); // Normalize to ~1s
    double tps_score = std::min(1.0, tps / 100.0); // Normalize to 100 TPS
    double throughput_score = std::min(1.0, throughput / 1000.0); // Normalize
    
    double performance_score = (latency_score + tps_score + throughput_score) / 3.0;
    UpdateDimension(StabilityDimension::PERFORMANCE, performance_score);
}

StabilityState StabilityEnvelope::GetCurrentState() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return current_state_;
}

ThresholdSeverity StabilityEnvelope::GetDimensionSeverity(StabilityDimension dimension) const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    auto it = current_state_.current_severity.find(dimension);
    return (it != current_state_.current_severity.end()) ? it->second : ThresholdSeverity::INFO;
}

double StabilityEnvelope::GetStabilityScore() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return current_state_.overall_stability_score;
}

bool StabilityEnvelope::IsEnvelopeViolated() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return current_state_.envelope_violated;
}

bool StabilityEnvelope::CheckIntentSafety(const std::string& intent_type,
                                          const std::map<std::string, double>& context) const {
    if (!config_.enforce_safety_gates) {
        return true;
    }
    
    auto it = config_.intent_gates.find(intent_type);
    if (it == config_.intent_gates.end()) {
        // No gate defined, allow by default
        return true;
    }
    
    const auto& gate = it->second;
    
    // Check current system severity against required clearance
    auto current_severity = GetCurrentState().overall_severity;
    if (StabilityUtils::IsMoreSevere(current_severity, gate.required_clearance)) {
        return false;
    }
    
    // Check resource availability
    auto it_res = context.find("available_resources");
    if (it_res != context.end() && it_res->second < gate.min_available_resources) {
        return false;
    }
    
    // Check resource consumption
    auto it_cons = context.find("resource_consumption");
    if (it_cons != context.end() && it_cons->second > gate.max_resource_consumption) {
        return false;
    }
    
    return true;
}

bool StabilityEnvelope::CheckMutationSafety(const std::string& mutation_type,
                                           const std::map<std::string, double>& impact_estimate) const {
    // Check forbidden mutations
    const auto& forbidden = config_.mutation_constraints.forbidden_mutation_types;
    if (std::find(forbidden.begin(), forbidden.end(), mutation_type) != forbidden.end()) {
        return false;
    }
    
    // Check mutation rate
    // (Would need historical tracking in production)
    
    // Check rollback capability requirement
    if (config_.mutation_constraints.require_rollback_capability) {
        // Would check with RollbackEngine in production
    }
    
    // Check estimated impact
    auto it_impact = impact_estimate.find("stability_impact");
    if (it_impact != impact_estimate.end() && it_impact->second > 0.5) {
        return false; // Too risky
    }
    
    return true;
}

bool StabilityEnvelope::CheckRoleSafety(const std::string& role_name,
                                     const std::map<std::string, double>& role_context) const {
    auto it = config_.role_profiles.find(role_name);
    if (it == config_.role_profiles.end()) {
        return true; // No profile, allow
    }
    
    const auto& profile = it->second;
    
    // Check safety clearance
    auto current_severity = GetCurrentState().overall_severity;
    if (StabilityUtils::IsMoreSevere(current_severity, profile.min_safety_clearance)) {
        return false;
    }
    
    // Check resource allocation
    auto it_alloc = role_context.find("resource_allocation");
    if (it_alloc != role_context.end() && it_alloc->second > profile.max_resource_allocation) {
        return false;
    }
    
    // Check concurrent tasks
    auto it_tasks = role_context.find("concurrent_tasks");
    if (it_tasks != role_context.end() && it_tasks->second > profile.max_concurrent_tasks) {
        return false;
    }
    
    return true;
}

double StabilityEnvelope::AssessDecisionRisk(const std::string& decision_type,
                                               const std::map<std::string, double>& impact_factors) const {
    // Extract impact factors with defaults
    double perf_risk = 0.0;
    double stab_risk = 0.0;
    double res_risk = 0.0;
    double safety_risk = 0.0;
    double reversibility = 1.0;
    
    auto it = impact_factors.find("performance_impact");
    if (it != impact_factors.end()) perf_risk = it->second;
    
    it = impact_factors.find("stability_impact");
    if (it != impact_factors.end()) stab_risk = it->second;
    
    it = impact_factors.find("resource_impact");
    if (it != impact_factors.end()) res_risk = it->second;
    
    it = impact_factors.find("safety_impact");
    if (it != impact_factors.end()) safety_risk = it->second;
    
    it = impact_factors.find("reversibility");
    if (it != impact_factors.end()) reversibility = it->second;
    
    return config_.risk_profile.CalculateCompositeRisk(
        perf_risk, stab_risk, res_risk, safety_risk, reversibility);
}

ThresholdSeverity StabilityEnvelope::GetDecisionClearance(double risk_score) const {
    if (risk_score <= config_.risk_profile.max_acceptable_risk) {
        return ThresholdSeverity::INFO;
    } else if (risk_score <= config_.risk_profile.max_warning_risk) {
        return ThresholdSeverity::WARNING;
    } else {
        return ThresholdSeverity::CRITICAL;
    }
}

void StabilityEnvelope::SetAlertCallback(AlertCallback callback) {
    alert_callback_ = callback;
}

std::vector<StabilityAlert> StabilityEnvelope::GetActiveAlerts() const {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    return active_alerts_;
}

void StabilityEnvelope::AcknowledgeAlert(const std::string& alert_id) {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    
    for (auto& alert : active_alerts_) {
        if (alert.alert_id == alert_id) {
            // Mark as acknowledged (could add field)
            break;
        }
    }
}

void StabilityEnvelope::ClearAlert(const std::string& alert_id) {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    
    active_alerts_.erase(
        std::remove_if(active_alerts_.begin(), active_alerts_.end(),
            [alert_id](const auto& a) { return a.alert_id == alert_id; }),
        active_alerts_.end());
}

bool StabilityEnvelope::TriggerAutoRecovery(StabilityDimension dimension) {
    if (!config_.auto_recovery_enabled) {
        return false;
    }
    
    if (IsRecoveryInProgress()) {
        return false;
    }
    
    if (IsWithinCooldown(dimension)) {
        return false;
    }
    
    ExecuteAutoRecovery(dimension);
    return true;
}

bool StabilityEnvelope::IsRecoveryInProgress() const {
    return recovery_in_progress_.load();
}

std::vector<std::string> StabilityEnvelope::GetRecoveryActions() const {
    // Return list of available recovery actions
    return {
        "reduce_worker_count",
        "increase_worker_count",
        "clear_kv_cache",
        "reduce_batch_size",
        "increase_checkpoint_frequency",
        "pause_non_critical_tasks",
        "reset_graph_structure",
        "emergency_rollback"
    };
}

void StabilityEnvelope::UpdateThreshold(StabilityDimension dimension, 
                                        const StabilityThreshold& threshold) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    config_.thresholds[dimension] = threshold;
}

void StabilityEnvelope::UpdateResourceLimits(const ResourceSafetyLimits& limits) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    config_.resource_limits = limits;
}

void StabilityEnvelope::UpdateMutationConstraints(const GraphMutationConstraints& constraints) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    config_.mutation_constraints = constraints;
}

void StabilityEnvelope::UpdateRiskProfile(const DecisionRiskProfile& profile) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    config_.risk_profile = profile;
}

StabilityEnvelope::StabilityStatistics StabilityEnvelope::GetStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void StabilityEnvelope::ExportConfiguration(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return;
    
    file << "# Stability Envelope Configuration\n";
    file << "auto_recovery_enabled: " <> (config_.auto_recovery_enabled ? "true" : "false") << "\n";
    file << "alert_on_warning: " << (config_.alert_on_warning ? "true" : "false") << "\n";
    file << "enforce_safety_gates: " << (config_.enforce_safety_gates ? "true" : "false") << "\n";
    file << "max_alerts_per_minute: " << config_.max_alerts_per_minute << "\n";
    
    // Export thresholds
    file << "\n# Thresholds\n";
    for (const auto& [dim, thresh] : config_.thresholds) {
        file << StabilityUtils::DimensionToString(dim) << ":\n";
        file << "  nominal: [" << thresh.nominal_min << ", " << thresh.nominal_max << "]\n";
        file << "  warning: [" << thresh.warning_min << ", " << thresh.warning_max << "]\n";
        file << "  critical: [" << thresh.critical_min << ", " << thresh.critical_max << "]\n";
    }
}

void StabilityEnvelope::ImportConfiguration(const std::string& path) {
    // Simplified import - would use proper parser in production
    (void)path;
}

void StabilityEnvelope::ExportStateHistory(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return;
    
    file << "timestamp,dimension,value,severity\n";
    
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    for (const auto& [dim, history] : current_state_.history) {
        for (const auto& [ts, value] : history) {
            auto time_t = std::chrono::system_clock::to_time_t(
                std::chrono::system_clock::now() + 
                (ts - std::chrono::steady_clock::now()));
            
            file << time_t << ","
                 << StabilityUtils::DimensionToString(dim) << ","
                 << value << ","
                 << StabilityUtils::SeverityToString(current_state_.current_severity[dim])
                 << "\n";
        }
    }
}

// ============================================================================
// Private Methods
// ============================================================================

void StabilityEnvelope::MonitorLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        if (!running_) break;
        
        CheckForViolations();
    }
}

ThresholdSeverity StabilityEnvelope::EvaluateThreshold(StabilityDimension dimension, 
                                                        double value) const {
    auto it = config_.thresholds.find(dimension);
    if (it == config_.thresholds.end()) {
        return ThresholdSeverity::INFO;
    }
    
    const auto& thresh = it->second;
    
    // Check violation (outside critical bounds)
    if (value < thresh.critical_min || value > thresh.critical_max) {
        return ThresholdSeverity::VIOLATION;
    }
    
    // Check critical (outside nominal but within critical)
    if (value < thresh.nominal_min || value > thresh.nominal_max) {
        // Check if in warning zone
        if (value >= thresh.warning_min && value <= thresh.warning_max) {
            return ThresholdSeverity::WARNING;
        }
        return ThresholdSeverity::CRITICAL;
    }
    
    return ThresholdSeverity::INFO;
}

void StabilityEnvelope::CheckForViolations() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    for (const auto& [dim, sev] : current_state_.current_severity) {
        if (sev == ThresholdSeverity::VIOLATION) {
            // Check if violation has persisted long enough
            auto it = current_state_.violation_start_time.find(dim);
            if (it != current_state_.violation_start_time.end()) {
                auto duration = std::chrono::steady_clock::now() - it->second;
                auto it_thresh = config_.thresholds.find(dim);
                if (it_thresh != config_.thresholds.end() && 
                    duration >= it_thresh->second.min_violation_duration) {
                    // Trigger auto-recovery if enabled
                    if (ShouldTriggerRecovery(dim)) {
                        ExecuteAutoRecovery(dim);
                    }
                }
            }
        }
    }
}

void StabilityEnvelope::GenerateAlert(StabilityDimension dimension, 
                                      ThresholdSeverity severity,
                                      double current_value, 
                                      double threshold_value) {
    StabilityAlert alert;
    alert.alert_id = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    alert.dimension = dimension;
    alert.severity = severity;
    alert.current_value = current_value;
    alert.threshold_value = threshold_value;
    alert.timestamp = std::chrono::steady_clock::now();
    alert.auto_action_triggered = false;
    
    // Generate message
    std::stringstream msg;
    msg << StabilityUtils::DimensionToString(dimension) << " "
        << StabilityUtils::SeverityToString(severity) <> ": "
        << "value=" << std::fixed << std::setprecision(3) << current_value
        << ", threshold=" << threshold_value;
    alert.message = msg.str();
    
    // Generate recommendations
    switch (dimension) {
        case StabilityDimension::RESOURCE:
            alert.recommended_actions = {
                "reduce_worker_count",
                "clear_kv_cache",
                "pause_non_critical_tasks"
            };
            break;
        case StabilityDimension::PERFORMANCE:
            alert.recommended_actions = {
                "increase_worker_count",
                "reduce_batch_size",
                "optimize_graph_structure"
            };
            break;
        case StabilityDimension::HARMONIC:
            alert.recommended_actions = {
                "apply_oscillation_dampening",
                "increase_decision_cooldown",
                "reset_control_loop"
            };
            break;
        default:
            alert.recommended_actions = {"review_system_state"};
            break;
    }
    
    // Store alert
    {
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        active_alerts_.push_back(alert);
        
        // Limit number of alerts
        while (active_alerts_.size() > 100) {
            active_alerts_.erase(active_alerts_.begin());
        }
    }
    
    // Call callback
    if (alert_callback_) {
        alert_callback_(alert);
    }
}

void StabilityEnvelope::ExecuteAutoRecovery(StabilityDimension dimension) {
    if (recovery_in_progress_.exchange(true)) {
        return; // Already in progress
    }
    
    // Record recovery
    last_recovery_[dimension] = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.auto_recovery_count++;
        stats_.last_recovery = std::chrono::steady_clock::now();
    }
    
    // Execute recovery actions based on dimension
    switch (dimension) {
        case StabilityDimension::RESOURCE:
            // Would trigger resource recovery
            break;
        case StabilityDimension::PERFORMANCE:
            // Would trigger performance recovery
            break;
        case StabilityDimension::HARMONIC:
            // Would trigger oscillation dampening
            break;
        default:
            break;
    }
    
    recovery_in_progress_ = false;
}

double StabilityEnvelope::CalculateOverallStability() const {
    if (current_state_.current_values.empty()) {
        return 1.0;
    }
    
    double sum = 0.0;
    for (const auto& [dim, value] : current_state_.current_values) {
        // Normalize to stability score (1.0 = perfect stability)
        auto it = config_.thresholds.find(dim);
        if (it != config_.thresholds.end()) {
            double range = it->second.nominal_max - it->second.nominal_min;
            if (range > 0) {
                double normalized = 1.0 - std::abs(value - 0.5) * 2.0;
                sum += std::max(0.0, normalized);
            } else {
                sum += 1.0;
            }
        } else {
            sum += 1.0;
        }
    }
    
    return sum / current_state_.current_values.size();
}

bool StabilityEnvelope::ShouldTriggerRecovery(StabilityDimension dimension) const {
    if (!config_.auto_recovery_enabled) {
        return false;
    }
    
    auto it = config_.thresholds.find(dimension);
    if (it == config_.thresholds.end()) {
        return false;
    }
    
    // Check if within cooldown
    if (IsWithinCooldown(dimension)) {
        return false;
    }
    
    return true;
}

bool StabilityEnvelope::IsWithinCooldown(StabilityDimension dimension) const {
    auto it = last_recovery_.find(dimension);
    if (it == last_recovery_.end()) {
        return false;
    }
    
    auto it_thresh = config_.thresholds.find(dimension);
    if (it_thresh == config_.thresholds.end()) {
        return false;
    }
    
    auto elapsed = std::chrono::steady_clock::now() - it->second;
    return elapsed < it_thresh->second.recovery_cooldown;
}

// ============================================================================
// StabilityUtils Implementation
// ============================================================================

namespace StabilityUtils {

bool IsWithinEnvelope(double value, const StabilityThreshold& threshold) {
    return value >= threshold.nominal_min && value <= threshold.nominal_max;
}

bool IsWithinWarning(double value, const StabilityThreshold& threshold) {
    return (value >= threshold.warning_min && value < threshold.nominal_min) ||
           (value > threshold.nominal_max && value <= threshold.warning_max);
}

bool IsWithinCritical(double value, const StabilityThreshold& threshold) {
    return (value >= threshold.critical_min && value < threshold.warning_min) ||
           (value > threshold.warning_max && value <= threshold.critical_max);
}

bool IsMoreSevere(ThresholdSeverity a, ThresholdSeverity b) {
    static const std::map<ThresholdSeverity, int> severity_rank = {
        {ThresholdSeverity::INFO, 0},
        {ThresholdSeverity::WARNING, 1},
        {ThresholdSeverity::CRITICAL, 2},
        {ThresholdSeverity::VIOLATION, 3}
    };
    
    auto it_a = severity_rank.find(a);
    auto it_b = severity_rank.find(b);
    
    if (it_a == severity_rank.end() || it_b == severity_rank.end()) {
        return false;
    }
    
    return it_a->second > it_b->second;
}

ThresholdSeverity MaxSeverity(ThresholdSeverity a, ThresholdSeverity b) {
    return IsMoreSevere(a, b) ? a : b;
}

std::string DimensionToString(StabilityDimension dim) {
    switch (dim) {
        case StabilityDimension::HARMONIC: return "HARMONIC";
        case StabilityDimension::RESOURCE: return "RESOURCE";
        case StabilityDimension::PERFORMANCE: return "PERFORMANCE";
        case StabilityDimension::GRAPH_STRUCTURE: return "GRAPH_STRUCTURE";
        case StabilityDimension::DECISION_QUALITY: return "DECISION_QUALITY";
        case StabilityDimension::ROLE_BEHAVIOR: return "ROLE_BEHAVIOR";
        default: return "UNKNOWN";
    }
}

std::string SeverityToString(ThresholdSeverity sev) {
    switch (sev) {
        case ThresholdSeverity::INFO: return "INFO";
        case ThresholdSeverity::WARNING: return "WARNING";
        case ThresholdSeverity::CRITICAL: return "CRITICAL";
        case ThresholdSeverity::VIOLATION: return "VIOLATION";
        default: return "UNKNOWN";
    }
}

StabilityDimension StringToDimension(const std::string& str) {
    if (str == "HARMONIC") return StabilityDimension::HARMONIC;
    if (str == "RESOURCE") return StabilityDimension::RESOURCE;
    if (str == "PERFORMANCE") return StabilityDimension::PERFORMANCE;
    if (str == "GRAPH_STRUCTURE") return StabilityDimension::GRAPH_STRUCTURE;
    if (str == "DECISION_QUALITY") return StabilityDimension::DECISION_QUALITY;
    if (str == "ROLE_BEHAVIOR") return StabilityDimension::ROLE_BEHAVIOR;
    return StabilityDimension::HARMONIC; // Default
}

ThresholdSeverity StringToSeverity(const std::string& str) {
    if (str == "INFO") return ThresholdSeverity::INFO;
    if (str == "WARNING") return ThresholdSeverity::WARNING;
    if (str == "CRITICAL") return ThresholdSeverity::CRITICAL;
    if (str == "VIOLATION") return ThresholdSeverity::VIOLATION;
    return ThresholdSeverity::INFO; // Default
}

double CalculateVariance(const std::vector<double>& values) {
    if (values.size() < 2) return 0.0;
    
    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    double variance = 0.0;
    
    for (double v : values) {
        variance += (v - mean) * (v - mean);
    }
    
    return variance / values.size();
}

double CalculateTrend(const std::vector<std::pair<std::chrono::steady_clock::time_point, double>>& history) {
    if (history.size() < 2) return 0.0;
    
    // Simple linear regression on time series
    double n = static_cast<double>(history.size());
    double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_x2 = 0.0;
    
    auto start_time = history.front().first;
    
    for (size_t i = 0; i < history.size(); ++i) {
        double x = static_cast<double>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                history[i].first - start_time).count());
        double y = history[i].second;
        
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
    }
    
    double denominator = n * sum_x2 - sum_x * sum_x;
    if (std::abs(denominator) < 1e-10) return 0.0;
    
    return (n * sum_xy - sum_x * sum_y) / denominator;
}

bool DetectOscillation(const std::vector<double>& values, double threshold) {
    if (values.size() < 4) return false;
    
    // Count sign changes in first derivative
    uint32_t sign_changes = 0;
    double prev_diff = values[1] - values[0];
    
    for (size_t i = 2; i < values.size(); ++i) {
        double diff = values[i] - values[i-1];
        if ((prev_diff > 0 && diff < 0) || (prev_diff < 0 && diff > 0)) {
            sign_changes++;
        }
        prev_diff = diff;
    }
    
    // Oscillation if frequent sign changes
    double oscillation_ratio = static_cast<double>(sign_changes) / (values.size() - 2);
    return oscillation_ratio > threshold;
}

double NormalizeRiskScore(double raw_score, double min_expected, double max_expected) {
    if (max_expected <= min_expected) return raw_score;
    
    double normalized = (raw_score - min_expected) / (max_expected - min_expected);
    return std::max(0.0, std::min(1.0, normalized));
}

double CombineRiskScores(const std::vector<double>& scores, 
                        const std::vector<double>& weights) {
    if (scores.size() != weights.size() || scores.empty()) return 0.0;
    
    double sum = 0.0;
    double weight_sum = 0.0;
    
    for (size_t i = 0; i < scores.size(); ++i) {
        sum += scores[i] * weights[i];
        weight_sum += weights[i];
    }
    
    if (weight_sum < 1e-10) return 0.0;
    
    return sum / weight_sum;
}

} // namespace StabilityUtils

} // namespace Autonomy
