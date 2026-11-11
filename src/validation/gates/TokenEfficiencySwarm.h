// ============================================================================
// TokenEfficiencySwarm.h - Production-Ready Efficiency Optimization System
// ============================================================================
// Implements configurable thresholds, rate limiting, telemetry, and hysteresis
// for the efficiency swarm validation gate.
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"
#include <atomic>
#include <chrono>
#include <mutex>
#include <unordered_map>

namespace RawrXD {
namespace Validation {

// Configuration for efficiency swarm triggers
struct EfficiencySwarmConfig {
    float triggerThreshold = 3.0f;        // Trigger when actual > threshold * estimated
    float retriggerThreshold = 2.5f;      // Hysteresis - don't retrigger until below this
    uint32_t minTriggerIntervalMs = 1000; // Rate limiting - minimum ms between triggers
    uint32_t maxTriggersPerGoal = 10;     // Max triggers per goal before cooldown
    bool nonBlocking = true;              // If true, trigger() returns immediately
    bool enableTelemetry = true;          // Record trigger events for tuning
};

// Telemetry record for a single trigger event
struct TriggerTelemetry {
    std::string goalId;
    std::string goalName;
    float actualCost;
    float estimatedCost;
    uint32_t agentCount;
    std::string assignedAgent;
    std::chrono::steady_clock::time_point timestamp;
    uint32_t triggerCount;
};

// Goal-specific state tracking
struct GoalState {
    uint32_t triggerCount = 0;
    std::chrono::steady_clock::time_point lastTriggerTime;
    bool inCooldown = false;
    float lastActualCost = 0.0f;
};

// Patch context passed to validators
struct PatchContext {
    std::string goalId;
    std::string goalName;
    float actualCost;
    float estimatedCost;
    uint32_t agentCount;
    std::string assignedAgent;
};

// Patch result for validator returns
struct PatchResult {
    bool success;
    std::string message;
    
    static PatchResult ok(const std::string& msg) { return {true, msg}; }
    static PatchResult error(const std::string& msg) { return {false, msg}; }
};

// Token Efficiency Swarm - Production Implementation
class TokenEfficiencySwarm {
public:
    static TokenEfficiencySwarm& getInstance();
    
    // Configuration
    void setConfig(const EfficiencySwarmConfig& config);
    EfficiencySwarmConfig getConfig() const;
    
    // Main trigger point
    PatchResult trigger(const PatchContext& ctx);
    
    // Internal processing (can be called directly for synchronous operation)
    PatchResult processTrigger(const PatchContext& ctx);
    
    // Telemetry access
    std::vector<TriggerTelemetry> getTelemetry() const;
    void clearTelemetry();
    
    // Statistics
    struct Stats {
        uint64_t totalTriggers = 0;
        uint64_t rateLimitedTriggers = 0;
        uint64_t hysteresisBlockedTriggers = 0;
        std::unordered_map<std::string, uint32_t> triggersPerGoal;
    };
    Stats getStats() const;
    void resetStats();
    
    // Manual control
    void forceTrigger(const PatchContext& ctx);
    void resetGoalState(const std::string& goalId);
    
private:
    TokenEfficiencySwarm() = default;
    
    mutable std::mutex mutex_;
    EfficiencySwarmConfig config_;
    
    std::unordered_map<std::string, GoalState> goalStates_;
    std::vector<TriggerTelemetry> telemetry_;
    Stats stats_;
    
    bool shouldTrigger(const PatchContext& ctx, const GoalState& state);
    void recordTelemetry(const PatchContext& ctx);
    void updateGoalState(const std::string& goalId, const PatchContext& ctx);
};

// Proxy validator function
PatchResult efficiencySwarmValidator(const PatchContext* ctx);

// VAL-061: Token Efficiency Swarm Validation Gate
class VAL061_TokenEfficiencySwarmGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-061"; }
    std::string GetName() const override { return "Token Efficiency Swarm"; }
    std::string GetDescription() const override {
        return "Validates efficiency swarm with configurable thresholds, "
               "rate limiting, telemetry, and hysteresis";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-060"}; }
    
private:
    bool ValidateThresholdConfiguration();
    bool ValidateRateLimiting();
    bool ValidateHysteresis();
    bool ValidateTelemetry();
    bool ValidateNonBlockingTrigger();
};

} // namespace Validation
} // namespace RawrXD
