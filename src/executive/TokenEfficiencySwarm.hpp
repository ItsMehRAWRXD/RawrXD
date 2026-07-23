// ============================================================
// TokenEfficiencySwarm.hpp - Executive Cost Optimization Swarm
// ============================================================
// A swarm of 8 efficiency agents triggered when token costs exceed
// estimates by configurable thresholds.
// ============================================================

#pragma once
#include <cstdint>
#include <atomic>
#include <chrono>

namespace RawrXD {
namespace Executive {

// ============================================================
// Efficiency Agent Types (8 agents in the swarm)
// ============================================================
enum class EfficiencyAgent {
    CostAnalyzer = 0,      // Analyzes cost divergence patterns
    TokenOptimizer,        // Suggests token reduction strategies
    LoadBalancer,          // Rebalances across agents
    RoutingOptimizer,      // Optimizes request routing
    CacheAdvisor,          // Recommends caching strategies
    BatchingOptimizer,     // Optimizes batch sizes
    ModelSelector,         // Suggests model size adjustments
    TelemetryRecorder      // Records efficiency metrics
};

// ============================================================
// Swarm Trigger Configuration
// ============================================================
struct SwarmConfig {
    float triggerThreshold = 3.0f;        // Trigger when actual > 3x estimate
    float retriggerThreshold = 2.5f;      // Don't retrigger until below 2.5x
    uint32_t minTriggerIntervalMs = 1000; // Rate limiting: max 1 trigger/sec
    bool nonBlocking = true;              // trigger() returns immediately
    bool enableTelemetry = true;          // Record all triggers
};

// ============================================================
// Trigger Telemetry Record
// ============================================================
struct TriggerTelemetry {
    uint64_t goalId;
    float actualCost;
    float estimatedCost;
    size_t agentCount;
    std::chrono::steady_clock::time_point timestamp;
    uint32_t triggerCount;
};

// ============================================================
// Token Efficiency Swarm - Singleton
// ============================================================
class TokenEfficiencySwarm {
public:
    static TokenEfficiencySwarm& getInstance() {
        static TokenEfficiencySwarm instance;
        return instance;
    }

    // Configure swarm behavior
    void configure(const SwarmConfig& config) { config_ = config; }
    const SwarmConfig& getConfig() const { return config_; }

    // Main trigger point - called from bridge validator
    // Returns immediately (non-blocking)
    void trigger(uint64_t goalId, const char* goalName,
                 float actualCost, float estimatedCost,
                 size_t agentCount, const char* assignedAgent);

    // Check if trigger would fire (for testing)
    bool wouldTrigger(float actualCost, float estimatedCost) const {
        return actualCost > config_.triggerThreshold * estimatedCost;
    }

    // Get telemetry
    uint32_t getTriggerCount() const { return triggerCount_.load(); }
    auto getLastTriggerTime() const { return lastTriggerTime_; }
    
    // Reset telemetry
    void resetTelemetry() {
        triggerCount_.store(0);
        lastTriggerTime_ = {};
    }

    // Hysteresis check - prevents oscillation
    bool canRetrigger() const;

private:
    TokenEfficiencySwarm() = default;
    ~TokenEfficiencySwarm() = default;
    TokenEfficiencySwarm(const TokenEfficiencySwarm&) = delete;
    TokenEfficiencySwarm& operator=(const TokenEfficiencySwarm&) = delete;

    // Execute the 8 efficiency agents
    void executeSwarm(uint64_t goalId, const char* goalName,
                      float actualCost, float estimatedCost,
                      size_t agentCount, const char* assignedAgent);

    // Individual agent handlers
    void runCostAnalyzer(uint64_t goalId, float actual, float estimated);
    void runTokenOptimizer(uint64_t goalId, float actual, float estimated);
    void runLoadBalancer(uint64_t goalId, size_t agentCount);
    void runRoutingOptimizer(uint64_t goalId, const char* assignedAgent);
    void runCacheAdvisor(uint64_t goalId);
    void runBatchingOptimizer(uint64_t goalId);
    void runModelSelector(uint64_t goalId, float actual, float estimated);
    void runTelemetryRecorder(uint64_t goalId, float actual, float estimated, 
                               size_t agentCount);

    SwarmConfig config_;
    std::atomic<uint32_t> triggerCount_{0};
    std::atomic<std::chrono::steady_clock::time_point> lastTriggerTime_;
    std::atomic<bool> isExecuting_{false};
};

// ============================================================
// C-API for function pointer compatibility
// ============================================================
extern "C" {
    typedef void (*SwarmTriggerFn)(uint64_t goalId, const char* goalName,
                                  float actualCost, float estimatedCost,
                                  size_t agentCount, const char* assignedAgent);
    
    // Get the swarm trigger function pointer
    inline SwarmTriggerFn GetSwarmTriggerFn() {
        return [](uint64_t gid, const char* gname, float actual, float est,
                  size_t agents, const char* assigned) {
            TokenEfficiencySwarm::getInstance().trigger(gid, gname, actual, est, agents, assigned);
        };
    }
}

} // namespace Executive
} // namespace RawrXD
