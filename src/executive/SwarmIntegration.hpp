// ============================================================================
// SwarmIntegration.hpp - Unified Swarm Integration
// ============================================================================
// Integrates TokenEfficiencySwarm and TokenEstimatorSwarm together.
// When efficiency threshold is exceeded, triggers deep token analysis.
// ============================================================================

#pragma once
#include "TokenEfficiencySwarm.hpp"
#include "TokenEstimatorSwarm.hpp"
#include "EfficiencyBridge.hpp"

namespace RawrXD {
namespace Executive {

// ============================================================================
// Unified Swarm Context
// ============================================================================
struct UnifiedSwarmContext {
    // From EfficiencyBridge
    EfficiencyBridgeContext efficiency;
    
    // Token estimation data
    TokenEstimate tokenEstimate;
    
    // Integration flags
    bool enableDeepAnalysis;      // Trigger TokenEstimatorSwarm on efficiency alert
    bool enablePatternLearning;   // Update learned biases automatically
    bool enableTelemetryExport;   // Export to telemetry
};

// ============================================================================
// Swarm Integration Manager - Singleton
// ============================================================================
class SwarmIntegrationManager {
public:
    static SwarmIntegrationManager& getInstance() {
        static SwarmIntegrationManager instance;
        return instance;
    }
    
    // Initialize both swarms with coordinated configuration
    void initialize();
    
    // Process a cycle from AutonomousLoop
    // Records estimates before execution, actuals after, triggers analysis if needed
    void processCycleStart(uint64_t goalId, const char* operation, const char* agent, 
                           float estimatedTokens);
    void processCycleEnd(uint64_t goalId, float actualTokens, uint32_t retryCount = 0);
    
    // Check if efficiency threshold exceeded and trigger deep analysis
    void checkEfficiencyAndAnalyze(uint64_t goalId, float actual, float estimated);
    
    // Get combined recommendations from both swarms
    std::vector<const char*> getRecommendations(uint64_t goalId);
    
    // Export telemetry data
    void exportTelemetry(const char* filename);
    
    // Export Prometheus metrics
    void exportPrometheusMetrics(const char* filename);
    
    // Reset all state
    void reset();
    
private:
    SwarmIntegrationManager() = default;
    ~SwarmIntegrationManager() = default;
    SwarmIntegrationManager(const SwarmIntegrationManager&) = delete;
    SwarmIntegrationManager& operator=(const SwarmIntegrationManager&) = delete;
    
    bool initialized_ = false;
    
    // Track active goals
    std::unordered_map<uint64_t, TokenEstimate> activeEstimates_;
};

// ============================================================================
// C-API for integration with AutonomousLoop
// ============================================================================
extern "C" {
    // Initialize the integrated swarm system
    void InitializeSwarmIntegration();
    
    // Call at start of ACT phase
    void SwarmCycleStart(uint64_t goalId, const char* operation, const char* agent,
                         float estimatedTokens);
    
    // Call at end of ACT phase
    void SwarmCycleEnd(uint64_t goalId, float actualTokens, uint32_t retryCount);
    
    // Get recommendations (writes to buffer)
    void GetSwarmRecommendations(uint64_t goalId, char* buffer, size_t bufferSize);
}

} // namespace Executive
} // namespace RawrXD
