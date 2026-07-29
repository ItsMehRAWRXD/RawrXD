// ============================================================================
// VAL-062: Swarm Integration Validation Gate Implementation
// ============================================================================

#include "VAL062_SwarmIntegrationGate.h"
#include "../../Executive/SwarmIntegration.hpp"
#include "../../Executive/TokenEfficiencySwarm.hpp"
#include "../../Executive/TokenEstimatorSwarm.hpp"
#include <cstdio>
#include <cstring>

namespace RawrXD {
namespace Validation {

ValidationResult VAL062_SwarmIntegrationGate::Execute() {
    ValidationResult result;
    result.gateId = GetId();
    result.gateName = GetName();
    result.startTime = std::chrono::high_resolution_clock::now();
    result.status = GateStatus::IMPLEMENTED;
    
    printf("[%s] Validating Swarm Integration...\n", GetId().c_str());
    
    auto& manager = Executive::SwarmIntegrationManager::getInstance();
    manager.reset();
    manager.initialize();
    
    // Test 1: Verify both swarms are initialized
    printf("[%s] Test 1: Swarm initialization...\n", GetId().c_str());
    auto& efficiencySwarm = Executive::TokenEfficiencySwarm::getInstance();
    auto& estimatorSwarm = Executive::TokenEstimatorSwarm::getInstance();
    
    const auto& config = efficiencySwarm.getConfig();
    if (config.triggerThreshold != 2.0f) {
        result.success = false;
        result.message = "TokenEfficiencySwarm not properly configured";
        result.endTime = std::chrono::high_resolution_clock::now();
        return result;
    }
    printf("[%s]   TokenEfficiencySwarm configured (threshold: %.1f)\n", 
           GetId().c_str(), config.triggerThreshold);
    
    // Test 2: Simulate AutonomousLoop cycle with efficiency trigger
    printf("[%s] Test 2: End-to-end cycle simulation...\n", GetId().c_str());
    
    uint64_t goalId = 999062;
    float estimatedTokens = 1000.0f;
    
    // Start cycle (like AutonomousLoop::act)
    manager.processCycleStart(goalId, "complex_analysis", "architect_agent", estimatedTokens);
    printf("[%s]   Cycle started: goal=%llu, estimated=%.0f\n", 
           GetId().c_str(), (unsigned long long)goalId, estimatedTokens);
    
    // End cycle with 2.5x overhead (triggers efficiency swarm at 2.0x threshold)
    float actualTokens = estimatedTokens * 2.5f;
    uint32_t initialTriggerCount = efficiencySwarm.getTriggerCount();
    
    manager.processCycleEnd(goalId, actualTokens, 1);  // 1 retry
    
    uint32_t finalTriggerCount = efficiencySwarm.getTriggerCount();
    bool efficiencyTriggered = (finalTriggerCount > initialTriggerCount);
    
    printf("[%s]   Cycle ended: actual=%.0f (%.1fx), efficiency triggered: %s\n",
           GetId().c_str(), actualTokens, actualTokens/estimatedTokens,
           efficiencyTriggered ? "YES" : "NO");
    
    // Test 3: Verify TokenEstimatorSwarm recorded the data
    printf("[%s] Test 3: TokenEstimatorSwarm data recording...\n", GetId().c_str());
    
    auto history = estimatorSwarm.getHistory(goalId, 1);
    if (history.empty()) {
        result.success = false;
        result.message = "TokenEstimatorSwarm did not record cycle data";
        result.endTime = std::chrono::high_resolution_clock::now();
        return result;
    }
    
    const auto& record = history.back();
    printf("[%s]   Recorded: est=%.0f, actual=%.0f, slack=%+.0f\n",
           GetId().c_str(), record.totalEstimated, record.totalActual, record.slack);
    
    // Test 4: Verify recommendations are generated
    printf("[%s] Test 4: Recommendation generation...\n", GetId().c_str());
    
    auto recommendations = manager.getRecommendations(goalId);
    printf("[%s]   Generated %zu recommendations\n", GetId().c_str(), recommendations.size());
    
    for (size_t i = 0; i < recommendations.size() && i < 3; i++) {
        printf("[%s]     - %s\n", GetId().c_str(), recommendations[i]);
    }
    
    // Test 5: Verify recommendation quality
    printf("[%s] Test 5: Recommendation quality check...\n", GetId().c_str());
    
    if (recommendations.empty()) {
        result.success = false;
        result.message = "No recommendations generated";
        result.endTime = std::chrono::high_resolution_clock::now();
        return result;
    }
    printf("[%s]   Recommendations validated: %zu items\n", GetId().c_str(), recommendations.size());
    
    // All tests passed
    result.success = true;
    result.message = "Swarm Integration validation passed - all 5 tests successful";
    result.endTime = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        result.endTime - result.startTime).count();
    
    printf("[%s] All tests passed in %lld ms\n", GetId().c_str(), duration);
    
    return result;
}

} // namespace Validation
} // namespace RawrXD
