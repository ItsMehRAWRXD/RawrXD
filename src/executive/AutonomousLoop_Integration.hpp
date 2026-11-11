// ============================================================================
// AutonomousLoop_Integration.hpp - Swarm Integration for AutonomousLoop
// ============================================================================
// Drop-in integration points for AutonomousLoop ACT phase
// ============================================================================

#pragma once
#include "SwarmIntegration.hpp"

namespace RawrXD {
namespace Executive {

// ============================================================================
// AutonomousLoop Swarm Integration Helper
// ============================================================================
class AutonomousLoopSwarmIntegration {
public:
    // Call at the start of ACT phase
    static void onActStart(uint64_t goalId, 
                           const std::vector<std::string>& actions,
                           float estimatedTokenCost);
    
    // Call at the end of ACT phase
    static void onActEnd(uint64_t goalId,
                         size_t tokensConsumed,
                         size_t tokensSaved,
                         uint32_t retryCount = 0);
    
    // Get recommendations for the current cycle
    static std::vector<std::string> getRecommendations(uint64_t goalId);
    
    // Check if efficiency alert is active
    static bool hasEfficiencyAlert(uint64_t goalId);
    
    // Get efficiency metrics
    static float getEfficiencyRatio(uint64_t goalId);
    static float getSlackPercentage(uint64_t goalId);
};

// ============================================================================
// Convenience Macros for AutonomousLoop Integration
// ============================================================================

// At the start of ACT phase:
// SWARM_ACT_START(goalId, actions, estimatedCost)
#define SWARM_ACT_START(goalId, actions, estimatedCost) \
    RawrXD::Executive::AutonomousLoopSwarmIntegration::onActStart(goalId, actions, estimatedCost)

// At the end of ACT phase:
// SWARM_ACT_END(goalId, tokensConsumed, tokensSaved, retryCount)
#define SWARM_ACT_END(goalId, tokensConsumed, tokensSaved, retryCount) \
    RawrXD::Executive::AutonomousLoopSwarmIntegration::onActEnd(goalId, tokensConsumed, tokensSaved, retryCount)

// Get recommendations:
// auto recs = SWARM_GET_RECOMMENDATIONS(goalId);
#define SWARM_GET_RECOMMENDATIONS(goalId) \
    RawrXD::Executive::AutonomousLoopSwarmIntegration::getRecommendations(goalId)

} // namespace Executive
} // namespace RawrXD
