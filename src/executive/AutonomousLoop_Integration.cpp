// ============================================================================
// AutonomousLoop_Integration.cpp - Swarm Integration Implementation
// ============================================================================

#include "AutonomousLoop_Integration.hpp"
#include <cstdio>

namespace RawrXD {
namespace Executive {

// ============================================================================
// ACT Phase Start
// ============================================================================
void AutonomousLoopSwarmIntegration::onActStart(uint64_t goalId,
                                                  const std::vector<std::string>& actions,
                                                  float estimatedTokenCost) {
    // Determine operation type from actions
    const char* operation = "unknown";
    if (!actions.empty()) {
        // Use first action as operation type
        operation = actions[0].c_str();
    }
    
    // Determine agent from operation type
    const char* agent = "default_agent";
    if (strstr(operation, "code")) agent = "coder_agent";
    else if (strstr(operation, "analyze")) agent = "analyzer_agent";
    else if (strstr(operation, "test")) agent = "tester_agent";
    else if (strstr(operation, "dispatch")) agent = "dispatcher_agent";
    
    // Record the estimate
    SwarmIntegrationManager::getInstance().processCycleStart(
        goalId, operation, agent, estimatedTokenCost);
}

// ============================================================================
// ACT Phase End
// ============================================================================
void AutonomousLoopSwarmIntegration::onActEnd(uint64_t goalId,
                                               size_t tokensConsumed,
                                               size_t tokensSaved,
                                               uint32_t retryCount) {
    // Record the actuals
    SwarmIntegrationManager::getInstance().processCycleEnd(
        goalId, static_cast<float>(tokensConsumed), retryCount);
}

// ============================================================================
// Get Recommendations
// ============================================================================
std::vector<std::string> AutonomousLoopSwarmIntegration::getRecommendations(uint64_t goalId) {
    std::vector<std::string> result;
    
    auto recs = SwarmIntegrationManager::getInstance().getRecommendations(goalId);
    for (const auto& rec : recs) {
        if (rec) result.push_back(std::string(rec));
    }
    
    return result;
}

// ============================================================================
// Check Efficiency Alert
// ============================================================================
bool AutonomousLoopSwarmIntegration::hasEfficiencyAlert(uint64_t goalId) {
    // Check if TokenEfficiencySwarm has triggered for this goal
    // This is a simplified check - in production, you'd track per-goal state
    auto& swarm = TokenEfficiencySwarm::getInstance();
    return swarm.getTriggerCount() > 0;
}

// ============================================================================
// Get Efficiency Ratio
// ============================================================================
float AutonomousLoopSwarmIntegration::getEfficiencyRatio(uint64_t goalId) {
    // Get from TokenEstimatorSwarm history
    auto history = TokenEstimatorSwarm::getInstance().getHistory(goalId, 1);
    if (!history.empty()) {
        const auto& record = history.back();
        if (record.totalEstimated > 0) {
            return record.totalActual / record.totalEstimated;
        }
    }
    return 1.0f;  // No data = neutral
}

// ============================================================================
// Get Slack Percentage
// ============================================================================
float AutonomousLoopSwarmIntegration::getSlackPercentage(uint64_t goalId) {
    auto history = TokenEstimatorSwarm::getInstance().getHistory(goalId, 1);
    if (!history.empty()) {
        const auto& record = history.back();
        if (record.totalEstimated > 0) {
            return (record.slack / record.totalEstimated) * 100.0f;
        }
    }
    return 0.0f;  // No data = no slack
}

} // namespace Executive
} // namespace RawrXD
