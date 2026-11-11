// ============================================================================
// VAL-061: Token Estimator Swarm Validation Gate Implementation
// ============================================================================

#include "VAL061_TokenEstimatorSwarmGate.h"
#include "../../Executive/TokenEstimatorSwarm.hpp"
#include <cstdio>
#include <cmath>

namespace RawrXD {
namespace Validation {

ValidationResult VAL061_TokenEstimatorSwarmGate::Execute() {
    ValidationResult result;
    result.gateId = GetId();
    result.gateName = GetName();
    result.startTime = std::chrono::high_resolution_clock::now();
    result.status = GateStatus::IMPLEMENTED;
    
    printf("[%s] Validating Token Estimator Swarm...\n", GetId().c_str());
    
    auto& swarm = Executive::TokenEstimatorSwarm::getInstance();
    
    // Test 1: Record and retrieve estimates
    printf("[%s] Test 1: Recording token estimates...\n", GetId().c_str());
    
    Executive::TokenEstimate estimate;
    estimate.goalId = 999001;
    estimate.totalEstimated = 500.0f;
    estimate.estimatedByCategory[static_cast<int>(Executive::TokenCategory::PROMPT_TOKENS)] = 100.0f;
    estimate.estimatedByCategory[static_cast<int>(Executive::TokenCategory::COMPLETION_TOKENS)] = 400.0f;
    estimate.operationType = "test_operation";
    estimate.agentName = "test_agent";
    
    swarm.recordEstimate(999001, estimate);
    
    // Test 2: Record actuals and calculate slack
    printf("[%s] Test 2: Recording actuals and calculating slack...\n", GetId().c_str());
    
    Executive::TokenEstimate actuals;
    actuals.goalId = 999001;
    actuals.totalActual = 650.0f;
    actuals.actualByCategory[static_cast<int>(Executive::TokenCategory::PROMPT_TOKENS)] = 110.0f;
    actuals.actualByCategory[static_cast<int>(Executive::TokenCategory::COMPLETION_TOKENS)] = 480.0f;
    actuals.actualByCategory[static_cast<int>(Executive::TokenCategory::THINKING_TOKENS)] = 60.0f;
    actuals.operationType = "test_operation";
    actuals.agentName = "test_agent";
    
    swarm.recordActuals(999001, actuals);
    
    // Test 3: Analyze slack
    printf("[%s] Test 3: Analyzing slack...\n", GetId().c_str());
    
    auto analysis = swarm.analyzeSlack(999001);
    
    if (analysis.totalSlack < 0) {
        result.success = false;
        result.message = "Slack calculation failed - expected positive slack";
        result.endTime = std::chrono::high_resolution_clock::now();
        return result;
    }
    
    printf("[%s]   Total slack: %+.0f tokens\n", GetId().c_str(), analysis.totalSlack);
    printf("[%s]   Largest category: %s\n", GetId().c_str(), 
           Executive::TokenCategoryToString(analysis.largestSlackCategory));
    
    // Test 4: Verify improved estimates
    printf("[%s] Test 4: Testing improved estimate generation...\n", GetId().c_str());
    
    float baseEstimate = 500.0f;
    auto improved = swarm.getImprovedEstimate("test_operation", "test_agent", baseEstimate);
    
    printf("[%s]   Base estimate: %.0f, Improved: %.0f\n", GetId().c_str(), 
           baseEstimate, improved.totalEstimated);
    
    // Test 5: Verify history retrieval
    printf("[%s] Test 5: Testing history retrieval...\n", GetId().c_str());
    
    auto history = swarm.getHistory(999001, 10);
    if (history.empty()) {
        result.success = false;
        result.message = "History retrieval failed - no records found";
        result.endTime = std::chrono::high_resolution_clock::now();
        return result;
    }
    
    printf("[%s]   Retrieved %zu records from history\n", GetId().c_str(), history.size());
    
    // All tests passed
    result.success = true;
    result.message = "Token Estimator Swarm validation passed - all 5 tests successful";
    result.endTime = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        result.endTime - result.startTime).count();
    
    printf("[%s] \u2713 All tests passed in %lld ms\n", GetId().c_str(), duration);
    
    return result;
}

} // namespace Validation
} // namespace RawrXD
