// ============================================================================
// test_swarm_integration.cpp - End-to-End Swarm Integration Test
// ============================================================================
// Tests the complete flow: TokenEfficiencySwarm triggers TokenEstimatorSwarm
// for deep analysis when efficiency thresholds are exceeded.
// ============================================================================

#include "SwarmIntegration.hpp"
#include "TokenEfficiencySwarm.hpp"
#include "TokenEstimatorSwarm.hpp"
#include <cstdio>
#include <cstring>

using namespace RawrXD::Executive;

// Test result tracking
struct TestResults {
    int passed = 0;
    int failed = 0;
    
    void record(bool success, const char* testName) {
        if (success) {
            passed++;
            printf("  \u2713 %s\n", testName);
        } else {
            failed++;
            printf("  \u2717 %s\n", testName);
        }
    }
};

// ============================================================================
// Test 1: Basic Swarm Integration Initialization
// ============================================================================
bool test_initialization() {
    printf("\n[Test 1] Swarm Integration Initialization\n");
    
    auto& manager = SwarmIntegrationManager::getInstance();
    manager.initialize();
    
    // Verify TokenEfficiencySwarm is configured
    auto& efficiencySwarm = TokenEfficiencySwarm::getInstance();
    const auto& config = efficiencySwarm.getConfig();
    
    bool success = (config.triggerThreshold == 2.0f) &&
                   (config.retriggerThreshold == 1.5f) &&
                   (config.nonBlocking == true);
    
    printf("  Trigger threshold: %.1f (expected 2.0)\n", config.triggerThreshold);
    printf("  Retrigger threshold: %.1f (expected 1.5)\n", config.retriggerThreshold);
    printf("  Non-blocking: %s\n", config.nonBlocking ? "true" : "false");
    
    return success;
}

// ============================================================================
// Test 2: Cycle Start/End Recording
// ============================================================================
bool test_cycle_recording() {
    printf("\n[Test 2] Cycle Start/End Recording\n");
    
    auto& manager = SwarmIntegrationManager::getInstance();
    manager.reset();  // Clear previous state
    manager.initialize();
    
    uint64_t goalId = 1001;
    float estimatedTokens = 500.0f;
    
    // Start cycle
    manager.processCycleStart(goalId, "test_operation", "test_agent", estimatedTokens);
    
    // End cycle with 50% overhead (triggers efficiency swarm)
    float actualTokens = estimatedTokens * 1.5f;
    manager.processCycleEnd(goalId, actualTokens, 0);
    
    // Verify history was recorded
    auto history = TokenEstimatorSwarm::getInstance().getHistory(goalId, 1);
    bool success = !history.empty();
    
    if (success) {
        const auto& record = history.back();
        printf("  Recorded: est=%.0f, actual=%.0f, slack=%+.0f\n",
               record.totalEstimated, record.totalActual, record.slack);
    }
    
    return success;
}

// ============================================================================
// Test 3: Efficiency Threshold Triggering
// ============================================================================
bool test_efficiency_triggering() {
    printf("\n[Test 3] Efficiency Threshold Triggering\n");
    
    auto& manager = SwarmIntegrationManager::getInstance();
    manager.reset();
    manager.initialize();
    
    auto& efficiencySwarm = TokenEfficiencySwarm::getInstance();
    uint32_t initialTriggerCount = efficiencySwarm.getTriggerCount();
    
    uint64_t goalId = 1002;
    float estimatedTokens = 500.0f;
    
    // Start cycle
    manager.processCycleStart(goalId, "heavy_operation", "architect_agent", estimatedTokens);
    
    // End cycle with 3x overhead (definitely triggers efficiency swarm at 2.0x threshold)
    float actualTokens = estimatedTokens * 3.0f;
    manager.processCycleEnd(goalId, actualTokens, 0);
    
    uint32_t finalTriggerCount = efficiencySwarm.getTriggerCount();
    bool triggered = (finalTriggerCount > initialTriggerCount);
    
    printf("  Initial triggers: %u\n", initialTriggerCount);
    printf("  Final triggers: %u\n", finalTriggerCount);
    printf("  Triggered: %s\n", triggered ? "YES" : "NO");
    
    return triggered;
}

// ============================================================================
// Test 4: Recommendations Retrieval
// ============================================================================
bool test_recommendations() {
    printf("\n[Test 4] Recommendations Retrieval\n");
    
    auto& manager = SwarmIntegrationManager::getInstance();
    manager.reset();
    manager.initialize();
    
    uint64_t goalId = 1003;
    
    // Create a scenario with significant slack
    manager.processCycleStart(goalId, "complex_refactoring", "architect_agent", 1000.0f);
    manager.processCycleEnd(goalId, 2500.0f, 2);  // 2.5x with 2 retries
    
    // Get recommendations
    auto recs = manager.getRecommendations(goalId);
    
    printf("  Retrieved %zu recommendations\n", recs.size());
    for (size_t i = 0; i < recs.size() && i < 3; i++) {
        printf("    %zu. %s\n", i + 1, recs[i]);
    }
    
    // Success if we got at least one recommendation (slack was analyzed)
    return !recs.empty();
}

// ============================================================================
// Test 5: C-API Integration
// ============================================================================
bool test_c_api() {
    printf("\n[Test 5] C-API Integration\n");
    
    // Reset and initialize via C-API
    SwarmIntegrationManager::getInstance().reset();
    InitializeSwarmIntegration();
    
    uint64_t goalId = 1004;
    
    // Use C-API functions
    SwarmCycleStart(goalId, "c_api_test", "test_agent", 300.0f);
    SwarmCycleEnd(goalId, 450.0f, 1);
    
    // Get recommendations via C-API
    char buffer[1024];
    GetSwarmRecommendations(goalId, buffer, sizeof(buffer));
    
    printf("  C-API recommendations:\n%s\n", buffer);
    
    // Success if buffer contains our goal ID
    return strstr(buffer, "1004") != nullptr;
}

// ============================================================================
// Test 6: Pattern Learning
// ============================================================================
bool test_pattern_learning() {
    printf("\n[Test 6] Pattern Learning\n");
    
    auto& manager = SwarmIntegrationManager::getInstance();
    manager.reset();
    manager.initialize();
    
    // Record multiple cycles for same operation type
    for (int i = 0; i < 5; i++) {
        uint64_t goalId = 2000 + i;
        manager.processCycleStart(goalId, "code_generation", "coder_agent", 500.0f);
        manager.processCycleEnd(goalId, 750.0f, 0);  // Consistent 50% overhead
    }
    
    // Get improved estimate
    auto improved = TokenEstimatorSwarm::getInstance()
        .getImprovedEstimate("code_generation", "coder_agent", 500.0f);
    
    printf("  Base estimate: 500.0\n");
    printf("  Improved estimate: %.0f\n", improved.totalEstimated);
    
    // Should have learned the +50% bias
    return improved.totalEstimated > 500.0f;
}

// ============================================================================
// Main Test Runner
// ============================================================================
int main() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║     Swarm Integration Test Suite                                ║\n");
    printf("║     Tests TokenEfficiencySwarm + TokenEstimatorSwarm Integration  ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    
    TestResults results;
    
    // Run all tests
    results.record(test_initialization(), "Initialization");
    results.record(test_cycle_recording(), "Cycle Recording");
    results.record(test_efficiency_triggering(), "Efficiency Triggering");
    results.record(test_recommendations(), "Recommendations");
    results.record(test_c_api(), "C-API");
    results.record(test_pattern_learning(), "Pattern Learning");
    
    // Summary
    printf("\n");
    printf("=================================================================\n");
    printf("  Test Results: %d passed, %d failed\n", results.passed, results.failed);
    printf("=================================================================\n");
    
    return results.failed > 0 ? 1 : 0;
}
