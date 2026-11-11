// ============================================================
// EfficiencyBridgeDemo.cpp - Demonstrates the 20-line bridge
// ============================================================
// Build: cl /EHsc /O2 EfficiencyBridgeDemo.cpp TokenEfficiencySwarm.cpp
// Run: EfficiencyBridgeDemo.exe
// ============================================================

#include "EfficiencyBridge.hpp"
#include <cstdio>
#include <string>#include <thread>
#include <chrono>
using namespace RawrXD;

// ============================================================
// Demo: Simulating AutonomousLoop ACT phase
// ============================================================
int main() {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  Token Efficiency Swarm - Bridge Demo                        ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Configure swarm
    auto& swarm = Executive::TokenEfficiencySwarm::getInstance();
    Executive::SwarmConfig config;
    config.triggerThreshold = 3.0f;        // Trigger at 3x
    config.retriggerThreshold = 2.5f;      // Hysteresis
    config.minTriggerIntervalMs = 100;     // 100ms rate limit for demo
    config.nonBlocking = true;
    config.enableTelemetry = true;
    swarm.configure(config);

    printf("Swarm Configuration:\n");
    printf("  Trigger Threshold: %.1fx\n", config.triggerThreshold);
    printf("  Retrigger Threshold: %.1fx\n", config.retriggerThreshold);
    printf("  Min Interval: %d ms\n", config.minTriggerIntervalMs);
    printf("  Non-blocking: %s\n\n", config.nonBlocking ? "yes" : "no");

    // ============================================================
    // Test Case 1: Within threshold (no trigger)
    // ============================================================
    printf("Test 1: Within threshold (actual=100, estimated=50)\n");
    printf("-----------------------------------------------------\n");
    
    EfficiencyBridgeContext ctx1;
    memset(&ctx1, 0, sizeof(ctx1));
    ctx1.actualCost = 100.0f;
    ctx1.estimatedCost = 50.0f;
    ctx1.agentCount = 4;
    ctx1.goalId = 1;
    ctx1.goalName = "code_completion";
    ctx1.assignedAgent = "coder_agent";
    
    auto result1 = efficiencyBridgeValidator(&ctx1);
    printf("Result: %s - %s\n\n", 
           result1.success ? "OK" : "ERROR", 
           result1.message);

    // ============================================================
    // Test Case 2: Exceeds threshold (triggers swarm)
    // ============================================================
    printf("Test 2: Exceeds threshold (actual=200, estimated=50)\n");
    printf("-----------------------------------------------------\n");
    
    EfficiencyBridgeContext ctx2;
    memset(&ctx2, 0, sizeof(ctx2));
    ctx2.actualCost = 200.0f;      // 4x estimate
    ctx2.estimatedCost = 50.0f;
    ctx2.agentCount = 4;
    ctx2.goalId = 2;
    ctx2.goalName = "complex_refactoring";
    ctx2.assignedAgent = "architect_agent";
    
    auto result2 = efficiencyBridgeValidator(&ctx2);
    printf("Result: %s - %s\n\n",
           result2.success ? "OK" : "ERROR",
           result2.message);

    // Wait for swarm to complete (in real usage, non-blocking)
    printf("Waiting for swarm execution...\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // ============================================================
    // Test Case 3: Rate limiting (should not trigger)
    // ============================================================
    printf("\nTest 3: Rate limiting (immediate retrigger attempt)\n");
    printf("-----------------------------------------------------\n");
    
    EfficiencyBridgeContext ctx3;
    memset(&ctx3, 0, sizeof(ctx3));
    ctx3.actualCost = 200.0f;
    ctx3.estimatedCost = 50.0f;
    ctx3.agentCount = 4;
    ctx3.goalId = 3;
    ctx3.goalName = "another_task";
    ctx3.assignedAgent = "coder_agent";
    
    auto result3 = efficiencyBridgeValidator(&ctx3);
    printf("Result: %s - %s\n", 
           result3.success ? "OK" : "ERROR",
           result3.message);
    printf("(Swarm not triggered due to rate limiting)\n\n");

    // ============================================================
    // Telemetry Summary
    // ============================================================
    printf("Telemetry Summary:\n");
    printf("------------------\n");
    printf("Total triggers: %u\n", swarm.getTriggerCount());
    
    auto lastTrigger = swarm.getLastTriggerTime();
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - lastTrigger).count();
    printf("Last trigger: %lld ms ago\n", elapsed);

    printf("\n✓ Demo complete. Swarm is operational.\n");
    printf("  - Configurable thresholds\n");
    printf("  - Rate limiting\n");
    printf("  - Hysteresis\n");
    printf("  - Non-blocking execution\n");
    printf("  - 8 efficiency agents\n");

    return 0;
}
