// ============================================================================
// TrailBrakeExample.cpp - Safety Anchor System Demo
//
// Demonstrates:
//   - Dropping anchor points before risky operations
//   - Drift detection when execution goes off-track
//   - Automatic trail back when thresholds exceeded
//   - Integration with The Bottle and The Antidote
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#include "Deep2Engine.h"
#include "TrailBrake.hpp"
#include "HotPatcher.hpp"
#include "AntiPatcher.hpp"
#include "GoalSystem.hpp"
#include <cstdio>
#include <thread>
#include <chrono>

using namespace Deep2;

// ============================================================================
// Simulated Risky Operations
// ============================================================================

bool SimulatePatchApplication(const std::string& patchId, uint64_t tokenCost) {
    printf("  [Sim] Applying patch %s (cost=%llu tokens)...\n", patchId.c_str(), tokenCost);
    
    // Report actual tokens
    GetTrailBrake().ReportActualTokens(tokenCost);
    
    // Check if we should proceed
    if (!IsSafeToProceed()) {
        printf("  [Sim] UNSAFE - TrailBrake says STOP\n");
        return false;
    }
    
    // Simulate work
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    // Check drift
    auto state = GetTrailBrake().GetState();
    if (state == BrakeState::BRAKING) {
        printf("  [Sim] WARNING: Brake applied, throttling...\n");
        return false;
    }
    
    printf("  [Sim] Patch applied successfully\n");
    return true;
}

// ============================================================================
// Test 1: Normal Operation (No Drift)
// ============================================================================

void testNormalOperation() {
    printf("\n=== Test 1: Normal Operation ===\n");
    
    // Initialize
    GetTrailBrake().Initialize();
    
    // Set expectations
    GetTrailBrake().SetExpectedTokens(1000);
    
    // Drop anchor before work
    std::string anchor = DropAnchor("before_normal_work");
    printf("Dropped anchor: %s\n", anchor.c_str());
    
    // Do work (within budget)
    for (int i = 0; i < 5; i++) {
        if (!SimulatePatchApplication("patch_" + std::to_string(i), 180)) {
            printf("Work stopped at iteration %d\n", i);
            break;
        }
    }
    
    // Verify anchor (work completed successfully)
    GetTrailBrake().VerifyAnchor(anchor);
    
    // Show status
    GetTrailBrake().PrintStatus();
}

// ============================================================================
// Test 2: Drift Detection and Warning
// ============================================================================

void testDriftWarning() {
    printf("\n=== Test 2: Drift Detection ===\n");
    
    // Reset
    GetTrailBrake().Shutdown();
    GetTrailBrake().Initialize();
    
    // Set expectations (expect 1000 tokens)
    GetTrailBrake().SetExpectedTokens(1000);
    
    // Drop anchor
    std::string anchor = DropAnchor("before_drift_work");
    
    // Do work that exceeds budget (drift)
    printf("Starting work (expecting 1000 tokens)...\n");
    
    uint64_t cumulativeTokens = 0;
    for (int i = 0; i < 10; i++) {
        uint64_t cost = 150;  // 1500 total, 1.5x expected
        cumulativeTokens += cost;
        
        printf("  Step %d: cumulative=%llu tokens\n", i, cumulativeTokens);
        GetTrailBrake().ReportActualTokens(cumulativeTokens);
        
        auto state = GetTrailBrake().GetState();
        if (state == BrakeState::WARNING) {
            printf("  *** WARNING: Drift detected! ***\n");
        }
        if (state == BrakeState::BRAKING) {
            printf("  *** BRAKING: Slowing down! ***\n");
            break;
        }
    }
    
    // Show final status
    GetTrailBrake().PrintStatus();
}

// ============================================================================
// Test 3: Emergency Trail Back
// ============================================================================

void testEmergencyTrailBack() {
    printf("\n=== Test 3: Emergency Trail Back ===\n");
    
    // Reset with aggressive config
    GetTrailBrake().Shutdown();
    TrailBrakeConfig config;
    config.warningThreshold = 1.3f;      // 30% over = warning
    config.brakeThreshold = 1.6f;        // 60% over = brake
    config.emergencyThreshold = 2.0f;   // 100% over = emergency
    config.autoRollback = true;
    GetTrailBrake().Initialize(config);
    
    // Set expectations
    GetTrailBrake().SetExpectedTokens(500);
    
    // Drop anchor
    std::string anchor = DropAnchor("before_risky_work");
    GetTrailBrake().VerifyAnchor(anchor);  // Mark as good
    
    printf("Starting work (expecting 500 tokens)...\n");
    
    // Simulate going way over budget
    uint64_t cumulativeTokens = 0;
    for (int i = 0; i < 20; i++) {
        uint64_t cost = 100;
        cumulativeTokens += cost;
        
        GetTrailBrake().ReportActualTokens(cumulativeTokens);
        
        auto state = GetTrailBrake().GetState();
        
        if (state == BrakeState::EMERGENCY) {
            printf("  *** EMERGENCY: Auto-rollback triggered! ***\n");
            printf("  Rolled back to anchor, saved %llu tokens\n", 
                   cumulativeTokens - 500);  // Approximate
            break;
        }
        
        if (state == BrakeState::TRAILING) {
            printf("  *** TRAILING: Rolling back to last anchor ***\n");
            break;
        }
    }
    
    // Show final status
    GetTrailBrake().PrintStatus();
}

// ============================================================================
// Test 4: Integration with Goals
// ============================================================================

void testGoalIntegration() {
    printf("\n=== Test 4: Integration with Goal System ===\n");
    
    // Initialize both systems
    GetGoalManager().Initialize();
    GetTrailBrake().Initialize();
    
    // Create goals
    std::string g1 = CreateGoal("Analyze threat pattern", Priority::Medium);
    std::string g2 = CreateGoal("Generate antidote", Priority::Medium);
    std::string g3 = CreateGoal("Apply patch", Priority::Medium);
    
    // Set dependencies
    GetGoalManager().AddDependency(g2, g1);
    GetGoalManager().AddDependency(g3, g2);
    
    // Auto-reprioritize (g1 should be boosted to HIGH)
    GetGoalManager().ReprioritizeBasedOnDependents();
    
    // Work on first goal with anchor
    printf("\nWorking on goal 1 (should be HIGH priority)...\n");
    std::string anchor = DropAnchor("goal_1_checkpoint");
    
    // Simulate work
    GetTrailBrake().SetExpectedTokens(1000);
    GetTrailBrake().ReportActualTokens(1200);  // Slight drift
    
    // Check if safe to continue
    if (IsSafeToProceed()) {
        printf("  Safe to proceed, completing goal 1\n");
        GetTrailBrake().VerifyAnchor(anchor);
        CompleteGoal(g1, 1200);
    } else {
        printf("  UNSAFE - trailing back\n");
        AutoTrailIfNeeded();
    }
    
    // Show status
    GetGoalManager().PrintStatus();
    GetTrailBrake().PrintStatus();
}

// ============================================================================
// Test 5: Progressive Braking
// ============================================================================

void testProgressiveBraking() {
    printf("\n=== Test 5: Progressive Braking ===\n");
    
    // Reset
    GetTrailBrake().Shutdown();
    GetTrailBrake().Initialize();
    
    // Set expectations
    GetTrailBrake().SetExpectedTokens(1000);
    
    printf("Testing progressive brake intensity...\n");
    
    // Gradually increase drift and watch brake intensity
    for (uint64_t tokens = 1000; tokens <= 3000; tokens += 200) {
        GetTrailBrake().ReportActualTokens(tokens);
        
        float drift = static_cast<float>(tokens) / 1000.0f;
        float intensity = GetTrailBrake().GetBrakeIntensity();
        auto state = GetTrailBrake().GetState();
        
        const char* stateStr = "FREE";
        switch (state) {
            case BrakeState::WARNING: stateStr = "WARNING"; break;
            case BrakeState::BRAKING: stateStr = "BRAKING"; break;
            case BrakeState::EMERGENCY: stateStr = "EMERGENCY"; break;
            default: break;
        }
        
        printf("  Drift=%.1fx, State=%s, Brake=%.0f%%\n", 
               drift, stateStr, intensity * 100);
        
        if (state == BrakeState::EMERGENCY) break;
    }
    
    // Show throttled budget
    uint64_t requested = 1000;
    uint64_t throttled = GetTrailBrake().GetThrottledBudget(requested);
    printf("\nRequested budget: %llu tokens\n", requested);
    printf("Throttled budget: %llu tokens (%.0f%% reduction)\n", 
           throttled, (1.0f - static_cast<float>(throttled)/requested) * 100);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     TrailBrake Demo - Safety Anchor System                   ║\n");
    printf("║     Reverse Engineering: When to Trail Back                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    // Run tests
    testNormalOperation();
    testDriftWarning();
    testEmergencyTrailBack();
    testGoalIntegration();
    testProgressiveBraking();
    
    // Final summary
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     TrailBrake Demo Complete                                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Key Concepts:                                                ║\n");
    printf("║   • Drop anchor before risky operations                      ║\n");
    printf("║   • Monitor drift (actual vs expected tokens)                ║\n");
    printf("║   • Progressive braking before emergency stop                ║\n");
    printf("║   • Automatic trail back to last verified anchor             ║\n");
    printf("║   • Integration with GoalSystem for priority management      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    // Cleanup
    GetTrailBrake().Shutdown();
    GetGoalManager().Shutdown();
    
    return 0;
}

// ============================================================================
// Summary
// ============================================================================
/*

TRAILBRAKE - SAFETY ANCHOR SYSTEM:

1. Drop Anchor
   - Call before risky operations
   - Captures known good state
   - Can be verified after success

2. Drift Detection
   - Compare actual vs expected tokens
   - Warning at 1.5x expected
   - Braking at 2.0x expected
   - Emergency at 3.0x expected

3. Progressive Braking
   - Warning: 50% brake
   - Braking: full brake intensity
   - Emergency: auto-rollback

4. Trail Back
   - Rolls back to last verified anchor
   - Applies antidote (purges patches)
   - Resets token count
   - Saves wasted tokens

5. Integration
   - Works with GoalSystem (priority management)
   - Works with HotPatcher (patch tracking)
   - Works with AntiPatcher (rollback)
   - Event callbacks for monitoring

USAGE:

// Before risky work
std::string anchor = DropAnchor("before_xor_patch");
GetTrailBrake().SetExpectedTokens(1000);

// Do work
apply_patch();
GetTrailBrake().ReportActualTokens(actual_cost);

// Check state
if (GetTrailBrake().GetState() == BrakeState::EMERGENCY) {
    // Auto-rollback happened
} else if (GetTrailBrake().GetState() == BrakeState::BRAKING) {
    // Slow down, reduce token budget
    uint64_t budget = GetTrailBrake().GetThrottledBudget(1000);
}

// Success - verify anchor
GetTrailBrake().VerifyAnchor(anchor);

*/
