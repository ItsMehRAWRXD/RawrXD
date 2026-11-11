// ============================================================================
// TheDualityExample.cpp - The Bottle and The Antidote Working Together
//
// Demonstrates the symbiotic relationship between:
//   - The Bottle (HotPatcher): Injects authorized patches
//   - The Antidote (AntiPatcher): Detects and removes unauthorized patches
//
// Together they provide safe, controlled runtime modification.
// ============================================================================

#include "Deep2Engine.h"
#include "HotPatcher.hpp"
#include "AntiPatcher.hpp"
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

using namespace Deep2;

// ============================================================================
// Example Functions to Patch
// ============================================================================

int originalCompute(int a, int b) {
    return a + b;  // Simple addition
}

int optimizedCompute(int a, int b) {
    // "Optimized" version (just for demo)
    return (a + b) * 2;  // Doubled result
}

int maliciousCompute(int a, int b) {
    // Model malicious patch
    return 0;  // Always returns 0
}

// ============================================================================
// Test 1: The Bottle Applies Authorized Patch
// ============================================================================

void testAuthorizedPatching() {
    printf("\n=== Test 1: Authorized Patching ===\n");
    
    // Create baseline BEFORE any patches
    void* funcAddr = reinterpret_cast<void*>(originalCompute);
    std::string baselineId = GetAntiPatcher().createBaseline(
        "compute_function",
        funcAddr,
        64,  // Size of function
        true // Critical
    );
    
    printf("Baseline created: %s\n", baselineId.c_str());
    
    // Test original
    int result1 = originalCompute(5, 3);
    printf("Original compute(5, 3) = %d\n", result1);
    
    // The Bottle applies authorized patch
    printf("\nThe Bottle applying patch...\n");
    
    // In real code, would use HotPatcher to hook the function
    // For demo, we'll simulate the patch
    printf("Patch applied by The Bottle\n");
    
    // Authorize with The Antidote
    GetAntiPatcher().authorizePatch(
        "compute_optimization",
        "HotPatcher",
        funcAddr,
        64
    );
    printf("Patch authorized with The Antidote\n");
    
    // Scan - should show authorized patch
    auto patches = GetAntiPatcher().scanRegion(baselineId);
    printf("Detected %zu patches (should be 0 since we didn't actually patch)\n", patches.size());
    
    for (const auto& patch : patches) {
        printf("  Patch: %s, Authorized: %s\n", 
               patch.id.c_str(), 
               patch.isKnownPatch ? "YES" : "NO");
    }
}

// ============================================================================
// Test 2: The Antidote Detects Unauthorized Patch
// ============================================================================

void testUnauthorizedDetection() {
    printf("\n=== Test 2: Unauthorized Patch Detection ===\n");
    
    // Set detection callback
    GetAntiPatcher().setDetectionCallback([](const DetectedPatch& patch) {
        printf("\n🚨 ALERT: Unauthorized patch detected!\n");
        printf("   ID: %s\n", patch.id.c_str());
        printf("   Address: %p\n", patch.address);
        printf("   Source: %s\n", patch.source.c_str());
        printf("   Malicious: %s\n", patch.isMalicious ? "YES" : "NO");
    });
    
    // Set aggressive policy
    ImmunizationPolicy policy;
    policy.level = ImmunizationPolicy::PREVENT;
    policy.autoRestore = true;
    policy.alarmOnUnknown = true;
    GetAntiPatcher().setPolicy(policy);
    
    printf("Policy set to PREVENT with auto-restore\n");
    
    // Start monitoring
    GetAntiPatcher().startMonitoring(500);  // Check every 500ms
    printf("Monitoring started\n");
    
    // Model time passing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // In real scenario, an unauthorized patch would be detected here
    printf("Monitoring for 1 second...\n");
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    GetAntiPatcher().stopMonitoring();
    printf("Monitoring stopped\n");
}

// ============================================================================
// Test 3: Emergency Purge
// ============================================================================

void testEmergencyPurge() {
    printf("\n=== Test 3: Emergency Purge ===\n");
    
    // Show status before
    GetAntiPatcher().printStatus();
    
    // Emergency purge
    printf("Initiating emergency purge...\n");
    int removed = PurgeAllPatches();
    printf("Removed %d patches\n", removed);
    
    // Show status after
    GetAntiPatcher().printStatus();
}

// ============================================================================
// Test 4: Integration with Deep2Engine
// ============================================================================

void testEngineIntegration() {
    printf("\n=== Test 4: Deep2Engine Integration ===\n");
    
    Deep2Engine engine;
    EngineConfig config;
    config.hiddenDim = 4096;
    config.numLayers = 32;
    config.numHeads = 32;
    config.maxSeqLen = 8192;
    
    if (!engine.initialize(config)) {
        printf("Failed to initialize engine\n");
        return;
    }
    
    // Create baselines for critical engine regions
    printf("Creating baselines for engine regions...\n");
    
    // In real code, would baseline actual function addresses
    // GetAntiPatcher().createBaseline("attention_kernel", addr, size, true);
    // GetAntiPatcher().createBaseline("gemm_kernel", addr, size, true);
    // GetAntiPatcher().createBaseline("sampling", addr, size, true);
    
    printf("Baselines created\n");
    
    // The Bottle can now safely patch
    printf("The Bottle can apply patches...\n");
    
    // Register and authorize
    // std::string patchId = engine.registerKernelPatch(...);
    // GetAntiPatcher().authorizePatch(patchId, "HotPatcher", addr, size);
    
    printf("Integration complete\n");
}

// ============================================================================
// Test 5: Forensics
// ============================================================================

void testForensics() {
    printf("\n=== Test 5: Forensic Analysis ===\n");
    
    printf("Evidence log would show:\n");
    printf("  - Timestamp of each detection\n");
    printf("  - Before/after state\n");
    printf("  - Call stack (if available)\n");
    printf("  - Patch origin analysis\n");
    
    // Export report
    // std::string report = GetAntiPatcher().exportForensicReport();
    // printf("\nForensic Report:\n%s\n", report.c_str());
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     The Duality - The Bottle and The Antidote                ║\n");
    printf("║     Safe Runtime Modification Through Balance                ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    // Initialize both systems
    printf("\nInitializing systems...\n");
    GetHotPatcher().initialize();
    GetAntiPatcher().initialize();
    
    printf("✓ The Bottle is ready\n");
    printf("✓ The Antidote is ready\n");
    
    // Run tests
    testAuthorizedPatching();
    testUnauthorizedDetection();
    testEmergencyPurge();
    testEngineIntegration();
    testForensics();
    
    // Final status
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Final Status                                             ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    GetHotPatcher().printStatus();
    GetAntiPatcher().printStatus();
    
    // Cleanup
    GetAntiPatcher().shutdown();
    GetHotPatcher().shutdown();
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     The Duality Demonstration Complete                       ║\n");
    printf("║     Balance is maintained                                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    return 0;
}

// ============================================================================
// The Philosophy of The Duality
// ============================================================================
/*

THE DUALITY:

The Bottle (HotPatcher)        The Antidote (AntiPatcher)
─────────────────────          ─────────────────────────
Injects patches                Detects patches
Enables change                 Maintains integrity
Creates modifications          Removes unauthorized
Optimizes performance          Ensures security
Embraces flexibility           Enforces stability

TOGETHER:
- The Bottle applies patches
- The Antidote verifies they're authorized
- Unauthorized patches are removed
- System remains both flexible AND secure

WORKFLOW:

1. Baseline Creation
   The Antidote records original code state
   
2. Authorized Patching
   The Bottle applies a patch
   The Antidote is notified and authorizes it
   
3. Continuous Monitoring
   The Antidote scans for unauthorized changes
   Known patches are allowed
   Unknown patches trigger alerts
   
4. Automatic Response
   If unauthorized patch detected:
   - Alert is raised
   - Patch is removed (if auto-restore enabled)
   - Evidence is logged
   
5. Emergency Response
   Emergency purge removes all patches
   System restored to baseline

SECURITY LEVELS:

Level 0 (NONE):      No protection, patches allowed
Level 1 (MONITOR):   Detect and log only
Level 2 (PREVENT):   Block unauthorized, auto-remove
Level 3 (AGGRESSIVE): Block all, alarm on any attempt

USE CASES:

Development:    Level 0 - Free patching
Production:     Level 2 - Prevent unauthorized
High Security:  Level 3 - Aggressive protection

*/
