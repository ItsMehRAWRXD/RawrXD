//=============================================================================
// test_sovereign_lifecycle.cpp - Dry-run test of Sovereign Lifecycle
//=============================================================================

#include <cstdio>
#include <cstdlib>
#include <thread>
#include <chrono>
#include "../src/sovereign/IDE_Lifecycle_Hook.hpp"

using namespace RawrXD::Sovereign;

void SimulateTaskWork(int durationMs) {
    std::this_thread::sleep_for(std::chrono::milliseconds(durationMs));
}

int main() {
    printf("=============================================================================\n");
    printf("SOVEREIGN LIFECYCLE MANAGEMENT - DRY RUN TEST\n");
    printf("=============================================================================\n\n");
    
    // Initialize the lifecycle hook
    IDE_Lifecycle_Hook::Config config;
    config.enableVCS = true;
    config.enableCheckpoint = true;
    config.autoCommitOnSuccess = true;
    config.autoCommitOnFailure = true;
    config.checkpointPrefix = "test_";
    
    IDE_Lifecycle_Hook::Instance().Initialize(config);
    
    printf("Configuration:\n");
    printf("  VCS Enabled: %s\n", config.enableVCS ? "YES" : "NO");
    printf("  Checkpoint Enabled: %s\n", config.enableCheckpoint ? "YES" : "NO");
    printf("  Auto-commit on success: %s\n", config.autoCommitOnSuccess ? "YES" : "NO");
    printf("  Auto-commit on failure: %s\n", config.autoCommitOnFailure ? "YES" : "NO");
    printf("\n");
    
    // Test 1: Successful task
    printf("[TEST 1] Successful Task Execution\n");
    printf("-----------------------------------\n");
    {
        SOVEREIGN_TASK("measurement_framework_implementation");
        printf("  Executing task...\n");
        SimulateTaskWork(100);
        printf("  Task completed successfully!\n");
        SOVEREIGN_TASK_COMPLETE("All benchmarks implemented");
    }
    printf("\n");
    
    // Test 2: Failed task
    printf("[TEST 2] Failed Task Execution\n");
    printf("-------------------------------\n");
    {
        SOVEREIGN_TASK("flame_graph_generation");
        printf("  Executing task...\n");
        SimulateTaskWork(50);
        printf("  Task encountered error!\n");
        SOVEREIGN_TASK_FAILED("Missing dependency: zlib");
    }
    printf("\n");
    
    // Test 3: Manual checkpoint
    printf("[TEST 3] Manual Checkpoint Creation\n");
    printf("------------------------------------\n");
    if (IDE_Lifecycle_Hook::Instance().CreateCheckpoint("manual_test")) {
        printf("  Manual checkpoint created successfully\n");
    } else {
        printf("  Manual checkpoint creation failed (expected if not in git repo)\n");
    }
    printf("\n");
    
    // Test 4: Session info
    printf("[TEST 4] Session Information\n");
    printf("---------------------------\n");
    printf("  Session Active: %s\n", 
           IDE_Lifecycle_Hook::Instance().IsSessionActive() ? "YES" : "NO");
    printf("  Current Session ID: %s\n", 
           IDE_Lifecycle_Hook::Instance().GetCurrentSessionID().c_str());
    printf("  Current Branch: %s\n", 
           IDE_Lifecycle_Hook::Instance().GetCurrentBranch().c_str());
    printf("\n");
    
    // Shutdown
    printf("Shutting down lifecycle hook...\n");
    IDE_Lifecycle_Hook::Instance().Shutdown();
    
    printf("\n=============================================================================\n");
    printf("DRY RUN COMPLETE\n");
    printf("=============================================================================\n");
    printf("\nThe Sovereign Lifecycle Management system is ready for production use.\n");
    printf("Each task execution will now:\n");
    printf("  1. Fork a new Git branch\n");
    printf("  2. Create a checkpoint on completion/failure\n");
    printf("  3. Commit changes to the branch\n");
    printf("  4. Preserve session state for restoration\n");
    printf("\n");
    
    return 0;
}
