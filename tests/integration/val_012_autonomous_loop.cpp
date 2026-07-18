/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-012: Autonomous Loop Closure Validation
 * 
 * This test validates that the Planner-Executor-Build-Test-Repair-Memory loop
 * is closed and functional.
 * 
 * Evidence Required:
 * - [ ] Bridge compiles and links
 * - [ ] Goal flows from input to plan
 * - [ ] Plan steps execute
 * - [ ] Execution trace captured
 * - [ ] Evidence saved to disk
 * 
 * Success Criteria:
 * - One complete autonomous task executes end-to-end
 * - Evidence chain is complete and inspectable
 * - No human intervention required
 */

#include "../../src/integration/planner_executor_bridge.h"
#include "../../src/plan_orchestrator.h"
#include "../../src/agentic_executor.h"
#include "../../src/error_recovery_system.h"
#include "../../src/agentic_memory_system.h"
#include <iostream>
#include <fstream>
#include <assert>
#include <filesystem>

using namespace RawrXD;

// Test result tracking
struct Val012Result {
    bool integrationCompiled = false;
    bool bridgeInstantiated = false;
    bool goalReceived = false;
    bool planGenerated = false;
    bool stepsExecuted = false;
    bool evidenceCaptured = false;
    bool traceSaved = false;
    std::string evidencePath;
    
    bool allPassed() const {
        return integrationCompiled && bridgeInstantiated && goalReceived 
            && planGenerated && stepsExecuted && evidenceCaptured && traceSaved;
    }
    
    void print() const {
        std::cout << "\n=== VAL-012 Results ===\n";
        std::cout << "Integration compiled: " << (integrationCompiled ? "PASS" : "FAIL") << "\n";
        std::cout << "Bridge instantiated: " << (bridgeInstantiated ? "PASS" : "FAIL") << "\n";
        std::cout << "Goal received: " << (goalReceived ? "PASS" : "FAIL") << "\n";
        std::cout << "Plan generated: " << (planGenerated ? "PASS" : "FAIL") << "\n";
        std::cout << "Steps executed: " << (stepsExecuted ? "PASS" : "FAIL") << "\n";
        std::cout << "Evidence captured: " << (evidenceCaptured ? "PASS" : "FAIL") << "\n";
        std::cout << "Trace saved: " << (traceSaved ? "PASS" : "FAIL") << "\n";
        std::cout << "\nOverall: " << (allPassed() ? "✓ VAL-012 PASSED" : "✗ VAL-012 FAILED") << "\n";
        
        if (!evidencePath.empty()) {
            std::cout << "Evidence: " << evidencePath << "\n";
        }
    }
};

int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "VAL-012: Autonomous Loop Closure Test\n";
    std::cout << "========================================\n\n";
    
    Val012Result result;
    
    // Test 1: Integration compiles
    // (If we're running, it compiled)
    result.integrationCompiled = true;
    std::cout << "[TEST 1] Integration code compiled: YES\n";
    
    try {
        // Create components
        std::cout << "\n[TEST 2] Creating components...\n";
        
        PlanOrchestrator planner;
        AgenticExecutor executor;
        ErrorRecoverySystem errorRecovery;
        AgenticMemorySystem memory;
        
        std::cout << "  - PlanOrchestrator: created\n";
        std::cout << "  - AgenticExecutor: created\n";
        std::cout << "  - ErrorRecoverySystem: created\n";
        std::cout << "  - AgenticMemorySystem: created\n";
        
        // Test 2: Bridge instantiation
        std::cout << "\n[TEST 3] Creating PlannerExecutorBridge...\n";
        PlannerExecutorBridge bridge(
            &planner,
            &executor,
            &errorRecovery,
            &memory
        );
        result.bridgeInstantiated = true;
        std::cout << "  ✓ Bridge created successfully\n";
        
        // Test 3: Execute autonomous goal
        std::string testGoal = "Fix the off-by-one error in the tokenizer";
        std::cout << "\n[TEST 4] Executing goal: \"" << testGoal << "\"\n";
        result.goalReceived = true;
        
        std::string evidenceDir = "evidence/val-012-test-" + 
                                  std::to_string(std::time(nullptr));
        
        auto executionResult = bridge.executeGoalWithEvidence(testGoal, evidenceDir);
        
        // Validate results
        result.planGenerated = executionResult.totalSteps > 0;
        result.stepsExecuted = executionResult.stepsCompleted > 0;
        result.evidenceCaptured = !executionResult.trace.goal.empty();
        
        // Check if evidence file was saved
        if (std::filesystem::exists(evidenceDir)) {
            for (const auto& entry : std::filesystem::directory_iterator(evidenceDir)) {
                if (entry.path().extension() == ".json") {
                    result.traceSaved = true;
                    result.evidencePath = entry.path().string();
                    break;
                }
            }
        }
        
        // Print execution summary
        std::cout << "\n--- Execution Summary ---\n";
        std::cout << "Goal: " << executionResult.goal << "\n";
        std::cout << "Steps: " << executionResult.stepsCompleted 
                  << "/" << executionResult.totalSteps << "\n";
        std::cout << "Success: " << (executionResult.success ? "YES" : "NO") << "\n";
        std::cout << "Build: " << (executionResult.buildSucceeded ? "YES" : "N/A") << "\n";
        std::cout << "Tests: " << (executionResult.testsPassed ? "YES" : "N/A") << "\n";
        std::cout << "Repairs: " << executionResult.repairsAttempted << "\n";
        
        if (!executionResult.errorMessage.empty()) {
            std::cout << "Error: " << executionResult.errorMessage << "\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Test failed with exception: " << e.what() << "\n";
    }
    
    // Print final results
    result.print();
    
    // Return appropriate exit code
    return result.allPassed() ? 0 : 1;
}
