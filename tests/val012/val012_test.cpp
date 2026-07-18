/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-012 Test: Autonomous Loop Closure
 * 
 * This test validates that the autonomous execution loop closes end-to-end.
 * 
 * Evidence Levels:
 * - [D] Source exists (this file)
 * - [C] Compiles and links
 * - [B] Test executes with mock goal
 * - [A] Real task produces completion.json
 * 
 * Success Criteria:
 * 1. Controller instantiates
 * 2. Goal flows through system
 * 3. Plan is generated
 * 4. Changes are applied
 * 5. Build is triggered
 * 6. Tests are run
 * 7. Evidence is saved
 * 8. Completion.json is valid
 */

#include "../../src/val012/val012_controller.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>

using namespace RawrXD::VAL012;

// Test result tracking
struct TestResult {
    bool controllerCreated = false;
    bool goalReceived = false;
    bool planGenerated = false;
    bool changesApplied = false;
    bool buildTriggered = false;
    bool testsRun = false;
    bool evidenceSaved = false;
    bool completionValid = false;
    std::string evidencePath;
    
    bool allPassed() const {
        return controllerCreated && goalReceived && planGenerated &&
               changesApplied && buildTriggered && testsRun &&
               evidenceSaved && completionValid;
    }
    
    void print() const {
        std::cout << "\n=== VAL-012 Test Results ===\n";
        std::cout << "Controller created: " << (controllerCreated ? "PASS" : "FAIL") << "\n";
        std::cout << "Goal received: " << (goalReceived ? "PASS" : "FAIL") << "\n";
        std::cout << "Plan generated: " << (planGenerated ? "PASS" : "FAIL") << "\n";
        std::cout << "Changes applied: " << (changesApplied ? "PASS" : "FAIL") << "\n";
        std::cout << "Build triggered: " << (buildTriggered ? "PASS" : "FAIL") << "\n";
        std::cout << "Tests run: " << (testsRun ? "PASS" : "FAIL") << "\n";
        std::cout << "Evidence saved: " << (evidenceSaved ? "PASS" : "FAIL") << "\n";
        std::cout << "Completion valid: " << (completionValid ? "PASS" : "FAIL") << "\n";
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
    
    TestResult result;
    
    // Test 1: Create controller
    std::cout << "[TEST 1] Creating Val012Controller...\n";
    Val012Controller controller;
    result.controllerCreated = true;
    std::cout << "  ✓ Controller created\n";
    
    // Test 2: Execute goal
    std::cout << "\n[TEST 2] Executing goal...\n";
    std::string testGoal = "Add --version command to CLI";
    std::string evidenceDir = "evidence/val-012-test-" + 
                               std::to_string(std::time(nullptr));
    
    std::cout << "  Goal: \"" << testGoal << "\"\n";
    std::cout << "  Evidence dir: " << evidenceDir << "\n";
    
    auto completion = controller.execute(testGoal, evidenceDir);
    
    // Validate results
    result.goalReceived = !completion.goalId.empty();
    result.planGenerated = completion.totalSteps > 0;
    result.changesApplied = !completion.filesModified.empty();
    result.buildTriggered = completion.buildSucceeded;
    result.testsRun = completion.testsPassed > 0;
    result.evidenceSaved = std::filesystem::exists(evidenceDir);
    result.evidencePath = evidenceDir;
    
    // Check completion.json
    if (result.evidenceSaved) {
        std::string completionPath = evidenceDir + "/completion.json";
        if (std::filesystem::exists(completionPath)) {
            std::ifstream ifs(completionPath);
            if (ifs) {
                // Check completion.json content manually
                std::string content((std::istreambuf_iterator<char>(ifs)),
                                    std::istreambuf_iterator<char>());
                result.completionValid = content.find("\"success\"") != std::string::npos && 
                                        content.find("\"goal_id\"") != std::string::npos &&
                                        content.find("\"summary\"") != std::string::npos;
            }
        }
    }
    
    // Print execution summary
    std::cout << "\n--- Execution Summary ---\n";
    std::cout << "Success: " << (completion.success ? "YES" : "NO") << "\n";
    std::cout << "Goal ID: " << completion.goalId << "\n";
    std::cout << "Steps: " << completion.stepsCompleted << "/" << completion.totalSteps << "\n";
    std::cout << "Files modified: " << completion.filesModified.size() << "\n";
    std::cout << "Build: " << (completion.buildSucceeded ? "PASSED" : "FAILED") << "\n";
    std::cout << "Tests: " << completion.testsPassed << "/" 
              << (completion.testsPassed + completion.testsFailed) << " passed\n";
    std::cout << "Duration: " << completion.totalDuration.count() << "ms\n";
    std::cout << "Summary: " << completion.summary << "\n";
    
    // Print events
    std::cout << "\n--- State Transitions ---\n";
    for (const auto& event : controller.getEvents()) {
        std::cout << "  " << event.eventType << ": " 
                  << stateToString(event.state) << "\n";
    }
    
    // Print final results
    result.print();
    
    // Return appropriate exit code
    return result.allPassed() ? 0 : 1;
}
