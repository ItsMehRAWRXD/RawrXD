/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-019 Autonomous Execution Test
 * 
 * Validates the complete autonomous execution chain:
 *   1. Autonomous Task Completion
 *   2. Autonomous Failure Recovery (VAL-016 integration)
 *   3. Evidence Integrity
 *   4. Long-run Stability
 */

#include "val019_autonomous_execution.h"
#include <iostream>
#include <cassert>
#include <filesystem>

using namespace RawrXD::VAL019;
using namespace RawrXD::VAL016;
using namespace RawrXD::VAL014;
using namespace RawrXD::VAL012;

// Test 1: Simple feature addition task
bool testFeatureAddition() {
    std::cout << "\n[Test 1] Feature Addition Task\n";
    std::cout << "================================\n";
    
    AutonomousExecutor executor;
    executor.setEvidencePath("evidence/val019/test1");
    
    TaskRequest request;
    request.taskId = "VAL019-TEST-001";
    request.type = TaskType::FeatureAddition;
    request.description = "Add a simple utility function";
    request.targetFiles = "src/utils.cpp";
    request.constraints = {"No external dependencies", "Maintain C++20 compatibility"};
    
    auto result = executor.execute(request);
    
    std::cout << "Result:\n";
    std::cout << "  Success: " << (result.success ? "YES" : "NO") << "\n";
    std::cout << "  Final Phase: " << static_cast<int>(result.finalPhase) << "\n";
    std::cout << "  Duration: " << result.duration.count() << "ms\n";
    std::cout << "  Modified Files: " << result.modifiedFiles.size() << "\n";
    std::cout << "  Evidence Chain: " << result.evidence.chainId << "\n";
    std::cout << "  Combined Hash: " << result.evidence.combinedHash << "\n";
    
    return result.success && 
           result.finalPhase == ExecutionPhase::Completed &&
           !result.evidence.combinedHash.empty();
}

// Test 2: Autonomous failure recovery with VAL-016
bool testFailureRecovery() {
    std::cout << "\n[Test 2] Failure Recovery (VAL-016 Integration)\n";
    std::cout << "==============================================\n";
    
    AutonomousExecutor executor;
    executor.setEvidencePath("evidence/val019/test2");
    
    TaskRequest request;
    request.taskId = "VAL019-TEST-002";
    request.type = TaskType::FailureRecovery;
    request.description = "Recover from intentional compile failure";
    request.targetFiles = "src/broken.cpp";
    
    auto result = executor.execute(request);
    
    std::cout << "Result:\n";
    std::cout << "  Success: " << (result.success ? "YES" : "NO") << "\n";
    std::cout << "  Repair Invoked: " << (result.repairInvoked ? "YES" : "NO") << "\n";
    std::cout << "  Repair Attempts: " << result.repairAttempts << "\n";
    std::cout << "  Repair Successful: " << (result.repairSuccessful ? "YES" : "NO") << "\n";
    std::cout << "  Final Phase: " << static_cast<int>(result.finalPhase) << "\n";
    
    // For this test, we expect repair to be invoked and succeed
    return result.success && 
           result.repairInvoked &&
           result.repairSuccessful;
}

// Test 3: Evidence integrity verification
bool testEvidenceIntegrity() {
    std::cout << "\n[Test 3] Evidence Integrity\n";
    std::cout << "============================\n";
    
    AutonomousExecutor executor;
    executor.setEvidencePath("evidence/val019/test3");
    
    TaskRequest request;
    request.taskId = "VAL019-TEST-003";
    request.type = TaskType::BugFix;
    request.description = "Fix a bug with evidence verification";
    request.targetFiles = "src/buggy.cpp";
    
    auto result = executor.execute(request);
    
    // Verify evidence chain
    bool evidenceValid = executor.verifyEvidenceChain(result.evidence);
    
    std::cout << "Evidence Chain Components:\n";
    for (const auto& hash : result.evidence.hashes) {
        std::cout << "  " << hash.component << ": " << hash.hash << "\n";
    }
    std::cout << "Combined Hash: " << result.evidence.combinedHash << "\n";
    std::cout << "Evidence Valid: " << (evidenceValid ? "YES" : "NO") << "\n";
    
    return result.success && evidenceValid;
}

// Test 4: Long-run stability
bool testLongRunStability() {
    std::cout << "\n[Test 4] Long-Run Stability\n";
    std::cout << "============================\n";
    
    AutonomousExecutor executor;
    executor.setEvidencePath("evidence/val019/test4");
    
    std::vector<AutonomousResult> results;
    
    // Execute multiple tasks
    for (int i = 0; i < 5; ++i) {
        TaskRequest request;
        request.taskId = "VAL019-TEST-004-" + std::to_string(i);
        request.type = TaskType::FeatureAddition;
        request.description = "Stability test task " + std::to_string(i);
        request.targetFiles = "src/task" + std::to_string(i) + ".cpp";
        
        auto result = executor.execute(request);
        results.push_back(result);
        
        std::cout << "  Task " << i << ": " << (result.success ? "PASS" : "FAIL") 
                  << " (" << result.duration.count() << "ms)\n";
    }
    
    // Calculate stability metrics
    StabilityValidator validator;
    auto metrics = validator.calculateMetrics(results);
    
    std::cout << "\nStability Metrics:\n";
    std::cout << "  Total Tasks: " << metrics.totalTasks << "\n";
    std::cout << "  Successful: " << metrics.successfulTasks << "\n";
    std::cout << "  Failed: " << metrics.failedTasks << "\n";
    std::cout << "  Success Rate: " << (metrics.successRate * 100.0) << "%\n";
    std::cout << "  Avg Duration: " << metrics.averageDurationMs << "ms\n";
    
    bool isStable = validator.isStable(metrics, 0.80);  // 80% threshold for test
    std::cout << "  Is Stable (>80%): " << (isStable ? "YES" : "NO") << "\n";
    
    auto patterns = validator.identifyFailurePatterns(results);
    if (!patterns.empty()) {
        std::cout << "  Failure Patterns:\n";
        for (const auto& pattern : patterns) {
            std::cout << "    - " << pattern << "\n";
        }
    }
    
    return isStable;
}

// Test 5: Async execution
bool testAsyncExecution() {
    std::cout << "\n[Test 5] Async Execution\n";
    std::cout << "========================\n";
    
    AutonomousExecutor executor;
    executor.setEvidencePath("evidence/val019/test5");
    
    TaskRequest request;
    request.taskId = "VAL019-TEST-005";
    request.type = TaskType::FeatureAddition;
    request.description = "Async task execution test";
    request.targetFiles = "src/async.cpp";
    
    std::cout << "Starting async execution...\n";
    auto future = executor.executeAsync(request);
    
    std::cout << "Waiting for completion...\n";
    auto result = future.get();
    
    std::cout << "Result:\n";
    std::cout << "  Success: " << (result.success ? "YES" : "NO") << "\n";
    std::cout << "  Duration: " << result.duration.count() << "ms\n";
    
    return result.success;
}

// Main test runner
int main() {
    std::cout << "========================================\n";
    std::cout << "VAL-019 Autonomous Execution Test Suite\n";
    std::cout << "========================================\n";
    std::cout << "\nArchitecture:\n";
    std::cout << "  Agentic Engine → Planner → Tool Dispatch → Code Modification\n";
    std::cout << "  → Build → Test → Repair Loop (VAL-016) → Evidence Archive\n\n";
    
    // Create evidence directories
    std::filesystem::create_directories("evidence/val019");
    
    int passed = 0;
    int failed = 0;
    
    // Run tests
    if (testFeatureAddition()) {
        std::cout << "\n✓ Test 1 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 1 FAILED\n";
        failed++;
    }
    
    if (testFailureRecovery()) {
        std::cout << "\n✓ Test 2 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 2 FAILED\n";
        failed++;
    }
    
    if (testEvidenceIntegrity()) {
        std::cout << "\n✓ Test 3 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 3 FAILED\n";
        failed++;
    }
    
    if (testLongRunStability()) {
        std::cout << "\n✓ Test 4 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 4 FAILED\n";
        failed++;
    }
    
    if (testAsyncExecution()) {
        std::cout << "\n✓ Test 5 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 5 FAILED\n";
        failed++;
    }
    
    // Summary
    std::cout << "\n========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    std::cout << "Total:  " << (passed + failed) << "\n";
    std::cout << "Passed: " << passed << "\n";
    std::cout << "Failed: " << failed << "\n";
    std::cout << "Success Rate: " << (100 * passed / (passed + failed)) << "%\n";
    
    if (failed == 0) {
        std::cout << "\n✓ All VAL-019 tests PASSED\n";
        std::cout << "\nThe autonomous execution framework is operational.\n";
        std::cout << "VAL-016 repair pipeline successfully integrated.\n";
        std::cout << "Evidence integrity validated.\n";
        return 0;
    } else {
        std::cout << "\n✗ Some tests FAILED\n";
        return 1;
    }
}
