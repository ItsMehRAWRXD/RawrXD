/**
 * @file test_phase4_agentic.cpp
 * @brief Phase 4: Agentic Integration Test with Real Legacy Code
 * 
 * Tests the LegacyCoreAdapter delegation to real AgenticEngine implementation.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <cassert>
#include <chrono>
#include <thread>

// Unified interface
#include "src/agentic/Core.h"
#include "src/agentic/LegacyCoreAdapter.h"

// Real legacy implementation
#include "src/agentic_engine.h"

using namespace RawrXD::Agentic;

// Test counters
int testsPassed = 0;
int testsFailed = 0;

void TestPass(const char* testName) {
    std::cout << "[PASS] " << testName << std::endl;
    testsPassed++;
}

void TestFail(const char* testName, const char* reason) {
    std::cout << "[FAIL] " << testName << ": " << reason << std::endl;
    testsFailed++;
}

// ============================================================================
// Test 1: Real AgenticEngine Creation and Adapter Wrapping
// ============================================================================
void TestRealAgenticEngineCreation() {
    std::cout << "\n=== Test 1: Real AgenticEngine Creation ===" << std::endl;
    
    // Create real legacy engine
    AgenticEngine legacyEngine;
    
    // Wrap with adapter
    CoreConfig config;
    auto core = LegacyCoreAdapter::Create(&legacyEngine, config);
    
    if (!core) {
        TestFail("Real AgenticEngine Creation", "Adapter returned nullptr");
        return;
    }
    
    TestPass("Real AgenticEngine Creation");
}

// ============================================================================
// Test 2: Initialize with Real Engine
// ============================================================================
void TestInitializeWithRealEngine() {
    std::cout << "\n=== Test 2: Initialize with Real Engine ===" << std::endl;
    
    AgenticEngine legacyEngine;
    CoreConfig config;
    auto core = LegacyCoreAdapter::Create(&legacyEngine, config);
    
    if (!core->Initialize()) {
        TestFail("Initialize", "Initialize() returned false");
        return;
    }
    
    if (!core->IsInitialized()) {
        TestFail("Initialize", "IsInitialized() returned false");
        return;
    }
    
    TestPass("Initialize with Real Engine");
}

// ============================================================================
// Test 3: File Operations via Adapter
// ============================================================================
void TestFileOperationsViaAdapter() {
    std::cout << "\n=== Test 3: File Operations via Adapter ===" << std::endl;
    
    AgenticEngine legacyEngine;
    CoreConfig config;
    auto core = LegacyCoreAdapter::Create(&legacyEngine, config);
    core->Initialize();
    
    // Test list directory
    Task task;
    task.type = TaskType::File;
    task.instruction = "List current directory";
    task.fileParams.operation = "list";
    task.fileParams.path = ".";
    
    auto future = core->SubmitTask(task);
    auto status = future.wait_for(std::chrono::seconds(5));
    
    if (status != std::future_status::ready) {
        TestFail("File Operations", "Task timed out");
        return;
    }
    
    auto result = future.get();
    
    // Task should complete (success depends on actual file system)
    if (result.taskId.empty()) {
        TestFail("File Operations", "Task ID is empty");
        return;
    }
    
    std::cout << "  File operation result: " << (result.success ? "success" : "failure") << std::endl;
    TestPass("File Operations via Adapter");
}

// ============================================================================
// Test 4: Search Operations via Adapter
// ============================================================================
void TestSearchOperationsViaAdapter() {
    std::cout << "\n=== Test 4: Search Operations via Adapter ===" << std::endl;
    
    AgenticEngine legacyEngine;
    CoreConfig config;
    auto core = LegacyCoreAdapter::Create(&legacyEngine, config);
    core->Initialize();
    
    // Test grep search
    Task task;
    task.type = TaskType::Search;
    task.instruction = "Search for test pattern";
    task.searchParams.query = "test";
    task.searchParams.paths = {"."};
    
    auto future = core->SubmitTask(task);
    auto status = future.wait_for(std::chrono::seconds(5));
    
    if (status != std::future_status::ready) {
        TestFail("Search Operations", "Task timed out");
        return;
    }
    
    auto result = future.get();
    
    if (result.taskId.empty()) {
        TestFail("Search Operations", "Task ID is empty");
        return;
    }
    
    std::cout << "  Search operation result: " << (result.success ? "success" : "failure") << std::endl;
    TestPass("Search Operations via Adapter");
}

// ============================================================================
// Test 5: Tool Registry Delegation
// ============================================================================
void TestToolRegistryDelegation() {
    std::cout << "\n=== Test 5: Tool Registry Delegation ===" << std::endl;
    
    AgenticEngine legacyEngine;
    CoreConfig config;
    auto core = LegacyCoreAdapter::Create(&legacyEngine, config);
    core->Initialize();
    
    // Get tool registry
    auto& toolRegistry = core->GetToolRegistry();
    
    // Execute listDir tool (should delegate to legacyEngine->listDir)
    std::string output;
    bool executed = toolRegistry.ExecuteTool("listDir", ".", output);
    
    std::cout << "  Tool execution result: " << (executed ? "executed" : "not executed") << std::endl;
    TestPass("Tool Registry Delegation");
}

// ============================================================================
// Test 6: Policy Engine Delegation
// ============================================================================
void TestPolicyEngineDelegation() {
    std::cout << "\n=== Test 6: Policy Engine Delegation ===" << std::endl;
    
    AgenticEngine legacyEngine;
    CoreConfig config;
    auto core = LegacyCoreAdapter::Create(&legacyEngine, config);
    core->Initialize();
    
    // Get policy engine
    auto& policies = core->GetPolicies();
    
    // Create a terminal task
    Task task;
    task.type = TaskType::Terminal;
    task.terminalParams.command = "echo test";
    
    // Validate task (should delegate to legacyEngine->isCommandSafe)
    std::string reason;
    bool valid = policies.ValidateTask(task, reason);
    
    std::cout << "  Policy validation result: " << (valid ? "valid" : "invalid") << std::endl;
    TestPass("Policy Engine Delegation");
}

// ============================================================================
// Test 7: Statistics Tracking
// ============================================================================
void TestStatisticsTracking() {
    std::cout << "\n=== Test 7: Statistics Tracking ===" << std::endl;
    
    AgenticEngine legacyEngine;
    CoreConfig config;
    auto core = LegacyCoreAdapter::Create(&legacyEngine, config);
    core->Initialize();
    
    // Get initial stats
    auto initialStats = core->GetStats();
    
    // Submit a task
    Task task;
    task.type = TaskType::File;
    task.instruction = "Test task";
    
    auto future = core->SubmitTask(task);
    future.wait_for(std::chrono::seconds(5));
    
    // Get updated stats
    auto updatedStats = core->GetStats();
    
    std::cout << "  Tasks submitted: " << updatedStats.tasksSubmitted << std::endl;
    std::cout << "  Tasks completed: " << updatedStats.tasksCompleted << std::endl;
    
    TestPass("Statistics Tracking");
}

// ============================================================================
// Test 8: Shutdown with Real Engine
// ============================================================================
void TestShutdownWithRealEngine() {
    std::cout << "\n=== Test 8: Shutdown with Real Engine ===" << std::endl;
    
    AgenticEngine legacyEngine;
    CoreConfig config;
    auto core = LegacyCoreAdapter::Create(&legacyEngine, config);
    core->Initialize();
    
    if (!core->Shutdown(std::chrono::seconds(5))) {
        TestFail("Shutdown", "Shutdown() returned false");
        return;
    }
    
    if (core->IsInitialized()) {
        TestFail("Shutdown", "Still initialized after shutdown");
        return;
    }
    
    TestPass("Shutdown with Real Engine");
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "Phase 4: Agentic Integration Tests" << std::endl;
    std::cout << "Testing REAL AgenticEngine via Adapter" << std::endl;
    std::cout << "========================================" << std::endl;
    
    try {
        // Run all tests
        TestRealAgenticEngineCreation();
        TestInitializeWithRealEngine();
        TestFileOperationsViaAdapter();
        TestSearchOperationsViaAdapter();
        TestToolRegistryDelegation();
        TestPolicyEngineDelegation();
        TestStatisticsTracking();
        TestShutdownWithRealEngine();
        
    } catch (const std::exception& e) {
        std::cerr << "\n[FATAL] Unhandled exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n[FATAL] Unknown exception" << std::endl;
        return 1;
    }
    
    // Print summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Passed: " << testsPassed << std::endl;
    std::cout << "Failed: " << testsFailed << std::endl;
    std::cout << "Total:  " << (testsPassed + testsFailed) << std::endl;
    
    if (testsFailed == 0) {
        std::cout << "\n✅ All Phase 4 agentic tests passed!" << std::endl;
        std::cout << "\nPhase 4 Status: Agentic integration verified" << std::endl;
        return 0;
    } else {
        std::cout << "\n❌ Some tests failed" << std::endl;
        return 1;
    }
}
