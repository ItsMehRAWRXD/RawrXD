/**
 * @file smoke_test.cpp
 * @brief Phase 1: Runtime Smoke Test - Core Architecture Validation
 * 
 * Validates the Core architecture actually runs, not just compiles.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <memory>
#include <chrono>
#include <thread>
#include "../src/agentic/Core.h"
#include "../src/agentic/ErrorHandling.h"

using namespace RawrXD::Agentic;

// Simple test framework
#define TEST(name) std::cout << "\n[TEST] " << #name << "... " << std::flush
#define PASS() do { std::cout << "✓ PASS" << std::endl; passed++; } while(0)
#define FAIL(msg) do { \
    std::cout << "✗ FAIL: " << msg << std::endl; \
    failed++; \
    return false; \
} while(0)

int passed = 0;
int failed = 0;

// ============================================================================
// Smoke Test 1: Core Lifecycle
// ============================================================================

bool Test_CoreLifecycle() {
    TEST(CoreLifecycle);
    
    // Create
    auto core = Core::Create();
    if (!core) FAIL("Failed to create Core");
    
    // Initialize
    if (!core->Initialize()) FAIL("Failed to initialize Core");
    if (!core->IsInitialized()) FAIL("Core reports not initialized");
    
    // Shutdown
    if (!core->Shutdown(std::chrono::seconds(5))) FAIL("Failed to shutdown Core");
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 2: Task Execution
// ============================================================================

bool Test_TaskExecution() {
    TEST(TaskExecution);
    
    auto core = Core::Create();
    if (!core->Initialize()) FAIL("Init failed");
    
    // Create and submit task
    Task task;
    task.type = TaskType::File;
    task.instruction = "List directory";
    task.fileParams.operation = "list";
    task.fileParams.path = ".";
    
    auto future = core->SubmitTask(task);
    
    // Wait for result (with timeout)
    auto status = future.wait_for(std::chrono::seconds(10));
    if (status != std::future_status::ready) {
        FAIL("Task timed out");
    }
    
    auto result = future.get();
    if (result.taskId.empty()) FAIL("Task has no ID");
    if (result.durationMs < 0) FAIL("Invalid duration");
    
    core->Shutdown(std::chrono::seconds(5));
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 3: Subsystem Access
// ============================================================================

bool Test_SubsystemAccess() {
    TEST(SubsystemAccess);
    
    auto core = Core::Create();
    if (!core->Initialize()) FAIL("Init failed");
    
    try {
        auto& scheduler = core->GetScheduler();
        (void)scheduler;
        
        auto& registry = core->GetToolRegistry();
        (void)registry;
        
        auto& history = core->GetHistory();
        (void)history;
        
        auto& policies = core->GetPolicies();
        (void)policies;
        
        auto& manager = core->GetSubAgentManager();
        (void)manager;
    } catch (const std::exception& e) {
        FAIL(std::string("Exception: ") + e.what());
    }
    
    core->Shutdown(std::chrono::seconds(5));
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 4: Error Handling
// ============================================================================

bool Test_ErrorHandling() {
    TEST(ErrorHandling);
    
    // Test Result<T> success
    auto successResult = Result<int>::Ok(42);
    if (!successResult.IsOk()) FAIL("Should be OK");
    if (successResult.Value() != 42) FAIL("Value should be 42");
    
    // Test Result<T> error
    auto errorResult = Result<int>::Err(ErrorCode::InvalidArgument, "Test error");
    if (!errorResult.IsErr()) FAIL("Should have error");
    if (errorResult.Code() != ErrorCode::InvalidArgument) {
        FAIL("Error code mismatch");
    }
    
    // Test error message
    if (errorResult.Message() != "Test error") FAIL("Error message mismatch");
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 5: Statistics
// ============================================================================

bool Test_Statistics() {
    TEST(Statistics);
    
    auto core = Core::Create();
    if (!core->Initialize()) FAIL("Init failed");
    
    auto stats = core->GetStats();
    if (stats.tasksSubmitted != 0) FAIL("Initial submitted should be 0");
    if (stats.tasksCompleted != 0) FAIL("Initial completed should be 0");
    
    // Submit task
    Task task;
    task.type = TaskType::File;
    task.fileParams.operation = "list";
    task.fileParams.path = ".";
    
    auto future = core->SubmitTask(task);
    auto result = future.get();
    (void)result;
    
    auto updatedStats = core->GetStats();
    if (updatedStats.tasksSubmitted < 1) FAIL("Submitted should increment");
    
    core->Shutdown(std::chrono::seconds(5));
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 6: Convenience Methods
// ============================================================================

bool Test_ConvenienceMethods() {
    TEST(ConvenienceMethods);
    
    auto core = Core::Create();
    if (!core->Initialize()) FAIL("Init failed");
    
    // Test ReadFile (may fail but shouldn't crash)
    auto content = core->ReadFile("nonexistent_test_file.txt");
    (void)content; // Expected to be empty
    
    // Test SearchCodebase
    auto results = core->SearchCodebase("test query");
    (void)results; // May return placeholder
    
    core->Shutdown(std::chrono::seconds(5));
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 7: Memory Safety
// ============================================================================

bool Test_MemorySafety() {
    TEST(MemorySafety);
    
    // Multiple create/destroy cycles
    for (int i = 0; i < 5; ++i) {
        auto core = Core::Create();
        if (!core->Initialize()) FAIL("Init failed");
        
        // Submit some tasks
        for (int j = 0; j < 3; ++j) {
            Task task;
            task.type = TaskType::File;
            task.fileParams.operation = "list";
            task.fileParams.path = ".";
            
            auto future = core->SubmitTask(task);
            auto result = future.get();
            (void)result;
        }
        
        if (!core->Shutdown(std::chrono::seconds(5))) FAIL("Shutdown failed");
    }
    
    PASS();
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Phase 1: Functional Validation" << std::endl;
    std::cout << "Smoke Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Testing unified architecture components..." << std::endl;
    
    auto startTime = std::chrono::steady_clock::now();
    
    // Run all tests
    Test_CoreLifecycle();
    Test_TaskExecution();
    Test_SubsystemAccess();
    Test_ErrorHandling();
    Test_Statistics();
    Test_ConvenienceMethods();
    Test_MemorySafety();
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "Duration: " << duration.count() << " ms" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (failed == 0) {
        std::cout << "\n✓ SMOKE TEST PASSED" << std::endl;
        std::cout << "Unified architecture is functional" << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ SMOKE TEST FAILED" << std::endl;
        return 1;
    }
}
