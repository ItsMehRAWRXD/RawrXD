/**
 * @file test_ggml_integration.cpp
 * @brief Validation tests for GGML integration
 * 
 * Phase 1: Validation - Functional correctness tests
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <cassert>
#include <cmath>
#include <chrono>
#include <fstream>
#include <vector>
#include <string>

// Unified architecture headers
#include "../../src/agentic/Core.h"
#include "../../src/inference/InferenceEngine.h"
#include "../../src/core/ErrorHandling.h"

// Test configuration
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[FAIL] " << msg << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            return false; \
        } \
    } while(0)

#define TEST_PASS(name) \
    do { \
        std::cout << "[PASS] " << name << std::endl; \
        return true; \
    } while(0)

using namespace RawrXD;

// ============================================================================
// Test 1: Core Initialization
// ============================================================================

bool Test_CoreInitialization() {
    std::cout << "\n[Test] Core Initialization..." << std::endl;
    
    auto core = Agentic::Core::Create();
    TEST_ASSERT(core != nullptr, "Core creation failed");
    
    bool initialized = core->Initialize();
    TEST_ASSERT(initialized, "Core initialization failed");
    
    TEST_ASSERT(core->IsInitialized(), "Core reports not initialized");
    
    bool shutdown = core->Shutdown(std::chrono::seconds(5));
    TEST_ASSERT(shutdown, "Core shutdown failed");
    
    TEST_PASS("Core Initialization");
}

// ============================================================================
// Test 2: Inference Engine Creation
// ============================================================================

bool Test_InferenceEngineCreation() {
    std::cout << "\n[Test] Inference Engine Creation..." << std::endl;
    
    Inference::EngineConfig config;
    config.backendType = Inference::BackendType::GGML;
    config.modelPath = "test_model.gguf";  // Non-existent, should handle gracefully
    
    auto engine = Inference::InferenceEngine::Create(config);
    TEST_ASSERT(engine != nullptr, "Engine creation failed");
    
    // Should initialize even without model (lazy loading)
    bool initialized = engine->Initialize();
    TEST_ASSERT(initialized, "Engine initialization failed");
    
    // Try to load non-existent model - should fail gracefully
    auto result = engine->LoadModel("nonexistent_model.gguf");
    TEST_ASSERT(!result.success, "Should fail to load non-existent model");
    TEST_ASSERT(!result.errorMessage.empty(), "Should provide error message");
    
    engine->Shutdown();
    
    TEST_PASS("Inference Engine Creation");
}

// ============================================================================
// Test 3: Task Submission and Execution
// ============================================================================

bool Test_TaskExecution() {
    std::cout << "\n[Test] Task Execution..." << std::endl;
    
    auto core = Agentic::Core::Create();
    TEST_ASSERT(core->Initialize(), "Core init failed");
    
    // Test file task
    Agentic::Task fileTask;
    fileTask.type = Agentic::TaskType::File;
    fileTask.instruction = "List directory";
    fileTask.fileParams.operation = "list";
    fileTask.fileParams.path = ".";
    
    auto future = core->SubmitTask(fileTask);
    auto result = future.get();
    
    // Task should execute (may fail due to filesystem, but should complete)
    TEST_ASSERT(!result.taskId.empty(), "Task should have ID");
    TEST_ASSERT(result.durationMs >= 0, "Task should have duration");
    
    // Test sync execution
    Agentic::Task syncTask;
    syncTask.type = Agentic::TaskType::File;
    syncTask.instruction = "Read test";
    syncTask.fileParams.operation = "read";
    syncTask.fileParams.path = "nonexistent.txt";
    
    auto syncResult = core->ExecuteSync(syncTask, std::chrono::seconds(5));
    TEST_ASSERT(!syncResult.taskId.empty(), "Sync task should have ID");
    
    core->Shutdown(std::chrono::seconds(5));
    
    TEST_PASS("Task Execution");
}

// ============================================================================
// Test 4: Error Handling
// ============================================================================

bool Test_ErrorHandling() {
    std::cout << "\n[Test] Error Handling..." << std::endl;
    
    // Test Result<T> success case
    Core::Result<int> successResult(42);
    TEST_ASSERT(successResult.HasValue(), "Result should have value");
    TEST_ASSERT(successResult.Value() == 42, "Result value should be 42");
    
    // Test Result<T> error case
    Core::Error error(Core::ErrorCode::InvalidArgument, "Test error");
    Core::Result<int> errorResult(error);
    TEST_ASSERT(errorResult.HasError(), "Result should have error");
    TEST_ASSERT(errorResult.GetError().code == Core::ErrorCode::InvalidArgument, 
                "Error code should match");
    
    // Test ValueOr
    int value = errorResult.ValueOr(99);
    TEST_ASSERT(value == 99, "ValueOr should return default");
    
    TEST_PASS("Error Handling");
}

// ============================================================================
// Test 5: Subsystem Access
// ============================================================================

bool Test_SubsystemAccess() {
    std::cout << "\n[Test] Subsystem Access..." << std::endl;
    
    auto core = Agentic::Core::Create();
    TEST_ASSERT(core->Initialize(), "Core init failed");
    
    // Test all subsystems are accessible
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
        TEST_ASSERT(false, std::string("Subsystem access failed: ") + e.what());
    }
    
    core->Shutdown(std::chrono::seconds(5));
    
    TEST_PASS("Subsystem Access");
}

// ============================================================================
// Test 6: Configuration
// ============================================================================

bool Test_Configuration() {
    std::cout << "\n[Test] Configuration..." << std::endl;
    
    auto& config = Core::Config::GetInstance();
    
    // Test setting and getting values
    config.SetString("test_key", "test_value");
    auto value = config.Get<std::string>("test_key");
    
    TEST_ASSERT(value.has_value(), "Config should return value");
    TEST_ASSERT(value.value() == "test_value", "Config value should match");
    
    // Test default value
    auto defaultValue = config.GetOrDefault<std::string>("nonexistent", "default");
    TEST_ASSERT(defaultValue == "default", "Should return default");
    
    TEST_PASS("Configuration");
}

// ============================================================================
// Test 7: Statistics
// ============================================================================

bool Test_Statistics() {
    std::cout << "\n[Test] Statistics..." << std::endl;
    
    auto core = Agentic::Core::Create();
    TEST_ASSERT(core->Initialize(), "Core init failed");
    
    auto stats = core->GetStats();
    
    // Initial stats should be zero
    TEST_ASSERT(stats.tasksSubmitted == 0, "Initial submitted should be 0");
    TEST_ASSERT(stats.tasksCompleted == 0, "Initial completed should be 0");
    TEST_ASSERT(stats.tasksFailed == 0, "Initial failed should be 0");
    TEST_ASSERT(stats.tasksCancelled == 0, "Initial cancelled should be 0");
    
    // Submit a task and verify stats update
    Agentic::Task task;
    task.type = Agentic::TaskType::File;
    task.fileParams.operation = "list";
    task.fileParams.path = ".";
    
    auto future = core->SubmitTask(task);
    auto result = future.get();
    
    auto updatedStats = core->GetStats();
    TEST_ASSERT(updatedStats.tasksSubmitted >= 1, "Submitted should increment");
    
    core->Shutdown(std::chrono::seconds(5));
    
    TEST_PASS("Statistics");
}

// ============================================================================
// Test 8: Concurrent Task Execution
// ============================================================================

bool Test_ConcurrentExecution() {
    std::cout << "\n[Test] Concurrent Execution..." << std::endl;
    
    auto core = Agentic::Core::Create();
    TEST_ASSERT(core->Initialize(), "Core init failed");
    
    // Submit multiple tasks concurrently
    std::vector<std::future<Agentic::TaskResult>> futures;
    
    for (int i = 0; i < 5; ++i) {
        Agentic::Task task;
        task.type = Agentic::TaskType::File;
        task.instruction = "Task " + std::to_string(i);
        task.fileParams.operation = "list";
        task.fileParams.path = ".";
        
        futures.push_back(core->SubmitTask(task));
    }
    
    // Wait for all tasks
    int completed = 0;
    for (auto& future : futures) {
        auto result = future.get();
        if (!result.taskId.empty()) {
            completed++;
        }
    }
    
    TEST_ASSERT(completed == 5, "All concurrent tasks should complete");
    
    core->Shutdown(std::chrono::seconds(5));
    
    TEST_PASS("Concurrent Execution");
}

// ============================================================================
// Test 9: Task Cancellation
// ============================================================================

bool Test_TaskCancellation() {
    std::cout << "\n[Test] Task Cancellation..." << std::endl;
    
    auto core = Agentic::Core::Create();
    TEST_ASSERT(core->Initialize(), "Core init failed");
    
    // Submit a task
    Agentic::Task task;
    task.type = Agentic::TaskType::File;
    task.fileParams.operation = "list";
    task.fileParams.path = ".";
    
    auto future = core->SubmitTask(task);
    
    // Try to cancel (may or may not succeed depending on timing)
    // Just verify the API works
    bool cancelled = core->CancelTask(task.id);
    (void)cancelled;  // Don't assert - timing dependent
    
    // Wait for result (task may have already completed)
    auto result = future.get();
    TEST_ASSERT(!result.taskId.empty(), "Task should have ID");
    
    core->Shutdown(std::chrono::seconds(5));
    
    TEST_PASS("Task Cancellation");
}

// ============================================================================
// Test 10: Memory Safety
// ============================================================================

bool Test_MemorySafety() {
    std::cout << "\n[Test] Memory Safety..." << std::endl;
    
    // Test multiple create/destroy cycles
    for (int i = 0; i < 10; ++i) {
        auto core = Agentic::Core::Create();
        TEST_ASSERT(core->Initialize(), "Core init failed");
        
        // Submit some tasks
        for (int j = 0; j < 5; ++j) {
            Agentic::Task task;
            task.type = Agentic::TaskType::File;
            task.fileParams.operation = "list";
            task.fileParams.path = ".";
            
            auto future = core->SubmitTask(task);
            auto result = future.get();
            (void)result;
        }
        
        TEST_ASSERT(core->Shutdown(std::chrono::seconds(5)), "Shutdown failed");
    }
    
    TEST_PASS("Memory Safety");
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Unified Architecture Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    auto runTest = [&](const char* name, bool (*test)()) {
        std::cout << "\nRunning: " << name << "..." << std::endl;
        if (test()) {
            passed++;
        } else {
            failed++;
            std::cerr << "FAILED: " << name << std::endl;
        }
    };
    
    runTest("Core Initialization", Test_CoreInitialization);
    runTest("Inference Engine Creation", Test_InferenceEngineCreation);
    runTest("Task Execution", Test_TaskExecution);
    runTest("Error Handling", Test_ErrorHandling);
    runTest("Subsystem Access", Test_SubsystemAccess);
    runTest("Configuration", Test_Configuration);
    runTest("Statistics", Test_Statistics);
    runTest("Concurrent Execution", Test_ConcurrentExecution);
    runTest("Task Cancellation", Test_TaskCancellation);
    runTest("Memory Safety", Test_MemorySafety);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return failed > 0 ? 1 : 0;
}
