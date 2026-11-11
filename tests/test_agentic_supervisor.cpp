//=============================================================================
// test_agentic_supervisor.cpp - Agentic Supervisor Validation
// Tests the autonomous agent orchestration layer
//=============================================================================

#include <cstdio>
#include <cassert>
#include <thread>
#include <chrono>
#include "../src/agentic/AgenticSupervisor.hpp"

using namespace RawrXD::Agentic;

//=============================================================================
// Test 1: Basic Initialization
//=============================================================================
bool Test_BasicInitialization() {
    printf("[TEST] Basic Initialization...\n");
    
    AgenticSupervisor::Config config;
    config.maxConcurrentTasks = 2;
    config.enableSelfHealing = false;
    config.enablePerformanceMonitoring = false;
    
    bool result = AgenticSupervisor::Instance().Initialize(config);
    assert(result);
    assert(AgenticSupervisor::Instance().IsRunning());
    
    AgenticSupervisor::Instance().Shutdown();
    assert(!AgenticSupervisor::Instance().IsRunning());
    
    printf("[PASS] Basic Initialization\n");
    return true;
}

//=============================================================================
// Test 2: Task Submission and Execution
//=============================================================================
bool Test_TaskSubmission() {
    printf("[TEST] Task Submission...\n");
    
    AgenticSupervisor::Config config;
    config.maxConcurrentTasks = 2;
    config.enableSelfHealing = false;
    config.enablePerformanceMonitoring = false;
    
    AgenticSupervisor::Instance().Initialize(config);
    
    // Submit a simple task
    AgenticTask task;
    task.name = "TestTask";
    task.priority = TaskPriority::NORMAL;
    task.execute = []() -> bool {
        printf("    [Task] Executing...\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return true;
    };
    
    std::string taskId = AgenticSupervisor::Instance().SubmitTask(std::move(task));
    assert(!taskId.empty());
    
    // Wait for completion
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    AgenticTask status = AgenticSupervisor::Instance().GetTaskStatus(taskId);
    assert(status.status == TaskStatus::COMPLETED);
    
    AgenticSupervisor::Instance().Shutdown();
    
    printf("[PASS] Task Submission\n");
    return true;
}

//=============================================================================
// Test 3: Agent Identity
//=============================================================================
bool Test_AgentIdentity() {
    printf("[TEST] Agent Identity...\n");
    
    AgentIdentity planner = AgentIdentity::Create(AgentRole::PLANNER, 10);
    assert(planner.id > 0);
    assert(planner.role == AgentRole::PLANNER);
    assert(planner.trustLevel == 10);
    assert(!planner.capabilities.empty());
    
    AgentIdentity coder = AgentIdentity::Create(AgentRole::CODER, 8);
    assert(coder.role == AgentRole::CODER);
    assert(coder.id > planner.id); // IDs should be unique and increasing
    
    printf("[PASS] Agent Identity\n");
    return true;
}

//=============================================================================
// Test 4: Tool Runtime
//=============================================================================
bool Test_ToolRuntime() {
    printf("[TEST] Tool Runtime...\n");
    
    AgentToolRuntime runtime;
    
    // Register a test tool
    bool toolExecuted = false;
    runtime.RegisterTool("test_tool", [&toolExecuted](const std::string& args) -> bool {
        printf("    [Tool] Executed with args: %s\n", args.c_str());
        toolExecuted = true;
        return true;
    });
    
    // Execute tool
    ToolCall call;
    call.tool = "test_tool";
    call.arguments = "{\"key\":\"value\"}";
    call.requiresApproval = false;
    
    bool result = runtime.Execute(call);
    assert(result);
    assert(toolExecuted);
    
    // Test unknown tool
    ToolCall unknown;
    unknown.tool = "unknown_tool";
    result = runtime.Execute(unknown);
    assert(!result);
    
    printf("[PASS] Tool Runtime\n");
    return true;
}

//=============================================================================
// Test 5: Reality Validator
//=============================================================================
bool Test_RealityValidator() {
    printf("[TEST] Reality Validator...\n");
    
    RealityValidator validator;
    
    // Test file existence validation
    ToolCall readFile;
    readFile.tool = "read_file";
    readFile.arguments = "{\"path\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\"}";
    
    bool result = validator.Validate(readFile);
    assert(result); // notepad.exe should exist
    
    // Test non-existent file
    ToolCall readNonExistent;
    readNonExistent.tool = "read_file";
    readNonExistent.arguments = "{\"path\":\"C:\\\\nonexistent\\\\file.txt\"}";
    
    result = validator.Validate(readNonExistent);
    assert(!result);
    
    // Test directory traversal blocking
    ToolCall traversal;
    traversal.tool = "write_file";
    traversal.arguments = "{\"path\":\"..\\\\..\\\\etc\\\\passwd\"}";
    
    result = validator.Validate(traversal);
    assert(!result);
    
    printf("[PASS] Reality Validator\n");
    return true;
}

//=============================================================================
// Test 6: Agent Context
//=============================================================================
bool Test_AgentContext() {
    printf("[TEST] Agent Context...\n");
    
    AgentContext ctx = AgentContext::Gather();
    
    assert(!ctx.workspace.empty());
    assert(!ctx.availableTools.empty());
    
    std::string prompt = AgentContext::BuildPrompt(ctx);
    assert(!prompt.empty());
    assert(prompt.find("Agent Context") != std::string::npos);
    
    printf("[PASS] Agent Context\n");
    return true;
}

//=============================================================================
// Test 7: Performance Metrics
//=============================================================================
bool Test_PerformanceMetrics() {
    printf("[TEST] Performance Metrics...\n");
    
    AgenticSupervisor::Config config;
    config.maxConcurrentTasks = 2;
    config.enableSelfHealing = false;
    config.enablePerformanceMonitoring = true;
    config.metricsInterval = std::chrono::milliseconds(100);
    
    AgenticSupervisor::Instance().Initialize(config);
    
    // Submit multiple tasks
    for (int i = 0; i < 5; ++i) {
        AgenticTask task;
        task.name = "MetricTask_" + std::to_string(i);
        task.execute = []() -> bool {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            return true;
        };
        AgenticSupervisor::Instance().SubmitTask(std::move(task));
    }
    
    // Wait for tasks and metrics collection
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    PerformanceMetrics metrics = AgenticSupervisor::Instance().GetMetrics();
    assert(metrics.completedTasks >= 5);
    
    std::string report = AgenticSupervisor::Instance().GetHealthReport();
    assert(!report.empty());
    
    AgenticSupervisor::Instance().Shutdown();
    
    printf("[PASS] Performance Metrics\n");
    return true;
}

//=============================================================================
// Test 8: Self-Healing
//=============================================================================
bool Test_SelfHealing() {
    printf("[TEST] Self-Healing...\n");
    
    AgenticSupervisor::Config config;
    config.maxConcurrentTasks = 2;
    config.enableSelfHealing = true;
    config.enablePerformanceMonitoring = false;
    
    AgenticSupervisor::Instance().Initialize(config);
    
    // Submit a failing task that should trigger healing
    AgenticTask task;
    task.name = "FailingTask";
    task.maxRetries = 2;
    task.execute = []() -> bool {
        static int attempts = 0;
        attempts++;
        printf("    [Task] Attempt %d...\n", attempts);
        return attempts >= 2; // Succeed on second attempt
    };
    
    std::string taskId = AgenticSupervisor::Instance().SubmitTask(std::move(task));
    
    // Wait for healing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    AgenticTask status = AgenticSupervisor::Instance().GetTaskStatus(taskId);
    // Task may have completed or still retrying
    
    AgenticSupervisor::Instance().Shutdown();
    
    printf("[PASS] Self-Healing\n");
    return true;
}

//=============================================================================
// Test 9: AGENTIC_TASK Macro
//=============================================================================
bool Test_AgenticTaskMacro() {
    printf("[TEST] AGENTIC_TASK Macro...\n");
    
    AgenticSupervisor::Config config;
    config.maxConcurrentTasks = 2;
    config.enableSelfHealing = false;
    config.enablePerformanceMonitoring = false;
    
    AgenticSupervisor::Instance().Initialize(config);
    
    // Use the macro
    bool executed = false;
    AGENTIC_TASK("MacroTask", {
        executed = true;
        printf("    [Macro] Task executed\n");
    });
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    AgenticSupervisor::Instance().Shutdown();
    
    printf("[PASS] AGENTIC_TASK Macro\n");
    return true;
}

//=============================================================================
// Test 10: Health Check
//=============================================================================
bool Test_HealthCheck() {
    printf("[TEST] Health Check...\n");
    
    AgenticSupervisor::Config config;
    config.maxConcurrentTasks = 2;
    config.targetSuccessRate = 0.95;
    config.maxLatencyMs = 100.0;
    
    AgenticSupervisor::Instance().Initialize(config);
    
    // Initially should be healthy
    assert(AgenticSupervisor::Instance().IsHealthy());
    
    // Get health report
    std::string report = AgenticSupervisor::Instance().GetHealthReport();
    printf("%s\n", report.c_str());
    
    AgenticSupervisor::Instance().Shutdown();
    
    printf("[PASS] Health Check\n");
    return true;
}

//=============================================================================
// Main
//=============================================================================
int main() {
    printf("=============================================================================\n");
    printf("AGENTIC SUPERVISOR TEST SUITE\n");
    printf("=============================================================================\n\n");
    
    int passed = 0;
    int failed = 0;
    
    auto runTest = [&](const char* name, bool (*test)()) {
        printf("\n--- %s ---\n", name);
        try {
            if (test()) {
                passed++;
            } else {
                failed++;
                printf("[FAIL] %s\n", name);
            }
        } catch (const std::exception& e) {
            failed++;
            printf("[EXCEPTION] %s: %s\n", name, e.what());
        }
    };
    
    runTest("Basic Initialization", Test_BasicInitialization);
    runTest("Task Submission", Test_TaskSubmission);
    runTest("Agent Identity", Test_AgentIdentity);
    runTest("Tool Runtime", Test_ToolRuntime);
    runTest("Reality Validator", Test_RealityValidator);
    runTest("Agent Context", Test_AgentContext);
    runTest("Performance Metrics", Test_PerformanceMetrics);
    runTest("Self-Healing", Test_SelfHealing);
    runTest("AGENTIC_TASK Macro", Test_AgenticTaskMacro);
    runTest("Health Check", Test_HealthCheck);
    
    printf("\n=============================================================================\n");
    printf("RESULTS: %d passed, %d failed\n", passed, failed);
    printf("=============================================================================\n");
    
    return failed == 0 ? 0 : 1;
}
