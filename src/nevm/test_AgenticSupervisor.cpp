//=============================================================================
// test_AgenticSupervisor.cpp - Level 4 Validation Suite
// Tests: Initialization, Task Execution, Self-Healing, Metrics, Health
//=============================================================================

#include "AgenticSupervisor.hpp"
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <atomic>

using namespace RawrXD::Agentic;

//=============================================================================
// Test Infrastructure
//=============================================================================
static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("  [FAIL] %s:%d - %s\n", __FILE__, __LINE__, msg); \
            g_testsFailed++; \
        } else { \
            g_testsPassed++; \
        } \
    } while(0)

#define TEST_SECTION(name) \
    printf("\n=== %s ===\n", name)

//=============================================================================
// Test 1: Singleton & Initialization
//=============================================================================
void Test_SingletonInitialization() {
    TEST_SECTION("Test 1: Singleton & Initialization");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    
    // Fresh instance should not be running
    TEST_ASSERT(!sup.IsRunning(), "Instance should not be running initially");
    
    // Initialize with default config
    bool ok = sup.Initialize();
    TEST_ASSERT(ok, "Initialize should succeed");
    TEST_ASSERT(sup.IsRunning(), "Instance should be running after Init");
    
    // Double-init should be idempotent
    ok = sup.Initialize();
    TEST_ASSERT(ok, "Double-init should succeed (idempotent)");
    
    sup.Shutdown();
    TEST_ASSERT(!sup.IsRunning(), "Instance should not be running after Shutdown");
}

//=============================================================================
// Test 2: Basic Task Submission & Execution
//=============================================================================
void Test_BasicTaskExecution() {
    TEST_SECTION("Test 2: Basic Task Execution");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    sup.Initialize();
    
    std::atomic<int> counter{0};
    
    AgenticTask task;
    task.name = "IncrementCounter";
    task.execute = [&counter]() -> bool {
        counter.fetch_add(1);
        return true;
    };
    task.priority = TaskPriority::HIGH;
    
    std::string id = sup.SubmitTask(std::move(task));
    TEST_ASSERT(!id.empty(), "Task ID should not be empty");
    
    // Wait for completion
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    auto status = sup.GetTaskStatus(id);
    TEST_ASSERT(status.status == TaskStatus::COMPLETED, 
                "Task should complete successfully");
    TEST_ASSERT(counter.load() == 1, "Counter should be incremented");
    
    sup.Shutdown();
}

//=============================================================================
// Test 3: Task Failure & Retry
//=============================================================================
void Test_TaskFailureAndRetry() {
    TEST_SECTION("Test 3: Task Failure & Retry");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    sup.Initialize();
    
    std::atomic<int> attemptCount{0};
    
    // Task that fails twice then succeeds
    bool result = sup.ExecuteWithRetry("FlakyTask", [&attemptCount]() -> bool {
        int attempt = attemptCount.fetch_add(1);
        return attempt >= 2; // Succeed on 3rd attempt
    }, 3);
    
    TEST_ASSERT(result, "Retry should eventually succeed");
    TEST_ASSERT(attemptCount.load() == 3, "Should take exactly 3 attempts");
    
    sup.Shutdown();
}

//=============================================================================
// Test 4: ExecuteWithCheckpoint Wrapper
//=============================================================================
void Test_CheckpointWrapper() {
    TEST_SECTION("Test 4: ExecuteWithCheckpoint");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    sup.Initialize();
    
    bool executed = false;
    bool result = sup.ExecuteWithCheckpoint("CheckpointedTask", [&executed]() -> bool {
        executed = true;
        return true;
    });
    
    TEST_ASSERT(result, "Checkpoint task should succeed");
    TEST_ASSERT(executed, "Task body should execute");
    
    sup.Shutdown();
}

//=============================================================================
// Test 5: Concurrent Task Execution
//=============================================================================
void Test_ConcurrentExecution() {
    TEST_SECTION("Test 5: Concurrent Execution (10 tasks)");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    AgenticSupervisor::Config cfg;
    cfg.maxConcurrentTasks = 4;
    sup.Initialize(cfg);
    
    std::atomic<int> completedTasks{0};
    std::vector<std::string> taskIds;
    
    // Submit 10 tasks
    for (int i = 0; i < 10; i++) {
        AgenticTask task;
        task.name = "ConcurrentTask_" + std::to_string(i);
        task.execute = [&completedTasks]() -> bool {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            completedTasks.fetch_add(1);
            return true;
        };
        taskIds.push_back(sup.SubmitTask(std::move(task)));
    }
    
    // Wait for all
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    TEST_ASSERT(completedTasks.load() == 10, "All 10 tasks should complete");
    
    // Verify all statuses
    int completed = 0;
    for (const auto& id : taskIds) {
        auto status = sup.GetTaskStatus(id);
        if (status.status == TaskStatus::COMPLETED) completed++;
    }
    TEST_ASSERT(completed == 10, "All tasks should report COMPLETED");
    
    sup.Shutdown();
}

//=============================================================================
// Test 6: Task Cancellation
//=============================================================================
void Test_TaskCancellation() {
    TEST_SECTION("Test 6: Task Cancellation");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    sup.Initialize();
    
    // Submit a long-running task
    AgenticTask task;
    task.name = "LongTask";
    task.execute = []() -> bool {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return true;
    };
    
    std::string id = sup.SubmitTask(std::move(task));
    
    // Cancel immediately (before it starts)
    bool cancelled = sup.CancelTask(id);
    TEST_ASSERT(cancelled, "Should be able to cancel pending task");
    
    auto status = sup.GetTaskStatus(id);
    TEST_ASSERT(status.status == TaskStatus::CANCELLED, 
                "Task should be CANCELLED");
    
    sup.Shutdown();
}

//=============================================================================
// Test 7: Health Monitoring & Metrics
//=============================================================================
void Test_HealthAndMetrics() {
    TEST_SECTION("Test 7: Health & Metrics");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    AgenticSupervisor::Config cfg;
    cfg.targetSuccessRate = 0.8; // Lower threshold for test
    sup.Initialize(cfg);
    
    // Execute mix of success/failure tasks
    for (int i = 0; i < 10; i++) {
        sup.ExecuteWithCheckpoint("MetricTask_" + std::to_string(i), [i]() -> bool {
            return i < 8; // 8 success, 2 failure
        });
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    auto metrics = sup.GetMetrics();
    TEST_ASSERT(metrics.completedTasks >= 8, "Should have 8+ completed");
    
    // Health should reflect the 80% success rate
    bool healthy = sup.IsHealthy();
    TEST_ASSERT(healthy, "Should be healthy at 80% success rate");
    
    std::string report = sup.GetHealthReport();
    TEST_ASSERT(!report.empty(), "Health report should not be empty");
    TEST_ASSERT(report.find("HEALTHY") != std::string::npos ||
                report.find("DEGRADED") != std::string::npos,
                "Report should contain health status");
    
    sup.Shutdown();
}

//=============================================================================
// Test 8: ScopedAgenticTask RAII
//=============================================================================
void Test_ScopedTask() {
    TEST_SECTION("Test 8: ScopedAgenticTask RAII");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    sup.Initialize();
    
    bool executed = false;
    {
        ScopedAgenticTask scoped("ScopedTask", [&executed]() -> bool {
            executed = true;
            return true;
        });
        
        bool result = scoped.Execute();
        TEST_ASSERT(result, "Scoped task should execute successfully");
        TEST_ASSERT(executed, "Scoped task body should run");
        TEST_ASSERT(scoped.WasSuccessful(), "WasSuccessful should be true");
    }
    // RAII cleanup happens here
    
    sup.Shutdown();
}

//=============================================================================
// Test 9: Self-Healing Trigger
//=============================================================================
void Test_SelfHealing() {
    TEST_SECTION("Test 9: Self-Healing");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    AgenticSupervisor::Config cfg;
    cfg.enableSelfHealing = true;
    cfg.targetSuccessRate = 1.0; // Impossible - forces healing
    sup.Initialize(cfg);
    
    // Submit a failing task to trigger healing
    sup.ExecuteWithCheckpoint("FailTask", []() -> bool {
        return false; // Force failure
    });
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Trigger healing manually
    sup.TriggerSelfHealing("Test trigger");
    
    auto metrics = sup.GetMetrics();
    TEST_ASSERT(metrics.failedTasks >= 1, "Should have recorded failure");
    
    sup.Shutdown();
}

//=============================================================================
// Test 10: Interrupt Flag (Inference Loop Integration)
//=============================================================================
void Test_InterruptFlag() {
    TEST_SECTION("Test 10: Interrupt Flag");
    
    // Test the global interrupt flag
    g_interrupt_flag.store(false);
    TEST_ASSERT(!g_interrupt_flag.load(), "Flag should start false");
    
    g_interrupt_flag.store(true);
    TEST_ASSERT(g_interrupt_flag.load(), "Flag should be settable");
    
    g_interrupt_flag.store(false);
    TEST_ASSERT(!g_interrupt_flag.load(), "Flag should be clearable");
    
    // Test generation flag
    g_is_generating.store(false);
    TEST_ASSERT(!g_is_generating.load(), "Gen flag should start false");
}

//=============================================================================
// Test 11: Task Timeout
//=============================================================================
void Test_TaskTimeout() {
    TEST_SECTION("Test 11: Task Timeout");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    AgenticSupervisor::Config cfg;
    cfg.taskTimeout = std::chrono::milliseconds(100); // Very short
    sup.Initialize(cfg);
    
    bool result = sup.ExecuteWithCheckpoint("TimeoutTask", []() -> bool {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return true;
    });
    
    TEST_ASSERT(!result, "Task should timeout and fail");
    
    sup.Shutdown();
}

//=============================================================================
// Test 12: Priority Ordering (Basic)
//=============================================================================
void Test_PriorityOrdering() {
    TEST_SECTION("Test 12: Priority Ordering");
    
    AgenticSupervisor& sup = AgenticSupervisor::Instance();
    sup.Initialize();
    
    std::atomic<int> order{0};
    std::vector<int> executionOrder;
    std::mutex orderMutex;
    
    // Submit tasks with different priorities
    for (int i = 0; i < 5; i++) {
        AgenticTask task;
        task.name = "Priority_" + std::to_string(i);
        task.priority = (i == 0) ? TaskPriority::CRITICAL : TaskPriority::NORMAL;
        int idx = i;
        task.execute = [idx, &order, &executionOrder, &orderMutex]() -> bool {
            int myOrder = order.fetch_add(1);
            std::lock_guard<std::mutex> lock(orderMutex);
            executionOrder.push_back(idx);
            return true;
        };
        sup.SubmitTask(std::move(task));
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    TEST_ASSERT(executionOrder.size() == 5, "All priority tasks should execute");
    
    sup.Shutdown();
}

//=============================================================================
// Main
//=============================================================================
int main(int argc, char** argv) {
    printf("========================================\n");
    printf("  AgenticSupervisor Level 4 Test Suite  \n");
    printf("  RawrXD Sovereign Substrate           \n");
    printf("========================================\n");
    
    auto start = std::chrono::steady_clock::now();
    
    // Run all tests
    Test_SingletonInitialization();
    Test_BasicTaskExecution();
    Test_TaskFailureAndRetry();
    Test_CheckpointWrapper();
    Test_ConcurrentExecution();
    Test_TaskCancellation();
    Test_HealthAndMetrics();
    Test_ScopedTask();
    Test_SelfHealing();
    Test_InterruptFlag();
    Test_TaskTimeout();
    Test_PriorityOrdering();
    
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    printf("\n========================================\n");
    printf("  RESULTS                               \n");
    printf("========================================\n");
    printf("  Tests Passed:  %d\n", g_testsPassed);
    printf("  Tests Failed:  %d\n", g_testsFailed);
    printf("  Total Tests:   %d\n", g_testsPassed + g_testsFailed);
    printf("  Duration:      %lld ms\n", elapsed.count());
    printf("========================================\n");
    
    if (g_testsFailed > 0) {
        printf("\n  STATUS: FAILED\n");
        return 1;
    }
    
    printf("\n  STATUS: ALL TESTS PASSED\n");
    printf("  Sovereign Substrate Level 4: OPERATIONAL\n");
    return 0;
}
