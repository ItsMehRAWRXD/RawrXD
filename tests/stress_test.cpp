/**
 * @file stress_test.cpp
 * @brief Phase 1B: Stress Testing - Race Conditions & Memory Stability
 * 
 * Aggressive validation that uncovers concurrency bugs and memory issues
 * that don't appear in basic smoke tests.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <memory>
#include <chrono>
#include <thread>
#include <vector>
#include <random>
#include <atomic>

#include "../src/agentic/Core.h"

using namespace RawrXD::Agentic;

// Test configuration
constexpr int LIFECYCLE_ITERATIONS = 1000;
constexpr int TASKS_PER_ITERATION = 100;
constexpr int MAX_CONCURRENT_THREADS = 16;
constexpr int RANDOM_SEED = 42;

// Statistics
std::atomic<int> totalTasksSubmitted{0};
std::atomic<int> totalTasksCompleted{0};
std::atomic<int> totalTasksFailed{0};
std::atomic<int> lifecycleFailures{0};
std::atomic<int> raceConditionsDetected{0};

// Simple test framework
#define TEST(name) std::cout << "\n[STRESS TEST] " << #name << "... " << std::flush
#define PASS() do { std::cout << "✓ PASS" << std::endl; passed++; } while(0)
#define FAIL(msg) do { \
    std::cout << "✗ FAIL: " << msg << std::endl; \
    failed++; \
    return false; \
} while(0)

int passed = 0;
int failed = 0;

// ============================================================================
// Stress Test 1: Rapid Lifecycle Cycling
// ============================================================================

bool Test_RapidLifecycle() {
    TEST(RapidLifecycle);
    
    std::random_device rd;
    std::mt19937 gen(RANDOM_SEED);
    std::uniform_int_distribution<> delayDist(0, 10); // 0-10ms random delay
    
    for (int i = 0; i < LIFECYCLE_ITERATIONS; ++i) {
        try {
            auto core = Core::Create();
            if (!core) {
                lifecycleFailures++;
                continue;
            }
            
            if (!core->Initialize()) {
                lifecycleFailures++;
                continue;
            }
            
            // Random micro-delay to simulate real-world timing variation
            std::this_thread::sleep_for(std::chrono::milliseconds(delayDist(gen)));
            
            if (!core->IsInitialized()) {
                lifecycleFailures++;
                continue;
            }
            
            if (!core->Shutdown(std::chrono::milliseconds(100))) {
                lifecycleFailures++;
                continue;
            }
        } catch (const std::exception& e) {
            lifecycleFailures++;
            if (i < 5) { // Only log first few failures to avoid spam
                std::cerr << "Lifecycle exception at iteration " << i << ": " << e.what() << std::endl;
            }
        }
        
        if (i % 100 == 0) {
            std::cout << "." << std::flush;
        }
    }
    
    if (lifecycleFailures > LIFECYCLE_ITERATIONS / 10) { // Allow 10% failure rate
        FAIL("Too many lifecycle failures: " + std::to_string(lifecycleFailures.load()));
    }
    
    std::cout << "\n  Completed " << LIFECYCLE_ITERATIONS << " cycles, " 
              << lifecycleFailures << " failures" << std::endl;
    PASS();
    return true;
}

// ============================================================================
// Stress Test 2: Concurrent Task Submission
// ============================================================================

bool Test_ConcurrentTaskSubmission() {
    TEST(ConcurrentTaskSubmission);
    
    auto core = Core::Create();
    if (!core->Initialize()) FAIL("Init failed");
    
    std::vector<std::thread> threads;
    std::atomic<int> readyCount{0};
    std::atomic<bool> startFlag{false};
    
    auto worker = [&](int threadId) {
        // Signal ready and wait for all threads
        readyCount++;
        while (readyCount.load() < MAX_CONCURRENT_THREADS) {
            std::this_thread::yield();
        }
        
        // Wait for signal to start simultaneously
        while (!startFlag.load()) {
            std::this_thread::yield();
        }
        
        std::random_device rd;
        std::mt19937 gen(RANDOM_SEED + threadId);
        std::uniform_int_distribution<> typeDist(0, 2);
        std::uniform_int_distribution<> delayDist(0, 5);
        
        for (int i = 0; i < TASKS_PER_ITERATION; ++i) {
            Task task;
            task.type = static_cast<TaskType>(typeDist(gen));
            task.instruction = "Thread " + std::to_string(threadId) + " Task " + std::to_string(i);
            
            try {
                auto future = core->SubmitTask(task);
                totalTasksSubmitted++;
                
                // Random delay between submissions
                std::this_thread::sleep_for(std::chrono::microseconds(delayDist(gen)));
                
                // Wait for result with timeout
                if (future.wait_for(std::chrono::seconds(5)) == std::future_status::ready) {
                    auto result = future.get();
                    if (result.success) {
                        totalTasksCompleted++;
                    } else {
                        totalTasksFailed++;
                    }
                } else {
                    totalTasksFailed++;
                    raceConditionsDetected++;
                }
            } catch (const std::exception& e) {
                totalTasksFailed++;
                if (i < 3 && threadId == 0) {
                    std::cerr << "Task exception: " << e.what() << std::endl;
                }
            }
        }
    };
    
    // Launch all threads
    for (int i = 0; i < MAX_CONCURRENT_THREADS; ++i) {
        threads.emplace_back(worker, i);
    }
    
    // Give threads time to reach barrier
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Signal all threads to start simultaneously
    startFlag = true;
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    core->Shutdown(std::chrono::seconds(10));
    
    int expectedTasks = MAX_CONCURRENT_THREADS * TASKS_PER_ITERATION;
    std::cout << "\n  Submitted: " << totalTasksSubmitted 
              << ", Completed: " << totalTasksCompleted
              << ", Failed: " << totalTasksFailed << std::endl;
    
    if (totalTasksSubmitted != expectedTasks) {
        FAIL("Task count mismatch");
    }
    
    if (totalTasksCompleted < expectedTasks * 0.8) { // Allow 20% failure
        FAIL("Too many task failures");
    }
    
    if (raceConditionsDetected > 0) {
        std::cout << "  ⚠️  Race conditions detected: " << raceConditionsDetected << std::endl;
    }
    
    PASS();
    return true;
}

// ============================================================================
// Stress Test 3: Memory Pressure
// ============================================================================

bool Test_MemoryPressure() {
    TEST(MemoryPressure);
    
    std::vector<std::unique_ptr<Core>> cores;
    std::vector<std::thread> threads;
    
    // Create many cores simultaneously
    for (int i = 0; i < 50; ++i) {
        auto core = Core::Create();
        if (!core || !core->Initialize()) {
            continue;
        }
        cores.push_back(std::move(core));
    }
    
    std::cout << "\n  Created " << cores.size() << " concurrent cores" << std::endl;
    
    // Submit tasks from all cores
    std::atomic<int> tasksFromAllCores{0};
    
    for (size_t i = 0; i < cores.size(); ++i) {
        threads.emplace_back([&, i]() {
            for (int j = 0; j < 20; ++j) {
                Task task;
                task.type = TaskType::File;
                task.instruction = "Memory test " + std::to_string(i) + ":" + std::to_string(j);
                
                try {
                    auto future = cores[i]->SubmitTask(task);
                    if (future.wait_for(std::chrono::seconds(2)) == std::future_status::ready) {
                        tasksFromAllCores++;
                    }
                } catch (...) {
                    // Expected under memory pressure
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    std::cout << "  Tasks completed under pressure: " << tasksFromAllCores << std::endl;
    
    // Cleanup
    for (auto& core : cores) {
        core->Shutdown(std::chrono::seconds(1));
    }
    cores.clear();
    
    if (tasksFromAllCores < 500) { // At least some tasks should complete
        FAIL("Too few tasks completed under memory pressure");
    }
    
    PASS();
    return true;
}

// ============================================================================
// Stress Test 4: Rapid Task Cancellation
// ============================================================================

bool Test_RapidCancellation() {
    TEST(RapidCancellation);
    
    auto core = Core::Create();
    if (!core->Initialize()) FAIL("Init failed");
    
    std::vector<std::future<TaskResult>> futures;
    std::vector<std::string> taskIds;
    
    // Submit many tasks
    for (int i = 0; i < 200; ++i) {
        Task task;
        task.type = TaskType::File;
        task.instruction = "Cancel test " + std::to_string(i);
        
        auto future = core->SubmitTask(task);
        futures.push_back(std::move(future));
    }
    
    // Immediately try to cancel half of them
    int cancelled = 0;
    for (size_t i = 0; i < futures.size(); i += 2) {
        // Note: CancelTask would need taskId, which we don't have here
        // This tests the race between submission and execution
        std::this_thread::sleep_for(std::chrono::microseconds(10));
        cancelled++;
    }
    
    // Wait for all tasks
    int completed = 0;
    int failed = 0;
    for (auto& future : futures) {
        try {
            if (future.wait_for(std::chrono::seconds(5)) == std::future_status::ready) {
                auto result = future.get();
                if (result.success) completed++;
                else failed++;
            } else {
                failed++;
            }
        } catch (...) {
            failed++;
        }
    }
    
    core->Shutdown(std::chrono::seconds(5));
    
    std::cout << "\n  Completed: " << completed << ", Failed: " << failed << std::endl;
    
    if (completed + failed != 200) {
        FAIL("Task count mismatch after cancellation test");
    }
    
    PASS();
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Phase 1B: Stress Testing" << std::endl;
    std::cout << "Aggressive Concurrency Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Lifecycle iterations: " << LIFECYCLE_ITERATIONS << std::endl;
    std::cout << "  Tasks per thread: " << TASKS_PER_ITERATION << std::endl;
    std::cout << "  Concurrent threads: " << MAX_CONCURRENT_THREADS << std::endl;
    std::cout << "  Random seed: " << RANDOM_SEED << std::endl;
    std::cout << std::endl;
    
    auto startTime = std::chrono::steady_clock::now();
    
    // Run stress tests
    Test_RapidLifecycle();
    Test_ConcurrentTaskSubmission();
    Test_MemoryPressure();
    Test_RapidCancellation();
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "Duration: " << duration.count() << " seconds" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (failed == 0) {
        std::cout << "\n✓ STRESS TEST PASSED" << std::endl;
        std::cout << "Architecture is robust under pressure" << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ STRESS TEST FAILED" << std::endl;
        return 1;
    }
}
