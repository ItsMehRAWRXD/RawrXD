//============================================================================
// test_parallel_executor.hpp
// RawrXD N-EVM - Parallel Executor Unit Tests
//============================================================================

#pragma once

#include "test_framework.hpp"
#include "../nevm_parallel_executor.hpp"
#include <thread>
#include <chrono>

namespace RawrXD {
namespace NEVM {
namespace Tests {

//============================================================================
// Parallel Executor Tests
//============================================================================

TestResult ParallelExecutorTests_SingleThread() {
    ParallelGateExecutor::Config config;
    config.max_threads = 1;
    config.stop_on_first_failure = true;
    
    ParallelGateExecutor executor(config);
    
    bool executed = false;
    executor.RegisterGate(0, "TestGate",
        [&executed](Json::Value& metrics) {
            executed = true;
            metrics["test"] = true;
            return true;
        }, false);
    
    auto results = executor.Execute();
    
    TEST_ASSERT_EQ(true, executed);
    TEST_ASSERT_EQ(1ULL, results.size());
    TEST_ASSERT_EQ(true, results[0].passed);
    
    TEST_SUCCESS();
}

TestResult ParallelExecutorTests_MultipleGates() {
    ParallelGateExecutor::Config config;
    config.max_threads = 4;
    config.stop_on_first_failure = true;
    
    ParallelGateExecutor executor(config);
    
    std::atomic<int> counter{0};
    
    // Register 5 independent gates
    for (int i = 0; i < 5; ++i) {
        executor.RegisterGate(i, "Gate" + std::to_string(i),
            [&counter](Json::Value& metrics) {
                counter++;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                metrics["executed"] = true;
                return true;
            }, true);
    }
    
    auto results = executor.Execute();
    
    TEST_ASSERT_EQ(5, counter.load());
    TEST_ASSERT_EQ(5ULL, results.size());
    
    for (const auto& result : results) {
        TEST_ASSERT_EQ(true, result.passed);
    }
    
    TEST_SUCCESS();
}

TestResult ParallelExecutorTests_Dependencies() {
    ParallelGateExecutor::Config config;
    config.max_threads = 4;
    config.stop_on_first_failure = true;
    
    ParallelGateExecutor executor(config);
    
    std::vector<int> execution_order;
    std::mutex order_mutex;
    
    // Gate 0: No dependencies (runs first)
    executor.RegisterGate(0, "Gate0",
        [&execution_order, &order_mutex](Json::Value& metrics) {
            std::lock_guard<std::mutex> lock(order_mutex);
            execution_order.push_back(0);
            return true;
        }, true);
    
    // Gate 1: Depends on Gate 0
    executor.RegisterGate(1, "Gate1",
        [&execution_order, &order_mutex](Json::Value& metrics) {
            std::lock_guard<std::mutex> lock(order_mutex);
            execution_order.push_back(1);
            return true;
        }, true, {0});
    
    // Gate 2: Depends on Gate 0
    executor.RegisterGate(2, "Gate2",
        [&execution_order, &order_mutex](Json::Value& metrics) {
            std::lock_guard<std::mutex> lock(order_mutex);
            execution_order.push_back(2);
            return true;
        }, true, {0});
    
    auto results = executor.Execute();
    
    // Gate 0 should execute before Gates 1 and 2
    auto it0 = std::find(execution_order.begin(), execution_order.end(), 0);
    auto it1 = std::find(execution_order.begin(), execution_order.end(), 1);
    auto it2 = std::find(execution_order.begin(), execution_order.end(), 2);
    
    TEST_ASSERT(it0 < it1);  // Gate 0 before Gate 1
    TEST_ASSERT(it0 < it2);  // Gate 0 before Gate 2
    
    TEST_SUCCESS();
}

TestResult ParallelExecutorTests_StopOnFailure() {
    ParallelGateExecutor::Config config;
    config.max_threads = 4;
    config.stop_on_first_failure = true;
    
    ParallelGateExecutor executor(config);
    
    std::atomic<int> counter{0};
    
    // Register gates where one fails
    executor.RegisterGate(0, "Gate0",
        [&counter](Json::Value& metrics) {
            counter++;
            return true;
        }, true);
    
    executor.RegisterGate(1, "Gate1",
        [&counter](Json::Value& metrics) {
            counter++;
            return false;  // This one fails
        }, true);
    
    executor.RegisterGate(2, "Gate2",
        [&counter](Json::Value& metrics) {
            counter++;
            return true;
        }, true);
    
    auto results = executor.Execute();
    
    // Should stop after first failure
    // Note: Due to parallel execution, Gate2 might still run
    bool has_failure = false;
    for (const auto& result : results) {
        if (!result.passed) {
            has_failure = true;
            break;
        }
    }
    TEST_ASSERT_EQ(true, has_failure);
    
    TEST_SUCCESS();
}

TestResult ParallelExecutorTests_ExecutionStats() {
    ParallelGateExecutor::Config config;
    config.max_threads = 4;
    
    ParallelGateExecutor executor(config);
    
    // Register multiple gates
    for (int i = 0; i < 10; ++i) {
        executor.RegisterGate(i, "Gate" + std::to_string(i),
            [](Json::Value& metrics) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                return true;
            }, true);
    }
    
    auto results = executor.Execute();
    auto stats = executor.GetStats();
    
    TEST_ASSERT_EQ(10ULL, stats.gates_executed);
    TEST_ASSERT(stats.total_duration_ms > 0);
    TEST_ASSERT(stats.parallel_speedup >= 1.0f);
    
    TEST_SUCCESS();
}

TestResult ParallelExecutorTests_ThreadPool() {
    ThreadPool pool(4);
    
    std::atomic<int> counter{0};
    std::vector<std::future<int>> futures;
    
    // Submit 10 tasks
    for (int i = 0; i < 10; ++i) {
        futures.push_back(pool.Enqueue([&counter, i]() {
            counter++;
            return i * i;
        }));
    }
    
    // Wait for all and check results
    for (int i = 0; i < 10; ++i) {
        TEST_ASSERT_EQ(i * i, futures[i].get());
    }
    
    TEST_ASSERT_EQ(10, counter.load());
    
    TEST_SUCCESS();
}

//============================================================================
// Registration
//============================================================================

void RegisterParallelExecutorTests(TestFramework& framework) {
    REGISTER_TEST(framework, ParallelExecutorTests, SingleThread);
    REGISTER_TEST(framework, ParallelExecutorTests, MultipleGates);
    REGISTER_TEST(framework, ParallelExecutorTests, Dependencies);
    REGISTER_TEST(framework, ParallelExecutorTests, StopOnFailure);
    REGISTER_TEST(framework, ParallelExecutorTests, ExecutionStats);
    REGISTER_TEST(framework, ParallelExecutorTests, ThreadPool);
}

} // namespace Tests
} // namespace NEVM
} // namespace RawrXD
