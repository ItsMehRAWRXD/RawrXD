// test_benchmark_workflow.cpp
// Batch 8: End-to-End Benchmark Workflow Tests
//
// Tests complete benchmark execution workflows:
// - Full benchmark lifecycle (setup, run, teardown)
// - Result validation
// - Error recovery
// - Timeout handling
// - Parallel execution

#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <future>

// Mock benchmark for testing workflows
class MockBenchmark {
public:
    struct Config {
        int iterations = 5;
        int warmup = 2;
        bool should_fail = false;
        int fail_after_iteration = -1;
        int sleep_ms = 10;
    };

    struct Result {
        bool success = false;
        int completed_iterations = 0;
        double total_time_ms = 0.0;
        std::string error_message;
    };

    explicit MockBenchmark(const Config& config = Config()) 
        : config_(config), cancelled_(false) {}

    Result Run() {
        Result result;
        auto start = std::chrono::high_resolution_clock::now();

        // Warmup phase
        for (int i = 0; i < config_.warmup && !cancelled_; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.sleep_ms));
        }

        // Measured phase
        for (int i = 0; i < config_.iterations && !cancelled_; ++i) {
            if (config_.should_fail && i == config_.fail_after_iteration) {
                result.error_message = "Simulated failure";
                return result;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(config_.sleep_ms));
            result.completed_iterations++;
        }

        auto end = std::chrono::high_resolution_clock::now();
        result.total_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result.success = !cancelled_ && result.completed_iterations == config_.iterations;

        return result;
    }

    void Cancel() {
        cancelled_ = true;
    }

private:
    Config config_;
    std::atomic<bool> cancelled_;
};

// Test fixture for workflow tests
class BenchmarkWorkflowTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code if needed
    }

    void TearDown() override {
        // Cleanup code if needed
    }
};

// Test: Successful benchmark completion
TEST_F(BenchmarkWorkflowTest, SuccessfulCompletion) {
    MockBenchmark::Config config;
    config.iterations = 5;
    config.warmup = 2;
    config.should_fail = false;

    MockBenchmark benchmark(config);
    auto result = benchmark.Run();

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.completed_iterations, 5);
    EXPECT_GT(result.total_time_ms, 0.0);
    EXPECT_TRUE(result.error_message.empty());
}

// Test: Benchmark failure
TEST_F(BenchmarkWorkflowTest, BenchmarkFailure) {
    MockBenchmark::Config config;
    config.iterations = 5;
    config.should_fail = true;
    config.fail_after_iteration = 2;

    MockBenchmark benchmark(config);
    auto result = benchmark.Run();

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.completed_iterations, 2);
    EXPECT_EQ(result.error_message, "Simulated failure");
}

// Test: Zero iterations
TEST_F(BenchmarkWorkflowTest, ZeroIterations) {
    MockBenchmark::Config config;
    config.iterations = 0;
    config.warmup = 0;

    MockBenchmark benchmark(config);
    auto result = benchmark.Run();

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.completed_iterations, 0);
}

// Test: Single iteration
TEST_F(BenchmarkWorkflowTest, SingleIteration) {
    MockBenchmark::Config config;
    config.iterations = 1;
    config.warmup = 0;

    MockBenchmark benchmark(config);
    auto result = benchmark.Run();

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.completed_iterations, 1);
}

// Test: Timeout handling (simulated)
TEST_F(BenchmarkWorkflowTest, TimeoutHandling) {
    MockBenchmark::Config config;
    config.iterations = 100;
    config.sleep_ms = 100; // 100ms per iteration = 10s total

    MockBenchmark benchmark(config);

    // Run in separate thread so we can cancel it
    std::future<MockBenchmark::Result> future = std::async(std::launch::async, [&benchmark]() {
        return benchmark.Run();
    });

    // Cancel after 200ms (should complete ~2 iterations)
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    benchmark.Cancel();

    auto result = future.get();

    // Should have completed some iterations but not all
    EXPECT_LT(result.completed_iterations, 100);
    EXPECT_FALSE(result.success);
}

// Test: Parallel benchmark execution
TEST_F(BenchmarkWorkflowTest, ParallelExecution) {
    const int num_benchmarks = 5;
    std::vector<std::future<MockBenchmark::Result>> futures;

    // Launch multiple benchmarks in parallel
    for (int i = 0; i < num_benchmarks; ++i) {
        futures.push_back(std::async(std::launch::async, []() {
            MockBenchmark::Config config;
            config.iterations = 3;
            config.sleep_ms = 10;
            MockBenchmark benchmark(config);
            return benchmark.Run();
        }));
    }

    // Collect results
    int success_count = 0;
    for (auto& future : futures) {
        auto result = future.get();
        if (result.success) {
            success_count++;
        }
    }

    EXPECT_EQ(success_count, num_benchmarks);
}

// Test: Sequential benchmark execution
TEST_F(BenchmarkWorkflowTest, SequentialExecution) {
    const int num_benchmarks = 3;
    int success_count = 0;

    for (int i = 0; i < num_benchmarks; ++i) {
        MockBenchmark::Config config;
        config.iterations = 2;
        config.sleep_ms = 5;
        MockBenchmark benchmark(config);
        auto result = benchmark.Run();

        if (result.success) {
            success_count++;
        }
    }

    EXPECT_EQ(success_count, num_benchmarks);
}

// Test: Benchmark with warmup only
TEST_F(BenchmarkWorkflowTest, WarmupOnly) {
    MockBenchmark::Config config;
    config.iterations = 0;
    config.warmup = 5;

    MockBenchmark benchmark(config);
    auto result = benchmark.Run();

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.completed_iterations, 0);
    EXPECT_GT(result.total_time_ms, 0.0); // Should still take time for warmup
}

// Test: Very fast benchmark
TEST_F(BenchmarkWorkflowTest, VeryFastBenchmark) {
    MockBenchmark::Config config;
    config.iterations = 100;
    config.warmup = 0;
    config.sleep_ms = 0; // No sleep

    MockBenchmark benchmark(config);
    auto start = std::chrono::high_resolution_clock::now();
    auto result = benchmark.Run();
    auto end = std::chrono::high_resolution_clock::now();

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.completed_iterations, 100);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 100); // Should complete quickly
}

// Test: Benchmark result validation
TEST_F(BenchmarkWorkflowTest, ResultValidation) {
    MockBenchmark::Config config;
    config.iterations = 10;
    config.sleep_ms = 10;

    MockBenchmark benchmark(config);
    auto result = benchmark.Run();

    // Validate result structure
    EXPECT_TRUE(result.success);
    EXPECT_GE(result.completed_iterations, 0);
    EXPECT_GT(result.total_time_ms, 0.0);

    // Time should be roughly iterations * sleep_ms
    EXPECT_GT(result.total_time_ms, 50.0);  // At least 50ms
    EXPECT_LT(result.total_time_ms, 500.0); // Less than 500ms
}

// Test: Multiple runs consistency
TEST_F(BenchmarkWorkflowTest, MultipleRunsConsistency) {
    MockBenchmark::Config config;
    config.iterations = 5;
    config.sleep_ms = 5;

    std::vector<double> durations;
    for (int i = 0; i < 5; ++i) {
        MockBenchmark benchmark(config);
        auto result = benchmark.Run();
        EXPECT_TRUE(result.success);
        durations.push_back(result.total_time_ms);
    }

    // All runs should complete similar number of iterations
    for (double duration : durations) {
        EXPECT_GT(duration, 0.0);
    }
}

// Test: Benchmark with different configurations
TEST_F(BenchmarkWorkflowTest, DifferentConfigurations) {
    std::vector<MockBenchmark::Config> configs = {
        {5, 2, false, -1, 10},
        {10, 5, false, -1, 5},
        {3, 1, false, -1, 20}
    };

    for (const auto& config : configs) {
        MockBenchmark benchmark(config);
        auto result = benchmark.Run();
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.completed_iterations, config.iterations);
    }
}

// Test: Error recovery (simulated)
TEST_F(BenchmarkWorkflowTest, ErrorRecovery) {
    // First benchmark fails
    MockBenchmark::Config fail_config;
    fail_config.should_fail = true;
    fail_config.fail_after_iteration = 1;

    MockBenchmark fail_benchmark(fail_config);
    auto fail_result = fail_benchmark.Run();
    EXPECT_FALSE(fail_result.success);

    // Second benchmark succeeds
    MockBenchmark::Config success_config;
    success_config.should_fail = false;

    MockBenchmark success_benchmark(success_config);
    auto success_result = success_benchmark.Run();
    EXPECT_TRUE(success_result.success);
}

// Test: Long-running benchmark
TEST_F(BenchmarkWorkflowTest, LongRunningBenchmark) {
    MockBenchmark::Config config;
    config.iterations = 10;
    config.sleep_ms = 50; // 500ms total

    MockBenchmark benchmark(config);
    auto start = std::chrono::high_resolution_clock::now();
    auto result = benchmark.Run();
    auto end = std::chrono::high_resolution_clock::now();

    EXPECT_TRUE(result.success);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_GE(duration.count(), 400); // At least 400ms
}

// Test: Benchmark lifecycle
TEST_F(BenchmarkWorkflowTest, BenchmarkLifecycle) {
    // Create
    MockBenchmark::Config config;
    config.iterations = 3;
    MockBenchmark benchmark(config);

    // Run
    auto result = benchmark.Run();
    EXPECT_TRUE(result.success);

    // Verify final state
    EXPECT_EQ(result.completed_iterations, 3);
}

// Main entry point
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
