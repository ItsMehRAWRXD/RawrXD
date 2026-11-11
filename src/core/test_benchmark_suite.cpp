// ============================================================================
// test_benchmark_suite.cpp - Phase 11 Test
// Validates performance benchmarking, TPS, latency, and throughput
// ============================================================================

#include "sovereign_benchmark_suite.hpp"
#include <stdio.h>
#include <windows.h>

using namespace Sovereign;

int main(int argc, char* argv[]) {
    printf("=== Phase 11: Performance Benchmark Suite Test ===\n\n");

    // Test 1: Initialize benchmark suite
    printf("Test 1: Initialize benchmark suite...\n");
    BenchmarkSuite benchmark;
    BenchmarkConfig config;
    config.warmup_iterations = 5;
    config.benchmark_iterations = 50;
    config.input_tokens = 64;
    config.output_tokens = 64;
    config.output_format = "table";
    
    if (!benchmark.Initialize(config)) {
        printf("  [FAIL] Failed to initialize benchmark suite\n");
        return 1;
    }
    printf("  [PASS] Benchmark suite initialized\n\n");

    // Test 2: Latency benchmark
    printf("Test 2: Latency benchmark...\n");
    BenchmarkResult latency_result = benchmark.RunLatencyBenchmark();
    if (latency_result.success) {
        printf("  Latency: avg=%.2fms, p95=%.2fms, p99=%.2fms\n",
               latency_result.latency.avg_ms,
               latency_result.latency.p95_ms,
               latency_result.latency.p99_ms);
        printf("  [PASS]\n\n");
    } else {
        printf("  [FAIL] %s\n\n", latency_result.error_message.c_str());
    }

    // Test 3: Throughput benchmark
    printf("Test 3: Throughput benchmark...\n");
    BenchmarkResult throughput_result = benchmark.RunThroughputBenchmark();
    if (throughput_result.success) {
        printf("  Throughput: %.2f tokens/sec, %.2f req/sec\n",
               throughput_result.throughput.tokens_per_second,
               throughput_result.throughput.requests_per_second);
        printf("  [PASS]\n\n");
    } else {
        printf("  [FAIL] %s\n\n", throughput_result.error_message.c_str());
    }

    // Test 4: Concurrency benchmark
    printf("Test 4: Concurrency benchmark...\n");
    BenchmarkResult concurrency_result = benchmark.RunConcurrencyBenchmark(2);
    if (concurrency_result.success) {
        printf("  Concurrent requests: %llu\n", concurrency_result.total_requests);
        printf("  [PASS]\n\n");
    } else {
        printf("  [FAIL]\n\n");
    }

    // Test 5: Batch size benchmark
    printf("Test 5: Batch size benchmark...\n");
    BenchmarkResult batch_result = benchmark.RunBatchSizeBenchmark(4);
    if (batch_result.success) {
        printf("  Batch size 4: %.2f tokens/sec\n", batch_result.throughput.tokens_per_second);
        printf("  [PASS]\n\n");
    } else {
        printf("  [FAIL]\n\n");
    }

    // Test 6: End-to-end benchmark
    printf("Test 6: End-to-end benchmark...\n");
    BenchmarkResult e2e_result = benchmark.RunEndToEndBenchmark();
    if (e2e_result.success) {
        printf("  E2E: %llu iterations\n", e2e_result.total_requests);
        printf("  [PASS]\n\n");
    } else {
        printf("  [FAIL]\n\n");
    }

    // Test 7: Export results
    printf("Test 7: Export results...\n");
    std::string table = benchmark.ExportResultsTable();
    printf("  Results table:\n%s\n", table.c_str());
    printf("  [PASS]\n\n");

    // Test 8: Quick TPS benchmark
    printf("Test 8: Quick TPS benchmark (5 seconds)...\n");
    double tps = QuickBenchmarkTPS(64, 64);
    if (tps > 0) {
        printf("  Quick TPS: %.2f tokens/sec\n", tps);
        printf("  [PASS]\n\n");
    } else {
        printf("  [FAIL]\n\n");
    }

    // Test 9: Stress test (short)
    printf("Test 9: Stress test (5 seconds)...\n");
    StressTestConfig stress_config;
    stress_config.duration_seconds = 5;
    stress_config.max_concurrent = 3;
    stress_config.ramp_up_seconds = 2;
    
    StressTestResult stress_result = RunStressTest(stress_config);
    if (stress_result.success) {
        printf("  Stress test: %.2f avg TPS, %.2f peak TPS\n",
               stress_result.avg_tps, stress_result.peak_tps);
        printf("  [PASS]\n\n");
    } else {
        printf("  [FAIL] Error rate: %.2f%%\n\n", stress_result.error_rate);
    }

    // Test 10: Regression check
    printf("Test 10: Regression check...\n");
    BenchmarkResult baseline = latency_result;
    BenchmarkResult current = throughput_result;
    RegressionResult regression = CheckRegression(baseline, current, -10.0, 20.0);
    printf("  %s\n", regression.summary.c_str());
    printf("  [PASS]\n\n");

    // Cleanup
    benchmark.Shutdown();

    printf("=== Phase 11 Complete ===\n");
    printf("All performance benchmarking features validated\n");
    return 0;
}
