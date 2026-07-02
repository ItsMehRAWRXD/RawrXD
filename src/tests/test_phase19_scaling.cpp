// =============================================================================
// test_phase19_scaling.cpp
// Phase 19: Scaling & Concurrency Optimization - Test Suite
// Validates thread pool, batch processing, and throughput scaling
// =============================================================================

#include "../core/sovereign_thread_pool.h"
#include "../core/sovereign_batch_processor.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <math.h>
#include <atomic>

// =============================================================================
// Test Configuration
// =============================================================================

#define TEST_DURATION_MS 5000
#define MIN_SPEEDUP_TARGET 1.5  // 50% improvement with threading

// =============================================================================
// Test Results
// =============================================================================

struct TestResult {
    const char* name;
    int passed;
    double duration_ms;
    const char* message;
};

static TestResult g_results[32];
static int g_num_results = 0;

void record_result(const char* name, int passed, double duration_ms, const char* message) {
    if (g_num_results < 32) {
        g_results[g_num_results++] = {name, passed, duration_ms, message};
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

double get_time_ms() {
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart * 1000.0 / freq.QuadPart;
}

// =============================================================================
// Test 1: Thread Pool Basic Functionality
// =============================================================================

static std::atomic<int> g_counter{0};

void increment_task(void* data, uint32_t thread_id) {
    (void)data;
    (void)thread_id;
    g_counter.fetch_add(1, std::memory_order_relaxed);
}

void test_thread_pool_basic() {
    printf("\n[Test 1] Thread Pool Basic Functionality\n");
    
    double start = get_time_ms();
    
    // Create thread pool
    SovereignThreadPoolHandle pool = Sovereign_ThreadPool_Init(4, 0);
    if (!pool) {
        record_result("ThreadPool_Init", 0, 0, "Failed to create thread pool");
        return;
    }
    
    // Submit tasks
    g_counter.store(0);
    const int NUM_TASKS = 1000;
    
    for (int i = 0; i < NUM_TASKS; i++) {
        SovereignTask task = {
            increment_task,
            nullptr,
            0,
            0
        };
        Sovereign_ThreadPool_Submit(pool, &task);
    }
    
    // Wait for completion
    Sovereign_ThreadPool_WaitAll(pool);
    
    int counter_value = g_counter.load();
    int init_passed = (counter_value == NUM_TASKS) ? 1 : 0;
    
    // Get stats
    SovereignThreadPoolStats stats;
    Sovereign_ThreadPool_GetStats(pool, &stats);
    
    Sovereign_ThreadPool_Shutdown(pool);
    
    double duration = get_time_ms() - start;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Tasks: %d/%d completed, Stolen: %llu, Throughput: %.2f tasks/sec",
        counter_value, NUM_TASKS, stats.tasks_stolen, stats.throughput_tasks_per_sec);
    
    record_result("ThreadPool_Basic", init_passed, duration, msg);
    
    printf("  %s\n", init_passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 2: Thread Pool Scaling
// =============================================================================

void heavy_compute_task(void* data, uint32_t thread_id) {
    (void)data;
    (void)thread_id;
    
    // Simulate compute-heavy work
    volatile double sum = 0;
    for (int i = 0; i < 100000; i++) {
        sum += sin((double)i) * cos((double)i);
    }
}

void test_thread_pool_scaling() {
    printf("\n[Test 2] Thread Pool Scaling\n");
    
    const int NUM_TASKS = 100;
    
    // Single-threaded baseline
    double single_start = get_time_ms();
    for (int i = 0; i < NUM_TASKS; i++) {
        heavy_compute_task(nullptr, 0);
    }
    double single_duration = get_time_ms() - single_start;
    
    // Multi-threaded
    SovereignThreadPoolHandle pool = Sovereign_ThreadPool_Init(0, 0);  // Auto-detect threads
    if (!pool) {
        record_result("ThreadPool_Scaling", 0, 0, "Failed to create thread pool");
        return;
    }
    
    double multi_start = get_time_ms();
    
    for (int i = 0; i < NUM_TASKS; i++) {
        SovereignTask task = {
            heavy_compute_task,
            nullptr,
            0,
            0
        };
        Sovereign_ThreadPool_Submit(pool, &task);
    }
    
    Sovereign_ThreadPool_WaitAll(pool);
    double multi_duration = get_time_ms() - multi_start;
    
    SovereignThreadPoolStats stats;
    Sovereign_ThreadPool_GetStats(pool, &stats);
    
    Sovereign_ThreadPool_Shutdown(pool);
    
    double speedup = single_duration / multi_duration;
    int passed = (speedup >= MIN_SPEEDUP_TARGET) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg),
        "Single: %.1fms, Multi: %.1fms, Speedup: %.2fx (target: %.1fx)",
        single_duration, multi_duration, speedup, MIN_SPEEDUP_TARGET);
    
    record_result("ThreadPool_Scaling", passed, multi_duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 3: Batch Processor Basic
// =============================================================================

void test_batch_processor_basic() {
    printf("\n[Test 3] Batch Processor Basic\n");
    
    double start = get_time_ms();
    
    SovereignThreadPoolHandle pool = Sovereign_ThreadPool_Init(4, 0);
    if (!pool) {
        record_result("BatchProcessor_Init", 0, 0, "Failed to create thread pool");
        return;
    }
    
    SovereignBatchConfig config;
    config.max_batch_size = 32;
    config.max_sequence_length = 512;
    config.timeout_us = 1000;
    config.padding_token_id = 0;
    config.padding_scale = 1.0f;
    config.enable_dynamic_batching = 1;
    config.enable_priority_queue = 1;
    
    SovereignBatchProcessorHandle processor = Sovereign_BatchProcessor_Init(pool, &config);
    if (!processor) {
        Sovereign_ThreadPool_Shutdown(pool);
        record_result("BatchProcessor_Init", 0, 0, "Failed to create batch processor");
        return;
    }
    
    // Submit requests
    const int NUM_REQUESTS = 100;
    
    for (int i = 0; i < NUM_REQUESTS; i++) {
        SovereignBatchRequest req;
        req.request_id = (uint32_t)i;
        req.input_data = nullptr;
        req.output_data = nullptr;
        req.seq_length = 128 + (uint32_t)(i % 128);  // Variable length
        req.batch_size = 1;
        req.priority = (uint32_t)(i % 4);
        req.submit_time = (uint64_t)get_time_ms();
        req.deadline = 0;
        
        Sovereign_BatchProcessor_Submit(processor, &req, SOVEREIGN_BATCH_ATTENTION_QK);
    }
    
    // Wait for all
    Sovereign_BatchProcessor_WaitAll(processor);
    
    // Get stats
    SovereignBatchStats stats;
    Sovereign_BatchProcessor_GetStats(processor, &stats);
    
    Sovereign_BatchProcessor_Shutdown(processor);
    Sovereign_ThreadPool_Shutdown(pool);
    
    double duration = get_time_ms() - start;
    
    int passed = (stats.requests_processed >= NUM_REQUESTS) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg),
        "Batches: %llu, Requests: %llu, Avg Batch: %.1f, Efficiency: %.1f%%",
        stats.batches_processed, stats.requests_processed,
        stats.avg_batch_size, stats.utilization_percent);
    
    record_result("BatchProcessor_Basic", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 4: Batch Efficiency
// =============================================================================

void test_batch_efficiency() {
    printf("\n[Test 4] Batch Efficiency\n");
    
    // Test sequence packing efficiency
    uint32_t lengths[] = {100, 150, 200, 120, 180};
    uint32_t count = 5;
    uint32_t padded_length = 200;  // Max length
    
    float efficiency = Sovereign_BatchProcessor_CalculateEfficiency(
        lengths, count, padded_length);
    
    // Expected: (100+150+200+120+180) / (200*5) = 750/1000 = 0.75
    float expected = 0.75f;
    float tolerance = 0.01f;
    
    int passed = (fabs(efficiency - expected) < tolerance) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg),
        "Efficiency: %.2f (expected: %.2f, tolerance: %.2f)",
        efficiency, expected, tolerance);
    
    record_result("Batch_Efficiency", passed, 0, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 5: NUMA Awareness
// =============================================================================

void test_numa_awareness() {
    printf("\n[Test 5] NUMA Awareness\n");
    
    uint32_t hw_threads = Sovereign_ThreadPool_GetHardwareThreads();
    uint32_t numa_nodes = Sovereign_ThreadPool_GetNumaNodes();
    
    printf("  Hardware Threads: %u\n", hw_threads);
    printf("  NUMA Nodes: %u\n", numa_nodes);
    
    int passed = (hw_threads > 0 && numa_nodes >= 1) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg),
        "Threads: %u, NUMA Nodes: %u", hw_threads, numa_nodes);
    
    record_result("NUMA_Awareness", passed, 0, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Phase 19: Scaling & Concurrency Test Suite                      ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    double total_start = get_time_ms();
    
    // Run all tests
    test_thread_pool_basic();
    test_thread_pool_scaling();
    test_batch_processor_basic();
    test_batch_efficiency();
    test_numa_awareness();
    
    double total_duration = get_time_ms() - total_start;
    
    // Summary
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Test Summary                                                    ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    int passed = 0, failed = 0;
    for (int i = 0; i < g_num_results; i++) {
        printf("[%s] %-30s %.1fms\n",
            g_results[i].passed ? "PASS" : "FAIL",
            g_results[i].name,
            g_results[i].duration_ms);
        printf("      %s\n\n", g_results[i].message);
        
        if (g_results[i].passed) passed++;
        else failed++;
    }
    
    printf("────────────────────────────────────────────────────────────────\n");
    printf("Total: %d tests, %d passed, %d failed\n", g_num_results, passed, failed);
    printf("Duration: %.1f ms\n", total_duration);
    printf("────────────────────────────────────────────────────────────────\n");
    
    if (failed == 0) {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  ALL TESTS PASSED - Phase 19 Ready for Production              ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        return 0;
    } else {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  SOME TESTS FAILED - Review before deployment                  ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
}
