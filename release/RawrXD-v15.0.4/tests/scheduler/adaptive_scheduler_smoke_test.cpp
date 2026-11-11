// adaptive_scheduler_smoke_test.cpp
// Phase C.2 Batch 1/5 — Pattern-Aware Scheduler Smoke Tests

#include <iostream>
#include <cassert>
#include <chrono>
#include <vector>
#include <string>
#include "../../src/scheduler/AdaptiveScheduler.hpp"
#include "../../src/emergent/EmergentPatterns.hpp"

using namespace Scheduler;
using namespace Emergent;

// Test result tracking
struct TestResult {
    std::string name;
    bool passed;
    std::string message;
    std::chrono::microseconds duration;
};

std::vector<TestResult> g_results;
int g_tests_passed = 0;
int g_tests_failed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) run_test(#name, test_##name)

void run_test(const std::string& name, std::function<void()> test_fn) {
    auto start = std::chrono::high_resolution_clock::now();
    
    try {
        test_fn();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        g_results.push_back({name, true, "PASSED", duration});
        g_tests_passed++;
        std::cout << "[PASS] " << name << " (" << duration.count() << " μs)" << std::endl;
    } catch (const std::exception& e) {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        g_results.push_back({name, false, e.what(), duration});
        g_tests_failed++;
        std::cout << "[FAIL] " << name << ": " << e.what() << std::endl;
    }
}

#define ASSERT_TRUE(expr) if (!(expr)) throw std::runtime_error("Assertion failed: " #expr)
#define ASSERT_FALSE(expr) if (expr) throw std::runtime_error("Assertion failed: NOT " #expr)
#define ASSERT_EQ(a, b) if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b)
#define ASSERT_GT(a, b) if ((a) <= (b)) throw std::runtime_error("Assertion failed: " #a " > " #b)
#define ASSERT_LT(a, b) if ((a) >= (b)) throw std::runtime_error("Assertion failed: " #a " < " #b)
#define ASSERT_NEAR(a, b, eps) if (std::abs((a) - (b)) > (eps)) throw std::runtime_error("Assertion failed: |" #a " - " #b "| < " #eps)

// ============================================================================
// Test Suite: Task Priority Calculation
// ============================================================================

TEST(task_priority_calculation) {
    AdaptiveSchedulerConfig config;
    TaskPriority priority;
    
    priority.stability_factor = 0.8;
    priority.confidence_factor = 0.9;
    priority.significance_factor = 0.7;
    priority.exploration_weight = 0.1;
    
    priority.CalculateTotal(config);
    
    ASSERT_GT(priority.total_priority, 0.0);
    ASSERT_LT(priority.total_priority, 1.0);
    ASSERT_GT(priority.execution_weight, 0.0);
    ASSERT_GT(priority.resource_weight, 0.0);
}

TEST(task_priority_normalization) {
    AdaptiveSchedulerConfig config;
    TaskPriority priority;
    
    // Test with extreme values
    priority.stability_factor = 2.0;  // Should be clamped
    priority.confidence_factor = 0.5;
    priority.significance_factor = 0.5;
    priority.exploration_weight = 0.1;
    
    priority.CalculateTotal(config);
    
    ASSERT_LE(priority.total_priority, 1.0);
    ASSERT_GE(priority.total_priority, 0.0);
}

// ============================================================================
// Test Suite: Pattern Priority Engine
// ============================================================================

TEST(pattern_priority_from_signature) {
    AdaptiveSchedulerConfig config;
    PatternPriorityEngine engine(config);
    SchedulerMetrics metrics;
    
    PatternSignature pattern;
    pattern.id = "test_pattern";
    pattern.type = PatternType::HARMONIC_ATTRACTOR;
    pattern.confidence = 0.85;
    pattern.metrics["stability"] = 0.9;
    pattern.metrics["significance"] = 0.75;
    
    TaskPriority priority = engine.CalculatePriority(pattern, metrics);
    
    ASSERT_GT(priority.total_priority, 0.0);
    ASSERT_GT(priority.stability_factor, 0.0);
    ASSERT_GT(priority.confidence_factor, 0.0);
}

TEST(pattern_priority_from_attractor) {
    AdaptiveSchedulerConfig config;
    PatternPriorityEngine engine(config);
    SchedulerMetrics metrics;
    
    HarmonicAttractor attractor;
    attractor.id = "attractor_1";
    attractor.stability_score = 0.9;
    attractor.convergence_rate = 0.85;
    attractor.amplitude = 1.0;
    
    TaskPriority priority = engine.CalculatePriority(attractor, metrics);
    
    ASSERT_GT(priority.total_priority, 0.0);
    ASSERT_GT(priority.stability_factor, 0.0);
    ASSERT_GT(priority.confidence_factor, 0.0);
}

TEST(pattern_priority_from_cluster) {
    AdaptiveSchedulerConfig config;
    PatternPriorityEngine engine(config);
    SchedulerMetrics metrics;
    
    SwarmCluster cluster;
    cluster.id = "cluster_1";
    cluster.cohesion_score = 0.8;
    cluster.performance_score = 0.75;
    cluster.agent_ids = {0, 1, 2, 3};
    
    TaskPriority priority = engine.CalculatePriority(cluster, metrics);
    
    ASSERT_GT(priority.total_priority, 0.0);
    ASSERT_GT(priority.stability_factor, 0.0);
}

TEST(pattern_priority_batch_calculation) {
    AdaptiveSchedulerConfig config;
    PatternPriorityEngine engine(config);
    SchedulerMetrics metrics;
    
    EmergentPatternReport report;
    
    HarmonicAttractor attractor;
    attractor.id = "attractor_1";
    attractor.stability_score = 0.9;
    report.harmonic_attractors.push_back(attractor);
    
    SwarmCluster cluster;
    cluster.id = "cluster_1";
    cluster.cohesion_score = 0.8;
    report.swarm_clusters.push_back(cluster);
    
    auto priorities = engine.CalculatePriorities(report, metrics);
    
    ASSERT_EQ(priorities.size(), 2);
    ASSERT_TRUE(priorities.count("attractor_1") > 0);
    ASSERT_TRUE(priorities.count("cluster_1") > 0);
}

// ============================================================================
// Test Suite: Worker Pool Manager
// ============================================================================

TEST(worker_pool_initialization) {
    AdaptiveSchedulerConfig config;
    WorkerPoolManager pool(config);
    
    pool.InitializeWorkers(4);
    
    ASSERT_EQ(pool.GetTotalWorkers(), 4);
    ASSERT_EQ(pool.GetAvailableWorkers(), 4);
}

TEST(worker_assignment) {
    AdaptiveSchedulerConfig config;
    WorkerPoolManager pool(config);
    
    pool.InitializeWorkers(4);
    
    ScheduledTask task;
    task.task_id = 1;
    task.min_workers = 2;
    task.max_workers = 4;
    task.priority.total_priority = 0.8;
    
    auto workers = pool.AssignWorkers(task);
    
    ASSERT_GT(workers.size(), 0);
    ASSERT_LE(workers.size(), 4);
    ASSERT_LT(pool.GetAvailableWorkers(), 4);
}

TEST(worker_release) {
    AdaptiveSchedulerConfig config;
    WorkerPoolManager pool(config);
    
    pool.InitializeWorkers(4);
    
    ScheduledTask task;
    task.task_id = 1;
    task.min_workers = 2;
    task.max_workers = 4;
    task.priority.total_priority = 0.8;
    
    auto workers = pool.AssignWorkers(task);
    uint32_t available_after_assign = pool.GetAvailableWorkers();
    
    pool.ReleaseWorkers(task.task_id);
    uint32_t available_after_release = pool.GetAvailableWorkers();
    
    ASSERT_GT(available_after_release, available_after_assign);
}

TEST(worker_scaling) {
    AdaptiveSchedulerConfig config;
    config.min_workers = 2;
    config.max_workers = 8;
    
    WorkerPoolManager pool(config);
    pool.InitializeWorkers(4);
    
    ASSERT_EQ(pool.GetTotalWorkers(), 4);
    
    pool.ScaleWorkers(6);
    ASSERT_EQ(pool.GetTotalWorkers(), 6);
    
    pool.ScaleWorkers(3);
    ASSERT_EQ(pool.GetTotalWorkers(), 3);
}

TEST(worker_utilization) {
    AdaptiveSchedulerConfig config;
    WorkerPoolManager pool(config);
    
    pool.InitializeWorkers(4);
    
    double utilization_empty = pool.GetWorkerUtilization();
    ASSERT_EQ(utilization_empty, 0.0);
    
    ScheduledTask task;
    task.task_id = 1;
    task.min_workers = 2;
    task.max_workers = 4;
    task.priority.total_priority = 0.8;
    
    pool.AssignWorkers(task);
    
    double utilization_busy = pool.GetWorkerUtilization();
    ASSERT_GT(utilization_busy, 0.0);
}

// ============================================================================
// Test Suite: Exploration Engine
// ============================================================================

TEST(exploration_rate_initial) {
    AdaptiveSchedulerConfig config;
    config.exploration_rate = 0.1;
    
    ExplorationEngine engine(config);
    
    double rate = engine.GetExplorationRate();
    ASSERT_NEAR(rate, 0.1, 0.01);
}

TEST(exploration_decision) {
    AdaptiveSchedulerConfig config;
    config.exploration_rate = 0.5; // High rate for testing
    
    ExplorationEngine engine(config);
    
    PatternSignature pattern;
    pattern.id = "test_pattern";
    pattern.confidence = 0.5;
    
    // With high exploration rate, should sometimes explore
    int explore_count = 0;
    for (int i = 0; i < 100; ++i) {
        if (engine.ShouldExplore(pattern)) {
            explore_count++;
        }
    }
    
    // Should explore roughly 50% of the time (with high rate)
    ASSERT_GT(explore_count, 20);
    ASSERT_LT(explore_count, 80);
}

TEST(exploration_stable_pattern) {
    AdaptiveSchedulerConfig config;
    config.exploration_rate = 0.5;
    config.convergence_threshold = 0.8;
    
    ExplorationEngine engine(config);
    
    PatternSignature pattern;
    pattern.id = "stable_pattern";
    pattern.confidence = 0.9; // High confidence
    
    // Stable patterns should be exploited more
    int explore_count = 0;
    for (int i = 0; i < 100; ++i) {
        if (engine.ShouldExplore(pattern)) {
            explore_count++;
        }
    }
    
    // Should explore less for stable patterns
    ASSERT_LT(explore_count, 50);
}

TEST(exploration_unstable_pattern) {
    AdaptiveSchedulerConfig config;
    config.exploration_rate = 0.1;
    config.instability_threshold = 0.3;
    
    ExplorationEngine engine(config);
    
    PatternSignature pattern;
    pattern.id = "unstable_pattern";
    pattern.confidence = 0.2; // Low confidence
    
    // Unstable patterns should be explored more
    int explore_count = 0;
    for (int i = 0; i < 100; ++i) {
        if (engine.ShouldExplore(pattern)) {
            explore_count++;
        }
    }
    
    // Should explore more for unstable patterns
    ASSERT_GT(explore_count, 10);
}

TEST(exploration_success_reporting) {
    AdaptiveSchedulerConfig config;
    config.exploration_rate = 0.5;
    config.exploration_decay = 0.9;
    
    ExplorationEngine engine(config);
    
    // Report success
    engine.ReportSuccess("pattern_1", 100.0);
    
    double rate_after_success = engine.GetExplorationRateForPattern("pattern_1");
    // Should be reduced after success
    ASSERT_LT(rate_after_success, 0.5);
}

TEST(exploration_failure_reporting) {
    AdaptiveSchedulerConfig config;
    config.exploration_rate = 0.1;
    
    ExplorationEngine engine(config);
    
    // Report failure
    engine.ReportFailure("pattern_1");
    
    double rate_after_failure = engine.GetExplorationRateForPattern("pattern_1");
    // Should be increased after failure
    ASSERT_GT(rate_after_failure, 0.1);
}

TEST(exploration_trial_spawning) {
    AdaptiveSchedulerConfig config;
    
    ExplorationEngine engine(config);
    
    ScheduledTask base_task;
    base_task.task_id = 1;
    base_task.min_workers = 2;
    base_task.max_workers = 4;
    
    auto trials = engine.SpawnExplorationTrials(base_task, 3);
    
    ASSERT_EQ(trials.size(), 3);
    
    // Each trial should have unique ID
    ASSERT_NE(trials[0].task_id, trials[1].task_id);
    ASSERT_NE(trials[1].task_id, trials[2].task_id);
}

// ============================================================================
// Test Suite: Scheduler Utils
// ============================================================================

TEST(utils_calculate_utility) {
    double utility = SchedulerUtils::CalculateUtility(0.9, 100.0, 0.95, 10.0);
    
    ASSERT_GT(utility, 0.0);
    // Utility should be (0.9 * 100 * 0.95) / 10 = 8.55
    ASSERT_NEAR(utility, 8.55, 0.1);
}

TEST(utils_worker_allocation) {
    uint32_t workers = SchedulerUtils::CalculateWorkerAllocation(0.8, 2, 8, 1.5);
    
    ASSERT_GE(workers, 2);
    ASSERT_LE(workers, 8);
    
    // Higher priority should get more workers
    uint32_t workers_high = SchedulerUtils::CalculateWorkerAllocation(0.9, 2, 8, 1.5);
    uint32_t workers_low = SchedulerUtils::CalculateWorkerAllocation(0.3, 2, 8, 1.5);
    
    ASSERT_GE(workers_high, workers_low);
}

TEST(utils_exponential_moving_average) {
    std::vector<double> values = {10.0, 20.0, 30.0};
    
    double ema = SchedulerUtils::ExponentialMovingAverage(values, 0.5);
    
    ASSERT_GT(ema, 10.0);
    ASSERT_LT(ema, 30.0);
}

TEST(utils_predict_tps) {
    std::vector<double> historical = {100.0, 110.0, 105.0};
    
    PatternSignature pattern;
    pattern.confidence = 0.8;
    
    double predicted = SchedulerUtils::PredictTPS(historical, pattern);
    
    ASSERT_GT(predicted, 0.0);
}

// ============================================================================
// Test Suite: Scheduler Metrics
// ============================================================================

TEST(metrics_initialization) {
    SchedulerMetrics metrics;
    
    ASSERT_EQ(metrics.tasks_submitted.load(), 0);
    ASSERT_EQ(metrics.tasks_running.load(), 0);
    ASSERT_EQ(metrics.tasks_completed.load(), 0);
    ASSERT_EQ(metrics.average_tps.load(), 0.0);
}

TEST(metrics_throughput_calculation) {
    SchedulerMetrics metrics;
    metrics.tasks_completed = 100;
    
    // Simulate time passing
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - metrics.start_time).count();
    
    if (elapsed > 0) {
        double throughput = metrics.GetThroughput();
        ASSERT_GE(throughput, 0.0);
    }
}

TEST(metrics_exploration_ratio) {
    SchedulerMetrics metrics;
    metrics.exploration_tasks = 30;
    metrics.exploitation_tasks = 70;
    
    double ratio = metrics.GetExplorationRatio();
    ASSERT_NEAR(ratio, 0.3, 0.01);
}

// ============================================================================
// Test Suite: Configuration
// ============================================================================

TEST(config_default_values) {
    AdaptiveSchedulerConfig config;
    
    ASSERT_GT(config.stability_weight, 0.0);
    ASSERT_GT(config.confidence_weight, 0.0);
    ASSERT_GT(config.significance_weight, 0.0);
    ASSERT_GT(config.exploration_weight, 0.0);
    
    ASSERT_GE(config.min_workers, 1u);
    ASSERT_GT(config.max_workers, config.min_workers);
}

TEST(config_exploration_bounds) {
    AdaptiveSchedulerConfig config;
    
    ASSERT_GE(config.exploration_rate, 0.0);
    ASSERT_LE(config.exploration_rate, 1.0);
    ASSERT_GE(config.min_exploration_rate, 0.0);
    ASSERT_LE(config.min_exploration_rate, config.exploration_rate);
}

// ============================================================================
// Test Suite: Integration
// ============================================================================

TEST(integration_scheduling_decision) {
    SchedulingDecision decision;
    decision.task_id = 1;
    decision.assigned_workers = {1, 2, 3};
    decision.pattern_id = "pattern_1";
    decision.pattern_stability = 0.9;
    decision.predicted_tps = 150.0;
    decision.predicted_convergence = 0.95;
    decision.utility_score = 0.85;
    
    ASSERT_EQ(decision.task_id, 1);
    ASSERT_EQ(decision.assigned_workers.size(), 3);
    ASSERT_GT(decision.utility_score, 0.0);
}

TEST(integration_worker_assignment_tracking) {
    AdaptiveSchedulerConfig config;
    WorkerPoolManager pool(config);
    
    pool.InitializeWorkers(4);
    
    // Assign workers
    ScheduledTask task;
    task.task_id = 1;
    task.min_workers = 2;
    task.max_workers = 4;
    task.priority.total_priority = 0.8;
    
    auto workers = pool.AssignWorkers(task);
    
    // Update performance
    for (uint32_t worker_id : workers) {
        pool.UpdateWorkerPerformance(worker_id, 100.0, true);
    }
    
    auto assignments = pool.GetWorkerAssignments();
    ASSERT_GE(assignments.size(), workers.size());
}

// ============================================================================
// Main
// ============================================================================

void print_header() {
    std::cout << "================================================================================" << std::endl;
    std::cout << "Phase C.2 Batch 1/5 — Pattern-Aware Scheduler Smoke Tests" << std::endl;
    std::cout << "================================================================================" << std::endl;
    std::cout << std::endl;
}

void print_summary() {
    std::cout << std::endl;
    std::cout << "================================================================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "================================================================================" << std::endl;
    std::cout << "Total:  " << (g_tests_passed + g_tests_failed) << std::endl;
    std::cout << "Passed: " << g_tests_passed << std::endl;
    std::cout << "Failed: " << g_tests_failed << std::endl;
    std::cout << std::endl;
    
    if (g_tests_failed == 0) {
        std::cout << "✅ ALL TESTS PASSED" << std::endl;
    } else {
        std::cout << "❌ SOME TESTS FAILED" << std::endl;
    }
    
    std::cout << "================================================================================" << std::endl;
}

int main(int argc, char* argv[]) {
    print_header();
    
    std::cout << "Running Task Priority Tests..." << std::endl;
    RUN_TEST(task_priority_calculation);
    RUN_TEST(task_priority_normalization);
    
    std::cout << std::endl << "Running Pattern Priority Engine Tests..." << std::endl;
    RUN_TEST(pattern_priority_from_signature);
    RUN_TEST(pattern_priority_from_attractor);
    RUN_TEST(pattern_priority_from_cluster);
    RUN_TEST(pattern_priority_batch_calculation);
    
    std::cout << std::endl << "Running Worker Pool Tests..." << std::endl;
    RUN_TEST(worker_pool_initialization);
    RUN_TEST(worker_assignment);
    RUN_TEST(worker_release);
    RUN_TEST(worker_scaling);
    RUN_TEST(worker_utilization);
    
    std::cout << std::endl << "Running Exploration Engine Tests..." << std::endl;
    RUN_TEST(exploration_rate_initial);
    RUN_TEST(exploration_decision);
    RUN_TEST(exploration_stable_pattern);
    RUN_TEST(exploration_unstable_pattern);
    RUN_TEST(exploration_success_reporting);
    RUN_TEST(exploration_failure_reporting);
    RUN_TEST(exploration_trial_spawning);
    
    std::cout << std::endl << "Running Scheduler Utils Tests..." << std::endl;
    RUN_TEST(utils_calculate_utility);
    RUN_TEST(utils_worker_allocation);
    RUN_TEST(utils_exponential_moving_average);
    RUN_TEST(utils_predict_tps);
    
    std::cout << std::endl << "Running Metrics Tests..." << std::endl;
    RUN_TEST(metrics_initialization);
    RUN_TEST(metrics_throughput_calculation);
    RUN_TEST(metrics_exploration_ratio);
    
    std::cout << std::endl << "Running Configuration Tests..." << std::endl;
    RUN_TEST(config_default_values);
    RUN_TEST(config_exploration_bounds);
    
    std::cout << std::endl << "Running Integration Tests..." << std::endl;
    RUN_TEST(integration_scheduling_decision);
    RUN_TEST(integration_worker_assignment_tracking);
    
    print_summary();
    
    return g_tests_failed > 0 ? 1 : 0;
}
