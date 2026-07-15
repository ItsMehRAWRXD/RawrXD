/**
 * seg_runtime_cost_profiler_smoke_test.cpp
 * 
 * Phase C.0 Batch 2/5: Runtime Cost Profiler Validation
 * 
 * Tests per-component cost attribution:
 * - Component lifecycle tracking
 * - Cost aggregation
 * - Regression detection
 * - Scheduler integration
 */

#include "../src/seg/SEGRuntimeCostProfiler.hpp"
#include <iostream>
#include <sstream>
#include <fstream>

using namespace Sovereign::SEG;

// Test framework
int testsPassed = 0;
int testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "  Running " << #name << "... "; \
    try { \
        test_##name(); \
        std::cout << "PASSED" << std::endl; \
        testsPassed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << std::endl; \
        testsFailed++; \
    } catch (...) { \
        std::cout << "FAILED: Unknown exception" << std::endl; \
        testsFailed++; \
    } \
} while(0)

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << #expr; \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))
#define ASSERT_GT(a, b) ASSERT_TRUE((a) > (b))
#define ASSERT_LT(a, b) ASSERT_TRUE((a) < (b))

// ============================================================================
// Test: Basic component profiling
// ============================================================================

TEST(profile_single_component) {
    SEGRuntimeCostProfiler profiler;
    
    profiler.StartExecution("test-1");
    
    auto* cost = profiler.StartComponent(ComponentType::EngineCycle, "RunUnityCycle");
    ASSERT_TRUE(cost != nullptr);
    
    // Simulate work
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    
    profiler.EndComponent(cost, true);
    
    auto* profile = profiler.EndExecution();
    ASSERT_TRUE(profile != nullptr);
    
    ASSERT_EQ(profile->componentCosts.size(), 1u);
    ASSERT_GT(profile->componentCosts[0].durationMs, 0.0);
}

TEST(profile_multiple_components) {
    SEGRuntimeCostProfiler profiler;
    
    profiler.StartExecution("test-2");
    
    // Profile graph build
    auto* graphCost = profiler.StartComponent(ComponentType::GraphBuild, "BuildGraph");
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    profiler.EndComponent(graphCost, true);
    
    // Profile planner
    auto* plannerCost = profiler.StartComponent(ComponentType::Planner, "CreatePlan");
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
    profiler.EndComponent(plannerCost, true);
    
    // Profile engine cycle
    auto* cycleCost = profiler.StartComponent(ComponentType::EngineCycle, "RunUnityCycle");
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    profiler.EndComponent(cycleCost, true);
    
    auto* profile = profiler.EndExecution();
    ASSERT_TRUE(profile != nullptr);
    
    ASSERT_EQ(profile->componentCosts.size(), 3u);
}

// ============================================================================
// Test: Component statistics
// ============================================================================

TEST(component_statistics_aggregation) {
    SEGRuntimeCostProfiler profiler;
    
    // Run multiple executions to build stats
    for (int i = 0; i < 5; i++) {
        profiler.StartExecution("test-" + std::to_string(i));
        
        auto* cost = profiler.StartComponent(ComponentType::EngineCycle, "RunUnityCycle");
        std::this_thread::sleep_for(std::chrono::milliseconds(5 + i));
        profiler.EndComponent(cost, true);
        
        profiler.EndExecution();
    }
    
    auto stats = profiler.GetStatsForType(ComponentType::EngineCycle);
    
    ASSERT_EQ(stats.executionCount, 5u);
    ASSERT_EQ(stats.successCount, 5u);
    ASSERT_EQ(stats.failureCount, 0u);
    ASSERT_GT(stats.avgDurationMs, 0.0);
    ASSERT_GT(stats.totalDurationMs, 0.0);
    ASSERT_EQ(stats.successRate, 1.0);
}

TEST(failure_tracking) {
    SEGRuntimeCostProfiler profiler;
    
    profiler.StartExecution("test-fail");
    
    auto* cost = profiler.StartComponent(ComponentType::SwarmTask, "ComputeOrderTopology");
    profiler.EndComponent(cost, false, "Task failed");
    
    auto* profile = profiler.EndExecution();
    
    ASSERT_EQ(profile->componentCosts[0].success, false);
    ASSERT_EQ(profile->componentCosts[0].errorMessage, "Task failed");
    
    auto stats = profiler.GetStatsForType(ComponentType::SwarmTask);
    ASSERT_EQ(stats.failureCount, 1u);
    ASSERT_LT(stats.successRate, 1.0);
}

// ============================================================================
// Test: Convergence tracking
// ============================================================================

TEST(convergence_tracking) {
    SEGRuntimeCostProfiler profiler;
    profiler.SetConvergenceTrackingEnabled(true);
    
    profiler.StartExecution("test-conv");
    
    auto* cost = profiler.StartComponent(ComponentType::EngineCycle, "RunUnityCycle");
    profiler.RecordConvergenceGain(cost, 0.07);
    profiler.RecordConvergenceDelta(cost, 0.85);
    profiler.EndComponent(cost, true);
    
    profiler.EndExecution();
    
    auto stats = profiler.GetStatsForType(ComponentType::EngineCycle);
    ASSERT_GT(stats.avgConvergenceGain, 0.0);
}

// ============================================================================
// Test: History management
// ============================================================================

TEST(history_management) {
    SEGRuntimeCostProfiler profiler;
    profiler.SetMaxHistorySize(3);
    
    // Add 5 executions
    for (int i = 0; i < 5; i++) {
        profiler.StartExecution("test-" + std::to_string(i));
        auto* cost = profiler.StartComponent(ComponentType::EngineCycle, "RunUnityCycle");
        profiler.EndComponent(cost, true);
        profiler.EndExecution();
    }
    
    // History should be limited to 3
    ASSERT_EQ(profiler.GetHistorySize(), 3u);
    
    // Clear history
    profiler.ClearHistory();
    ASSERT_EQ(profiler.GetHistorySize(), 0u);
}

// ============================================================================
// Test: Expensive component detection
// ============================================================================

TEST(expensive_component_detection) {
    SEGRuntimeCostProfiler profiler;
    
    // Add fast component
    profiler.StartExecution("test-fast");
    auto* fastCost = profiler.StartComponent(ComponentType::Telemetry, "QuickTelemetry");
    profiler.EndComponent(fastCost, true);
    profiler.EndExecution();
    
    // Add slow component
    profiler.StartExecution("test-slow");
    auto* slowCost = profiler.StartComponent(ComponentType::EngineCycle, "SlowCycle");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    profiler.EndComponent(slowCost, true);
    profiler.EndExecution();
    
    auto expensive = profiler.GetExpensiveComponents(10.0); // threshold 10ms
    
    // Should detect the slow component
    ASSERT_TRUE(expensive.size() > 0);
}

// ============================================================================
// Test: Scheduler integration
// ============================================================================

TEST(scheduler_cost_estimates) {
    SEGRuntimeCostProfiler profiler;
    
    // Build up some history
    for (int i = 0; i < 3; i++) {
        profiler.StartExecution("test-" + std::to_string(i));
        auto* cost = profiler.StartComponent(ComponentType::EngineCycle, "RunUnityCycle");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        profiler.EndComponent(cost, true);
        profiler.EndExecution();
    }
    
    double costEstimate = profiler.GetComponentCostEstimate(ComponentType::EngineCycle);
    double successRate = profiler.GetComponentSuccessRate(ComponentType::EngineCycle);
    double convEfficiency = profiler.GetComponentConvergenceEfficiency(ComponentType::EngineCycle);
    
    ASSERT_GT(costEstimate, 0.0);
    ASSERT_EQ(successRate, 1.0);
}

// ============================================================================
// Test: JSON export
// ============================================================================

TEST(json_export) {
    SEGRuntimeCostProfiler profiler;
    
    profiler.StartExecution("test-export");
    auto* cost = profiler.StartComponent(ComponentType::EngineCycle, "RunUnityCycle");
    profiler.EndComponent(cost, true);
    profiler.EndExecution();
    
    std::string json = profiler.ExportToJson();
    
    ASSERT_TRUE(json.find("runtime_cost_profiler") != std::string::npos);
    ASSERT_TRUE(json.find("execution_count") != std::string::npos);
}

TEST(file_export) {
    SEGRuntimeCostProfiler profiler;
    
    profiler.StartExecution("test-file");
    auto* cost = profiler.StartComponent(ComponentType::EngineCycle, "RunUnityCycle");
    profiler.EndComponent(cost, true);
    profiler.EndExecution();
    
    bool exported = profiler.ExportToFile("cost_profile_test.json");
    ASSERT_TRUE(exported);
    
    std::ifstream file("cost_profile_test.json");
    ASSERT_TRUE(file.good());
}

// ============================================================================
// Test: Cost-aware config
// ============================================================================

TEST(cost_aware_config) {
    CostAwareExecutionConfig config;
    config.maxAcceptableDurationMs = 100.0;
    config.maxAcceptableMemoryMB = 50.0;
    config.minAcceptableSuccessRate = 0.95;
    
    ComponentCost acceptableCost;
    acceptableCost.durationMs = 50.0;
    acceptableCost.memoryDeltaMB = 10.0;
    
    ComponentCost expensiveCost;
    expensiveCost.durationMs = 200.0;
    expensiveCost.memoryDeltaMB = 10.0;
    
    ASSERT_TRUE(config.ShouldAcceptCost(acceptableCost));
    ASSERT_FALSE(config.ShouldAcceptCost(expensiveCost));
}

// ============================================================================
// Test: Component type strings
// ============================================================================

TEST(component_type_strings) {
    ASSERT_EQ(ComponentTypeToString(ComponentType::GraphBuild), "GraphBuild");
    ASSERT_EQ(ComponentTypeToString(ComponentType::Planner), "Planner");
    ASSERT_EQ(ComponentTypeToString(ComponentType::EngineCycle), "EngineCycle");
    ASSERT_EQ(ComponentTypeToString(ComponentType::SwarmTask), "SwarmTask");
    ASSERT_EQ(ComponentTypeToString(ComponentType::Telemetry), "Telemetry");
    ASSERT_EQ(ComponentTypeToString(ComponentType::Checkpoint), "Checkpoint");
}

// ============================================================================
// Test: Global validation
// ============================================================================

TEST(validate_runtime_cost_profiler) {
    bool result = ValidateRuntimeCostProfiler();
    ASSERT_TRUE(result);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "SEG Runtime Cost Profiler Smoke Tests" << std::endl;
    std::cout << "Phase C.0 Batch 2/5: Runtime Cost Profiler" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Component Profiling Tests
    std::cout << "Component Profiling Tests:" << std::endl;
    RUN_TEST(profile_single_component);
    RUN_TEST(profile_multiple_components);
    std::cout << std::endl;
    
    // Statistics Tests
    std::cout << "Statistics Tests:" << std::endl;
    RUN_TEST(component_statistics_aggregation);
    RUN_TEST(failure_tracking);
    std::cout << std::endl;
    
    // Convergence Tests
    std::cout << "Convergence Tests:" << std::endl;
    RUN_TEST(convergence_tracking);
    std::cout << std::endl;
    
    // History Tests
    std::cout << "History Tests:" << std::endl;
    RUN_TEST(history_management);
    std::cout << std::endl;
    
    // Detection Tests
    std::cout << "Detection Tests:" << std::endl;
    RUN_TEST(expensive_component_detection);
    std::cout << std::endl;
    
    // Scheduler Integration Tests
    std::cout << "Scheduler Integration Tests:" << std::endl;
    RUN_TEST(scheduler_cost_estimates);
    std::cout << std::endl;
    
    // Export Tests
    std::cout << "Export Tests:" << std::endl;
    RUN_TEST(json_export);
    RUN_TEST(file_export);
    std::cout << std::endl;
    
    // Configuration Tests
    std::cout << "Configuration Tests:" << std::endl;
    RUN_TEST(cost_aware_config);
    RUN_TEST(component_type_strings);
    std::cout << std::endl;
    
    // Validation Tests
    std::cout << "Validation Tests:" << std::endl;
    RUN_TEST(validate_runtime_cost_profiler);
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (testsFailed == 0) {
        std::cout << "\n✓ Phase C.0 Batch 2/5 Complete" << std::endl;
        std::cout << "✓ Runtime Cost Profiler validated" << std::endl;
        std::cout << "✓ Ready for Phase C.0 Batch 3/5: Historical Performance Store" << std::endl;
    }
    
    return testsFailed > 0 ? 1 : 0;
}
