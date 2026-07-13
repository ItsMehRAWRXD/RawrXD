/**
 * seg_performance_bridge_smoke_test.cpp
 * 
 * Phase C.0 Batch 1/5: SEG Performance Bridge Validation
 * 
 * Tests the performance instrumentation bridge:
 * - Metric recording
 * - Snapshot generation
 * - Scheduler score calculation
 * - JSON export
 * - Telemetry integration
 */

#include "../src/seg/SEGPerformanceBridge.hpp"
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
// Test: Basic metric recording
// ============================================================================

TEST(record_inference_metric) {
    SEGPerformanceBridge bridge;
    
    InferenceMetric metric;
    metric.model = "phi3-mini";
    metric.backend = "native";
    metric.promptTps = 3365.82;
    metric.generationTps = 182.03;
    metric.tokensProcessed = 1024;
    
    bridge.RecordInferenceMetric(metric);
    
    ASSERT_EQ(bridge.GetInferenceMetricCount(), 1u);
}

TEST(record_cycle_metric) {
    SEGPerformanceBridge bridge;
    
    CycleMetric metric;
    metric.cycleName = "RunUnityCycle";
    metric.batchNumber = 243;
    metric.durationMs = 14.0;
    metric.convergenceDelta = 0.07;
    metric.success = true;
    
    bridge.RecordCycleMetric(metric);
    
    ASSERT_EQ(bridge.GetCycleMetricCount(), 1u);
}

TEST(record_graph_metric) {
    SEGPerformanceBridge bridge;
    
    GraphPerformanceMetric metric;
    metric.graphBuildMs = 42.0;
    metric.planGenerationMs = 8.0;
    metric.executionMs = 1200.0;
    metric.parallelEfficiency = 0.84;
    metric.totalNodes = 36;
    
    bridge.RecordGraphMetric(metric);
    
    ASSERT_EQ(bridge.GetGraphMetricCount(), 1u);
}

// ============================================================================
// Test: Snapshot generation
// ============================================================================

TEST(snapshot_generation) {
    SEGPerformanceBridge bridge;
    
    // Add inference metrics
    for (int i = 0; i < 5; i++) {
        InferenceMetric inf;
        inf.promptTps = 3000.0 + i * 100;
        inf.generationTps = 150.0 + i * 10;
        bridge.RecordInferenceMetric(inf);
    }
    
    // Add cycle metrics
    for (int i = 0; i < 5; i++) {
        CycleMetric cycle;
        cycle.cycleName = "RunUnityCycle";
        cycle.durationMs = 14.0 + i;
        cycle.convergenceDelta = 0.8 + i * 0.02;
        cycle.success = true;
        bridge.RecordCycleMetric(cycle);
    }
    
    // Add graph metric
    GraphPerformanceMetric graph;
    graph.graphBuildMs = 42.0;
    graph.planGenerationMs = 8.0;
    graph.executionMs = 1200.0;
    graph.parallelEfficiency = 0.84;
    bridge.RecordGraphMetric(graph);
    
    auto snapshot = bridge.GetSnapshot();
    
    ASSERT_GT(snapshot.latestPromptTps, 0.0);
    ASSERT_GT(snapshot.avgPromptTps, 0.0);
    ASSERT_GT(snapshot.avgCycleDurationMs, 0.0);
    ASSERT_GT(snapshot.cycleSuccessRate, 0.0);
    ASSERT_GT(snapshot.latestGraphBuildMs, 0.0);
}

TEST(scheduler_scores) {
    SEGPerformanceBridge bridge;
    
    // Add metrics to generate scores
    InferenceMetric inf;
    inf.promptTps = 3365.82;
    inf.generationTps = 182.03;
    bridge.RecordInferenceMetric(inf);
    
    CycleMetric cycle;
    cycle.convergenceDelta = 0.85;
    cycle.success = true;
    bridge.RecordCycleMetric(cycle);
    
    GraphPerformanceMetric graph;
    graph.parallelEfficiency = 0.84;
    bridge.RecordGraphMetric(graph);
    
    auto snapshot = bridge.GetSnapshot();
    
    ASSERT_GT(snapshot.throughputScore, 0.0);
    ASSERT_GT(snapshot.convergenceScore, 0.0);
    ASSERT_GT(snapshot.reliabilityScore, 0.0);
    ASSERT_GT(snapshot.resourceEfficiencyScore, 0.0);
}

// ============================================================================
// Test: JSON export
// ============================================================================

TEST(json_export) {
    SEGPerformanceBridge bridge;
    
    InferenceMetric inf;
    inf.model = "phi3-mini";
    inf.backend = "native";
    inf.promptTps = 3365.82;
    inf.generationTps = 182.03;
    bridge.RecordInferenceMetric(inf);
    
    CycleMetric cycle;
    cycle.cycleName = "RunUnityCycle";
    cycle.batchNumber = 243;
    cycle.durationMs = 14.0;
    cycle.convergenceDelta = 0.07;
    cycle.success = true;
    bridge.RecordCycleMetric(cycle);
    
    GraphPerformanceMetric graph;
    graph.graphBuildMs = 42.0;
    graph.planGenerationMs = 8.0;
    graph.executionMs = 1200.0;
    graph.parallelEfficiency = 0.84;
    bridge.RecordGraphMetric(graph);
    
    std::string json = bridge.ExportToJson();
    
    ASSERT_TRUE(json.find("performance_snapshot") != std::string::npos);
    ASSERT_TRUE(json.find("inference") != std::string::npos);
    ASSERT_TRUE(json.find("cycles") != std::string::npos);
    ASSERT_TRUE(json.find("graph") != std::string::npos);
    ASSERT_TRUE(json.find("scheduler_scores") != std::string::npos);
}

TEST(file_export) {
    SEGPerformanceBridge bridge;
    
    InferenceMetric inf;
    inf.promptTps = 1000.0;
    inf.generationTps = 200.0;
    bridge.RecordInferenceMetric(inf);
    
    bool exported = bridge.ExportToFile("performance_test.json");
    ASSERT_TRUE(exported);
    
    // Verify file exists
    std::ifstream file("performance_test.json");
    ASSERT_TRUE(file.good());
    
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    ASSERT_TRUE(content.find("performance_snapshot") != std::string::npos);
}

// ============================================================================
// Test: History management
// ============================================================================

TEST(history_clear) {
    SEGPerformanceBridge bridge;
    
    InferenceMetric inf;
    inf.promptTps = 1000.0;
    bridge.RecordInferenceMetric(inf);
    
    ASSERT_EQ(bridge.GetInferenceMetricCount(), 1u);
    
    bridge.ClearHistory();
    
    ASSERT_EQ(bridge.GetInferenceMetricCount(), 0u);
    ASSERT_EQ(bridge.GetCycleMetricCount(), 0u);
    ASSERT_EQ(bridge.GetGraphMetricCount(), 0u);
}

TEST(sufficient_data_check) {
    SEGPerformanceBridge bridge;
    
    // Initially insufficient
    ASSERT_FALSE(bridge.HasSufficientData());
    
    // Add minimum required data
    for (int i = 0; i < 3; i++) {
        InferenceMetric inf;
        inf.promptTps = 1000.0;
        bridge.RecordInferenceMetric(inf);
        
        CycleMetric cycle;
        cycle.success = true;
        bridge.RecordCycleMetric(cycle);
    }
    
    GraphPerformanceMetric graph;
    bridge.RecordGraphMetric(graph);
    
    ASSERT_TRUE(bridge.HasSufficientData());
}

// ============================================================================
// Test: Performance-aware config
// ============================================================================

TEST(performance_aware_config) {
    PerformanceAwareConfig config;
    config.throughputWeight = 1.0;
    config.convergenceWeight = 2.0;
    config.reliabilityWeight = 1.5;
    config.resourceEfficiencyWeight = 0.5;
    
    double priority = config.CalculatePriority(
        0.85,   // convergence
        0.95,   // historical success
        0.75,   // throughput
        100.0   // resource cost
    );
    
    ASSERT_GT(priority, 0.0);
}

// ============================================================================
// Test: Global validation
// ============================================================================

TEST(validate_performance_bridge) {
    bool result = ValidatePerformanceBridge();
    ASSERT_TRUE(result);
}

// ============================================================================
// Test: Score getters
// ============================================================================

TEST(score_getters) {
    SEGPerformanceBridge bridge;
    
    // Add metrics
    InferenceMetric inf;
    inf.promptTps = 3000.0;
    inf.generationTps = 200.0;
    bridge.RecordInferenceMetric(inf);
    
    CycleMetric cycle;
    cycle.convergenceDelta = 0.9;
    cycle.success = true;
    bridge.RecordCycleMetric(cycle);
    
    GraphPerformanceMetric graph;
    graph.parallelEfficiency = 0.85;
    bridge.RecordGraphMetric(graph);
    
    ASSERT_GT(bridge.GetThroughputScore(), 0.0);
    ASSERT_GT(bridge.GetConvergenceScore(), 0.0);
    ASSERT_GT(bridge.GetReliabilityScore(), 0.0);
    ASSERT_GT(bridge.GetResourceEfficiencyScore(), 0.0);
}

// ============================================================================
// Test: Snapshot JSON structure
// ============================================================================

TEST(snapshot_json_structure) {
    SEGPerformanceBridge bridge;
    
    InferenceMetric inf;
    inf.promptTps = 3365.82;
    inf.generationTps = 182.03;
    bridge.RecordInferenceMetric(inf);
    
    auto snapshot = bridge.GetSnapshot();
    std::string json = snapshot.ToJson();
    
    // Verify all expected fields
    ASSERT_TRUE(json.find("\"latest_prompt_tps\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"latest_generation_tps\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"avg_prompt_tps\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"avg_generation_tps\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"throughput\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"convergence\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"reliability\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"resource_efficiency\"") != std::string::npos);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "SEG Performance Bridge Smoke Tests" << std::endl;
    std::cout << "Phase C.0 Batch 1/5: Performance Bridge" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Metric Recording Tests
    std::cout << "Metric Recording Tests:" << std::endl;
    RUN_TEST(record_inference_metric);
    RUN_TEST(record_cycle_metric);
    RUN_TEST(record_graph_metric);
    std::cout << std::endl;
    
    // Snapshot Generation Tests
    std::cout << "Snapshot Generation Tests:" << std::endl;
    RUN_TEST(snapshot_generation);
    RUN_TEST(scheduler_scores);
    std::cout << std::endl;
    
    // JSON Export Tests
    std::cout << "JSON Export Tests:" << std::endl;
    RUN_TEST(json_export);
    RUN_TEST(file_export);
    std::cout << std::endl;
    
    // History Management Tests
    std::cout << "History Management Tests:" << std::endl;
    RUN_TEST(history_clear);
    RUN_TEST(sufficient_data_check);
    std::cout << std::endl;
    
    // Configuration Tests
    std::cout << "Configuration Tests:" << std::endl;
    RUN_TEST(performance_aware_config);
    std::cout << std::endl;
    
    // Integration Tests
    std::cout << "Integration Tests:" << std::endl;
    RUN_TEST(validate_performance_bridge);
    RUN_TEST(score_getters);
    RUN_TEST(snapshot_json_structure);
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (testsFailed == 0) {
        std::cout << "\n✓ Phase C.0 Batch 1/5 Complete\n";
        std::cout << "✓ Performance Bridge validated\n";
        std::cout << "✓ Ready for Phase C.1: Adaptive Scheduling\n";
    }
    
    return testsFailed > 0 ? 1 : 0;
}
