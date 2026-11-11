/**
 * seg_validation_smoke_test.cpp
 * 
 * Phase B.4 Batch 5/5: SEG Validation Smoke Test
 * 
 * End-to-end integration test runner for SEG validation
 */

#include "../src/seg/SovereignSEGIntegrationTest.hpp"
#include <iostream>
#include <sstream>
#include <fstream>

using namespace Sovereign::SEG;

// ============================================================================
// Test Framework
// ============================================================================

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

// ============================================================================
// Validation Tests
// ============================================================================

TEST(full_validation_run) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    test.SetEnableTelemetry(true);
    test.SetEnableCheckpoints(true);
    
    auto report = test.RunFullValidation();
    
    ASSERT_TRUE(report.allPassed);
    ASSERT_EQ(report.GetFailCount(), 0);
    ASSERT_EQ(report.results.size(), 6u);  // 6 validation phases
}

TEST(graph_integrity_phase) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    
    auto result = test.ValidateGraphIntegrity();
    
    ASSERT_TRUE(result.passed);
    ASSERT_EQ(result.phase, "GraphIntegrity");
    
    // Check metrics
    auto it = result.metrics.find("total_nodes");
    ASSERT_TRUE(it != result.metrics.end());
    int nodeCount = std::stoi(it->second);
    ASSERT_TRUE(nodeCount >= 14);  // At minimum 7 cycles + some tasks
    
    it = result.metrics.find("engine_cycles");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 7);  // 7 Unity cycles (243-249)
    
    it = result.metrics.find("swarm_tasks");
    ASSERT_TRUE(it != result.metrics.end());
    // Full range has 28 tasks (7 batches * 4 tasks each)
    ASSERT_TRUE(std::stoi(it->second) >= 7);
}

TEST(planner_topology_phase) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    
    // First validate graph
    test.ValidateGraphIntegrity();
    
    auto result = test.ValidatePlannerTopology();
    
    ASSERT_TRUE(result.passed);
    ASSERT_EQ(result.phase, "PlannerTopology");
    
    // Check metrics
    auto it = result.metrics.find("topologically_valid");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
    
    it = result.metrics.find("has_critical_path");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
    
    it = result.metrics.find("deterministic");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
}

TEST(runtime_execution_phase) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    
    // First validate graph and planner
    test.ValidateGraphIntegrity();
    test.ValidatePlannerTopology();
    
    auto result = test.ValidateRuntimeExecution();
    
    ASSERT_TRUE(result.passed);
    ASSERT_EQ(result.phase, "RuntimeExecution");
    
    // Check metrics
    auto it = result.metrics.find("cycles_executed");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 7);  // 7 Unity cycles
    
    it = result.metrics.find("tasks_executed");
    ASSERT_TRUE(it != result.metrics.end());
    // Full batch range 243-256 has 28 tasks (7 batches * 4 tasks each)
    ASSERT_EQ(std::stoi(it->second), 28);
    
    it = result.metrics.find("converged");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
    
    it = result.metrics.find("harmony_index");
    ASSERT_TRUE(it != result.metrics.end());
    double harmony = std::stod(it->second);
    ASSERT_TRUE(harmony > 0.8);
}

TEST(telemetry_flow_phase) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    
    // First validate graph, planner, and runtime
    test.ValidateGraphIntegrity();
    test.ValidatePlannerTopology();
    test.ValidateRuntimeExecution();
    
    auto result = test.ValidateTelemetryFlow();
    
    ASSERT_TRUE(result.passed);
    ASSERT_EQ(result.phase, "TelemetryFlow");
    
    // Check metrics
    auto it = result.metrics.find("execution_complete");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
    
    it = result.metrics.find("failures");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 0);
    
    it = result.metrics.find("unity_converged");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
}

TEST(checkpoint_recovery_phase) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    test.SetEnableCheckpoints(true);
    
    // First validate graph
    test.ValidateGraphIntegrity();
    
    auto result = test.ValidateCheckpointRecovery();
    
    ASSERT_TRUE(result.passed);
    ASSERT_EQ(result.phase, "CheckpointRecovery");
    
    // Check metrics
    auto it = result.metrics.find("save_successful");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
    
    it = result.metrics.find("restore_successful");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
    
    it = result.metrics.find("graph_integrity");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
}

TEST(deterministic_execution_phase) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    
    // First validate graph and planner
    test.ValidateGraphIntegrity();
    test.ValidatePlannerTopology();
    
    auto result = test.ValidateDeterministicExecution();
    
    ASSERT_TRUE(result.passed);
    ASSERT_EQ(result.phase, "DeterministicExecution");
    
    // Check metrics
    auto it = result.metrics.find("order_match");
    ASSERT_TRUE(it != result.metrics.end());
    ASSERT_EQ(std::stoi(it->second), 1);
}

TEST(unity_sequence_execution) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    
    // Setup
    test.ValidateGraphIntegrity();
    test.ValidatePlannerTopology();
    
    auto results = test.ExecuteUnitySequence();
    
    ASSERT_TRUE(results.success);
    ASSERT_EQ(results.cyclesExecuted, 7);  // 7 Unity cycles
    ASSERT_EQ(results.tasksExecuted, 28);  // 28 Swarm tasks (7 batches * 4)
    ASSERT_TRUE(results.converged);
    ASSERT_TRUE(results.harmonyIndex > 0.8);
    
    // Verify all cycles and tasks executed
    ASSERT_EQ(results.executedCycles.size(), 7u);   // 7 Unity cycles
    ASSERT_EQ(results.executedTasks.size(), 28u);  // 28 Swarm tasks
}

TEST(validation_report_generation) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    
    auto report = test.RunFullValidation();
    
    // Test JSON export
    std::string json = report.ToJson();
    ASSERT_TRUE(json.find("seg_validation") != std::string::npos);
    ASSERT_TRUE(json.find("version") != std::string::npos);
    ASSERT_TRUE(json.find("summary") != std::string::npos);
    ASSERT_TRUE(json.find("phases") != std::string::npos);
    
    // Test report metrics
    ASSERT_EQ(report.GetPassCount() + report.GetFailCount(), static_cast<int>(report.results.size()));
}

TEST(validation_report_export) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    
    auto report = test.RunFullValidation();
    
    // Export to file
    bool exported = ExportValidationReport(report, "seg_validation_report.json");
    ASSERT_TRUE(exported);
    
    // Verify file exists and has content
    std::ifstream file("seg_validation_report.json");
    ASSERT_TRUE(file.good());
    
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    ASSERT_TRUE(content.find("seg_validation") != std::string::npos);
}

TEST(quick_validation_function) {
    // Test the quick validation function
    bool result = RunSEGQuickValidation();
    ASSERT_TRUE(result);
}

TEST(full_validation_function) {
    // Test the full validation function
    auto report = RunSEGFullValidation();
    ASSERT_TRUE(report.allPassed);
    ASSERT_EQ(report.results.size(), 6u);
}

TEST(small_batch_range) {
    // Test with smaller batch range
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 244);  // Just Unity and Integration cycles
    
    auto result = test.ValidateGraphIntegrity();
    
    // Should still pass but with fewer nodes
    ASSERT_TRUE(result.passed);
    
    auto it = result.metrics.find("total_nodes");
    ASSERT_TRUE(it != result.metrics.end());
    int nodeCount = std::stoi(it->second);
    // Batch 243-244: 2 cycles + 0 tasks (tasks start at 250) + 1 telemetry = 3 nodes
    ASSERT_TRUE(nodeCount >= 3);
}

TEST(telemetry_disabled) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    test.SetEnableTelemetry(false);
    
    auto report = test.RunFullValidation();
    
    // Should still pass even without telemetry
    ASSERT_TRUE(report.allPassed);
}

TEST(checkpoints_disabled) {
    SovereignSEGIntegrationTest test;
    test.SetBatchRange(243, 256);
    test.SetEnableCheckpoints(false);
    
    auto report = test.RunFullValidation();
    
    // Should still pass even without checkpoints
    ASSERT_TRUE(report.allPassed);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "SEG Validation Smoke Tests (Batch 5/5)" << std::endl;
    std::cout << "Phase B.4: Sovereign Execution Graph" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Core Validation Tests
    std::cout << "Core Validation Tests:" << std::endl;
    RUN_TEST(full_validation_run);
    RUN_TEST(graph_integrity_phase);
    RUN_TEST(planner_topology_phase);
    RUN_TEST(runtime_execution_phase);
    RUN_TEST(telemetry_flow_phase);
    RUN_TEST(checkpoint_recovery_phase);
    RUN_TEST(deterministic_execution_phase);
    std::cout << std::endl;
    
    // Unity Sequence Tests
    std::cout << "Unity Sequence Tests:" << std::endl;
    RUN_TEST(unity_sequence_execution);
    std::cout << std::endl;
    
    // Report Tests
    std::cout << "Report Tests:" << std::endl;
    RUN_TEST(validation_report_generation);
    RUN_TEST(validation_report_export);
    std::cout << std::endl;
    
    // Global Function Tests
    std::cout << "Global Function Tests:" << std::endl;
    RUN_TEST(quick_validation_function);
    RUN_TEST(full_validation_function);
    std::cout << std::endl;
    
    // Edge Case Tests
    std::cout << "Edge Case Tests:" << std::endl;
    RUN_TEST(small_batch_range);
    RUN_TEST(telemetry_disabled);
    RUN_TEST(checkpoints_disabled);
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (testsFailed == 0) {
        std::cout << "\n✓ Phase B.4 Complete: Sovereign Execution Graph validated\n";
        std::cout << "✓ All 5 batches passed\n";
        std::cout << "✓ Ready for Phase C: Autonomous Execution\n";
    }
    
    return testsFailed > 0 ? 1 : 0;
}
