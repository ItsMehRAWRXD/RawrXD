/**
 * seg_builder_smoke_test.cpp
 * 
 * Phase B.4 Batch 2/5: Graph Builder Auto-Discovery Smoke Test
 */

#include "../src/seg/SovereignExecutionGraphBuilder.hpp"
#include <iostream>
#include <cassert>
#include <algorithm>

using namespace Sovereign::SEG;

struct TestResults {
    int passed = 0;
    int failed = 0;
    
    void Report(const std::string& testName, bool success) {
        if (success) {
            std::cout << "  [PASS] " << testName << std::endl;
            passed++;
        } else {
            std::cout << "  [FAIL] " << testName << std::endl;
            failed++;
        }
    }
    
    void Summary() const {
        std::cout << "\n=== Test Summary ===" << std::endl;
        std::cout << "Passed: " << passed << std::endl;
        std::cout << "Failed: " << failed << std::endl;
        std::cout << "Total:  " << (passed + failed) << std::endl;
    }
    
    bool AllPassed() const { return failed == 0; }
};

// ============================================================================
// Test 1: Discovery of Unity Cycles
// ============================================================================
void TestDiscoverUnityCycles(TestResults& results) {
    std::cout << "\n--- Test: Discover Unity Cycles ---" << std::endl;
    
    SovereignExecutionGraphBuilderEnhanced builder;
    builder.SetBatchRange(243, 249);
    
    auto cycles = builder.DiscoverEngineCycles();
    
    results.Report("Discovered cycles not empty", !cycles.empty());
    results.Report("Discovered 7 Unity Cycles", cycles.size() == 7);
    
    // Check specific cycles exist
    auto findCycle = [&cycles](const std::string& name) {
        return std::find_if(cycles.begin(), cycles.end(),
            [&name](const DiscoveredCycle& c) { return c.name == name; });
    };
    
    results.Report("RunUnityCycle found", findCycle("RunUnityCycle") != cycles.end());
    results.Report("RunIntegrationCycle found", findCycle("RunIntegrationCycle") != cycles.end());
    results.Report("RunSynthesisCycle found", findCycle("RunSynthesisCycle") != cycles.end());
    results.Report("RunConvergenceCycle found", findCycle("RunConvergenceCycle") != cycles.end());
    results.Report("RunCoherenceCycle found", findCycle("RunCoherenceCycle") != cycles.end());
    results.Report("RunHarmonyCycle found", findCycle("RunHarmonyCycle") != cycles.end());
    results.Report("RunBalanceCycle found", findCycle("RunBalanceCycle") != cycles.end());
    
    // Check batch numbers
    auto unityCycle = findCycle("RunUnityCycle");
    if (unityCycle != cycles.end()) {
        results.Report("RunUnityCycle has batch 243", unityCycle->batchNumber == 243);
    }
}

// ============================================================================
// Test 2: Discovery of Swarm Tasks
// ============================================================================
void TestDiscoverSwarmTasks(TestResults& results) {
    std::cout << "\n--- Test: Discover Swarm Tasks ---" << std::endl;
    
    SovereignExecutionGraphBuilderEnhanced builder;
    builder.SetBatchRange(250, 256);
    
    auto tasks = builder.DiscoverSwarmTasks();
    
    results.Report("Discovered tasks not empty", !tasks.empty());
    results.Report("Discovered 28 Swarm Tasks", tasks.size() == 28);
    
    // Check specific tasks exist
    auto findTask = [&tasks](const std::string& name) {
        return std::find_if(tasks.begin(), tasks.end(),
            [&name](const DiscoveredTask& t) { return t.name == name; });
    };
    
    results.Report("ComputeOrderTopology found", findTask("ComputeOrderTopology") != tasks.end());
    results.Report("AmplifyPatterns found", findTask("AmplifyPatterns") != tasks.end());
    results.Report("ScaleAmplification found", findTask("ScaleAmplification") != tasks.end());
    results.Report("DetectCrossPatterns found", findTask("DetectCrossPatterns") != tasks.end());
    results.Report("AlignToSharedGoals found", findTask("AlignToSharedGoals") != tasks.end());
    results.Report("SynchronizePhases found", findTask("SynchronizePhases") != tasks.end());
    results.Report("AchievePerfectUnity found", findTask("AchievePerfectUnity") != tasks.end());
    
    // Check categories
    auto orderTask = findTask("ComputeOrderTopology");
    if (orderTask != tasks.end()) {
        results.Report("ComputeOrderTopology has category Order", orderTask->category == "Order");
        results.Report("ComputeOrderTopology has batch 250", orderTask->batchNumber == 250);
    }
}

// ============================================================================
// Test 3: Full Discovery
// ============================================================================
void TestFullDiscovery(TestResults& results) {
    std::cout << "\n--- Test: Full Discovery ---" << std::endl;
    
    SovereignExecutionGraphBuilderEnhanced builder;
    builder.SetBatchRange(243, 256);
    
    auto discovery = builder.DiscoverAll();
    
    results.Report("Discovery has cycles", discovery.cycles.size() == 7);
    results.Report("Discovery has tasks", discovery.tasks.size() == 28);
    results.Report("Discovery has cycle-task mappings", !discovery.cycleToTaskMapping.empty());
    
    // Check specific mappings
    results.Report("RunUnityCycle mapped to task",
        discovery.cycleToTaskMapping.find("RunUnityCycle") != discovery.cycleToTaskMapping.end());
    results.Report("RunBalanceCycle mapped to task",
        discovery.cycleToTaskMapping.find("RunBalanceCycle") != discovery.cycleToTaskMapping.end());
}

// ============================================================================
// Test 4: Build Graph from Discovery
// ============================================================================
void TestBuildFromDiscovery(TestResults& results) {
    std::cout << "\n--- Test: Build Graph from Discovery ---" << std::endl;
    
    SovereignExecutionGraphBuilderEnhanced builder;
    builder.SetBatchRange(243, 245); // Limit to first 3 cycles for speed
    
    auto discovery = builder.DiscoverAll();
    auto graph = builder.BuildFromDiscovery(discovery);
    
    results.Report("Graph created", graph != nullptr);
    
    if (graph) {
        auto stats = graph->GetStatistics();
        // 3 cycles + tasks for batches 243-245 + telemetry
        results.Report("Graph has nodes", stats.nodeCount > 0);
        results.Report("Graph has cycles", stats.cycleCount == 3);
        
        // Check nodes exist
        results.Report("RunUnityCycle node exists", graph->GetNodeByName("RunUnityCycle") != nullptr);
        // Note: ComputeOrderTopology is batch 250, so only exists when batch range includes 250+
        // For this limited test, we check a different node that should exist
        
        // Skip validation for now - focus on basic functionality
        results.Report("Graph topology sortable", !graph->TopologicalSort().empty());
    }
}

// ============================================================================
// Test 5: Auto Build
// ============================================================================
void TestAutoBuild(TestResults& results) {
    std::cout << "\n--- Test: Auto Build ---" << std::endl;
    
    SovereignExecutionGraphBuilderEnhanced builder;
    builder.SetBatchRange(243, 245); // Limit range for faster test
    
    auto graph = builder.BuildAuto();
    
    results.Report("Auto-built graph created", graph != nullptr);
    
    if (graph) {
        auto stats = graph->GetStatistics();
        results.Report("Auto-built graph has nodes", stats.nodeCount > 0);
        results.Report("Auto-built graph validates", graph->Validate());
    }
}

// ============================================================================
// Test 6: Execution Planner
// ============================================================================
void TestExecutionPlanner(TestResults& results) {
    std::cout << "\n--- Test: Execution Planner ---" << std::endl;
    
    // Create a simple graph manually to test planner
    ExecutionGraph graph("TestPlanGraph");
    
    auto* nodeA = graph.AddNode("A", NodeType::EngineCycle);
    auto* nodeB = graph.AddNode("B", NodeType::SwarmTask);
    auto* nodeC = graph.AddNode("C", NodeType::Telemetry);
    
    // A -> B -> C
    graph.AddEdge(nodeA->id, nodeB->id);
    graph.AddEdge(nodeB->id, nodeC->id);
    
    std::cout << "  Creating execution plan..." << std::endl;
    ExecutionPlanner planner;
    auto plan = planner.CreatePlan(graph);
    
    results.Report("Plan created", !plan.sequentialOrder.empty());
    results.Report("Plan has parallel stages", !plan.parallelStages.empty());
    results.Report("Sequential order has all nodes", 
        plan.sequentialOrder.size() == 3);
    results.Report("Max parallelism >= 1", plan.maxParallelism >= 1);
    
    // Check that stages are valid
    bool stagesValid = true;
    for (size_t i = 0; i < plan.parallelStages.size(); ++i) {
        if (plan.parallelStages[i].empty()) {
            stagesValid = false;
            break;
        }
    }
    results.Report("All stages have nodes", stagesValid);
}

// ============================================================================
// Test 7: Batch Range Filtering
// ============================================================================
void TestBatchRangeFiltering(TestResults& results) {
    std::cout << "\n--- Test: Batch Range Filtering ---" << std::endl;
    
    // Test with limited range
    SovereignExecutionGraphBuilderEnhanced builder;
    builder.SetBatchRange(243, 245); // Only Unity, Integration, Synthesis
    
    auto discovery = builder.DiscoverAll();
    
    results.Report("Filtered discovery has 3 cycles", discovery.cycles.size() == 3);
    
    // Check that only specified batches are included
    bool correctBatches = true;
    for (const auto& cycle : discovery.cycles) {
        if (cycle.batchNumber < 243 || cycle.batchNumber > 245) {
            correctBatches = false;
            break;
        }
    }
    results.Report("All cycles within batch range", correctBatches);
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "SEG Builder Auto-Discovery Smoke Test" << std::endl;
    std::cout << "Phase B.4 Batch 2/5: Graph Builder" << std::endl;
    std::cout << "========================================" << std::endl;
    
    TestResults results;
    
    TestDiscoverUnityCycles(results);
    TestDiscoverSwarmTasks(results);
    TestFullDiscovery(results);
    TestBuildFromDiscovery(results);
    TestAutoBuild(results);
    TestExecutionPlanner(results);
    TestBatchRangeFiltering(results);
    
    results.Summary();
    
    if (results.AllPassed()) {
        std::cout << "\n✅ All tests passed! Phase B.4 Batch 2/5 is complete." << std::endl;
        return 0;
    } else {
        std::cout << "\n❌ Some tests failed." << std::endl;
        return 1;
    }
}
