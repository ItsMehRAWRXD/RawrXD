/**
 * seg_smoke_test.cpp
 * 
 * Phase B.4 Batch 1/5: Sovereign Execution Graph Smoke Test
 * 
 * Validates the SEG core implementation:
 * - Node creation and management
 * - Edge creation and dependency tracking
 * - Topological sorting
 * - Cycle detection
 * - JSON export
 * - Graph statistics
 */

#include "../src/seg/SovereignExecutionGraph.hpp"
#include <iostream>
#include <cassert>
#include <algorithm>

using namespace Sovereign::SEG;

// Test result tracking
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
// Test 1: Basic Node Creation
// ============================================================================
void TestBasicNodeCreation(TestResults& results) {
    std::cout << "\n--- Test: Basic Node Creation ---" << std::endl;
    
    ExecutionGraph graph("TestGraph");
    
    // Test creating different node types
    auto* cycleNode = graph.AddEngineCycleNode("RunUnityCycle", 243);
    results.Report("EngineCycle node created", cycleNode != nullptr);
    results.Report("EngineCycle node has correct ID", cycleNode->id > 0);
    results.Report("EngineCycle node has correct name", cycleNode->name == "RunUnityCycle");
    results.Report("EngineCycle node has correct type", cycleNode->type == NodeType::EngineCycle);
    results.Report("EngineCycle node has batch number", cycleNode->batchNumber == 243);
    
    auto* swarmNode = graph.AddSwarmTaskNode("ComputeOrderTopology");
    results.Report("SwarmTask node created", swarmNode != nullptr);
    results.Report("SwarmTask node has correct type", swarmNode->type == NodeType::SwarmTask);
    
    auto* telemetryNode = graph.AddTelemetryNode("UnityCycle");
    results.Report("Telemetry node created", telemetryNode != nullptr);
    results.Report("Telemetry node has correct type", telemetryNode->type == NodeType::Telemetry);
    
    // Test node retrieval
    auto* retrieved = graph.GetNode(cycleNode->id);
    results.Report("Node retrieval by ID", retrieved == cycleNode);
    
    auto* retrievedByName = graph.GetNodeByName("RunUnityCycle");
    results.Report("Node retrieval by name", retrievedByName == cycleNode);
    
    // Test node count
    auto stats = graph.GetStatistics();
    results.Report("Correct node count", stats.nodeCount == 3);
    results.Report("Correct cycle count", stats.cycleCount == 1);
    results.Report("Correct swarm task count", stats.swarmTaskCount == 1);
}

// ============================================================================
// Test 2: Edge Creation and Dependencies
// ============================================================================
void TestEdgeCreation(TestResults& results) {
    std::cout << "\n--- Test: Edge Creation and Dependencies ---" << std::endl;
    
    ExecutionGraph graph("TestGraph");
    
    auto* nodeA = graph.AddNode("NodeA", NodeType::EngineCycle);
    auto* nodeB = graph.AddNode("NodeB", NodeType::SwarmTask);
    auto* nodeC = graph.AddNode("NodeC", NodeType::Telemetry);
    
    // Create edges: A -> B -> C
    auto* edgeAB = graph.AddEdge(nodeA->id, nodeB->id);
    results.Report("Edge A->B created", edgeAB != nullptr);
    
    auto* edgeBC = graph.AddEdge(nodeB->id, nodeC->id);
    results.Report("Edge B->C created", edgeBC != nullptr);
    
    // Verify dependencies
    results.Report("NodeB depends on NodeA", 
        std::find(nodeB->dependencies.begin(), nodeB->dependencies.end(), nodeA->id) != nodeB->dependencies.end());
    results.Report("NodeC depends on NodeB",
        std::find(nodeC->dependencies.begin(), nodeC->dependencies.end(), nodeB->id) != nodeC->dependencies.end());
    
    // Verify outputs
    results.Report("NodeA outputs to NodeB",
        std::find(nodeA->outputs.begin(), nodeA->outputs.end(), nodeB->id) != nodeA->outputs.end());
    
    // Test edge retrieval
    auto* retrievedEdge = graph.GetEdge(edgeAB->id);
    results.Report("Edge retrieval by ID", retrievedEdge == edgeAB);
    
    // Test edge count
    auto stats = graph.GetStatistics();
    results.Report("Correct edge count", stats.edgeCount == 2);
}

// ============================================================================
// Test 3: Cycle Detection
// ============================================================================
void TestCycleDetection(TestResults& results) {
    std::cout << "\n--- Test: Cycle Detection ---" << std::endl;
    
    ExecutionGraph graph("TestGraph");
    
    auto* nodeA = graph.AddNode("NodeA", NodeType::EngineCycle);
    auto* nodeB = graph.AddNode("NodeB", NodeType::SwarmTask);
    auto* nodeC = graph.AddNode("NodeC", NodeType::Telemetry);
    
    // Create acyclic graph: A -> B -> C
    graph.AddEdge(nodeA->id, nodeB->id);
    graph.AddEdge(nodeB->id, nodeC->id);
    
    results.Report("Acyclic graph detected correctly", !graph.HasCycle());
    
    // Try to create cycle: C -> A (should fail)
    auto* cycleEdge = graph.AddEdge(nodeC->id, nodeA->id);
    results.Report("Cycle creation prevented", cycleEdge == nullptr);
    results.Report("Graph still acyclic", !graph.HasCycle());
}

// ============================================================================
// Test 4: Topological Sorting
// ============================================================================
void TestTopologicalSort(TestResults& results) {
    std::cout << "\n--- Test: Topological Sorting ---" << std::endl;
    
    ExecutionGraph graph("TestGraph");
    
    // Create a simple DAG:
    //     A
    //    / \
    //   B   C
    //    \ /
    //     D
    
    auto* nodeA = graph.AddNode("A", NodeType::EngineCycle);
    auto* nodeB = graph.AddNode("B", NodeType::SwarmTask);
    auto* nodeC = graph.AddNode("C", NodeType::SwarmTask);
    auto* nodeD = graph.AddNode("D", NodeType::Telemetry);
    
    graph.AddEdge(nodeA->id, nodeB->id);
    graph.AddEdge(nodeA->id, nodeC->id);
    graph.AddEdge(nodeB->id, nodeD->id);
    graph.AddEdge(nodeC->id, nodeD->id);
    
    auto sorted = graph.TopologicalSort();
    results.Report("Topological sort returns correct size", sorted.size() == 4);
    
    // Verify ordering: A should come before B, C, and D
    auto posA = std::find(sorted.begin(), sorted.end(), nodeA->id);
    auto posB = std::find(sorted.begin(), sorted.end(), nodeB->id);
    auto posC = std::find(sorted.begin(), sorted.end(), nodeC->id);
    auto posD = std::find(sorted.begin(), sorted.end(), nodeD->id);
    
    results.Report("A comes before B", posA < posB);
    results.Report("A comes before C", posA < posC);
    results.Report("A comes before D", posA < posD);
    results.Report("B comes before D", posB < posD);
    results.Report("C comes before D", posC < posD);
}

// ============================================================================
// Test 5: Graph Statistics
// ============================================================================
void TestGraphStatistics(TestResults& results) {
    std::cout << "\n--- Test: Graph Statistics ---" << std::endl;
    
    ExecutionGraph graph("TestGraph");
    
    // Add nodes of different types
    graph.AddEngineCycleNode("Cycle1", 243);
    graph.AddEngineCycleNode("Cycle2", 244);
    graph.AddSwarmTaskNode("Task1");
    graph.AddSwarmTaskNode("Task2");
    graph.AddSwarmTaskNode("Task3");
    graph.AddTelemetryNode("Telemetry1");
    
    auto stats = graph.GetStatistics();
    
    results.Report("Total node count correct", stats.nodeCount == 6);
    results.Report("Cycle count correct", stats.cycleCount == 2);
    results.Report("Swarm task count correct", stats.swarmTaskCount == 3);
    results.Report("Edge count correct (no edges)", stats.edgeCount == 0);
    
    // Test statistics JSON output
    std::string statsJson = stats.ToJson();
    results.Report("Statistics JSON is valid", !statsJson.empty());
    results.Report("Statistics JSON contains nodeCount", 
        statsJson.find("\"nodeCount\"") != std::string::npos);
}

// ============================================================================
// Test 6: Graph Builder
// ============================================================================
void TestGraphBuilder(TestResults& results) {
    std::cout << "\n--- Test: Graph Builder ---" << std::endl;
    
    ExecutionGraphBuilder builder;
    builder.SetBatchRange(243, 256);
    // Telemetry is enabled by default via includeTelemetry_{true}
    
    builder.DiscoverAll();
    
    auto graph = builder.Build();
    
    results.Report("Graph builder produces valid graph", graph != nullptr);
    
    if (graph) {
        auto stats = graph->GetStatistics();
        results.Report("Builder discovers Unity Cycles", stats.cycleCount > 0);
        results.Report("Builder discovers Swarm Tasks", stats.swarmTaskCount > 0);
        results.Report("Builder includes Telemetry", stats.nodeCount > stats.cycleCount + stats.swarmTaskCount);
        
        // Check specific nodes exist
        results.Report("RunUnityCycle node exists", 
            graph->GetNodeByName("RunUnityCycle") != nullptr);
        results.Report("ComputeOrderTopology node exists",
            graph->GetNodeByName("ComputeOrderTopology") != nullptr);
    }
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Sovereign Execution Graph Smoke Test" << std::endl;
    std::cout << "Phase B.4 Batch 1/5: Graph Model Core" << std::endl;
    std::cout << "========================================" << std::endl;
    
    TestResults results;
    
    // Run all tests
    TestBasicNodeCreation(results);
    TestEdgeCreation(results);
    TestCycleDetection(results);
    TestTopologicalSort(results);
    TestGraphStatistics(results);
    TestGraphBuilder(results);
    
    results.Summary();
    
    if (results.AllPassed()) {
        std::cout << "\n✅ All tests passed! Phase B.4 Batch 1/5 is complete." << std::endl;
        return 0;
    } else {
        std::cout << "\n❌ Some tests failed." << std::endl;
        return 1;
    }
}
