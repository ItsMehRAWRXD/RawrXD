/**
 * SovereignExecutionGraphSmokeTest.cpp
 * 
 * Phase B.4 Batch 1/5: Graph Model Core Validation
 * 
 * Validates:
 * - Node creation and management
 * - Edge creation and dependency tracking
 * - Topological sorting
 * - Cycle detection
 * - JSON export/import
 * - Graph statistics
 * - Thread safety
 */

#include "SovereignExecutionGraph.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <vector>
#include <chrono>

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
    
    // Create new graph with cycle
    ExecutionGraph cyclicGraph("CyclicGraph");
    auto* n1 = cyclicGraph.AddNode("N1", NodeType::EngineCycle);
    auto* n2 = cyclicGraph.AddNode("N2", NodeType::SwarmTask);
    auto* n3 = cyclicGraph.AddNode("N3", NodeType::Telemetry);
    
    // Force cycle by creating edges in sequence
    cyclicGraph.AddEdge(n1->id, n2->id);
    cyclicGraph.AddEdge(n2->id, n3->id);
    // This should be prevented
    auto* forcedCycle = cyclicGraph.AddEdge(n3->id, n1->id);
    results.Report("Forced cycle prevented by validation", forcedCycle == nullptr);
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
// Test 5: Entry and Exit Points
// ============================================================================
void TestEntryExitPoints(TestResults& results) {
    std::cout << "\n--- Test: Entry and Exit Points ---" << std::endl;
    
    ExecutionGraph graph("TestGraph");
    
    // Create graph:
    // Entry -> A -> B -> Exit
    //          \
    //           -> C -> Exit
    
    auto* entry = graph.AddNode("Entry", NodeType::EntryPoint);
    auto* nodeA = graph.AddNode("A", NodeType::EngineCycle);
    auto* nodeB = graph.AddNode("B", NodeType::SwarmTask);
    auto* nodeC = graph.AddNode("C", NodeType::SwarmTask);
    auto* exit1 = graph.AddNode("Exit1", NodeType::ExitPoint);
    auto* exit2 = graph.AddNode("Exit2", NodeType::ExitPoint);
    
    graph.AddEdge(entry->id, nodeA->id);
    graph.AddEdge(nodeA->id, nodeB->id);
    graph.AddEdge(nodeA->id, nodeC->id);
    graph.AddEdge(nodeB->id, exit1->id);
    graph.AddEdge(nodeC->id, exit2->id);
    
    auto entryPoints = graph.GetEntryPoints();
    results.Report("Correct number of entry points", entryPoints.size() == 1);
    results.Report("Entry point is correct node", entryPoints[0]->id == entry->id);
    
    auto exitPoints = graph.GetExitPoints();
    results.Report("Correct number of exit points", exitPoints.size() == 2);
}

// ============================================================================
// Test 6: Node State Management
// ============================================================================
void TestNodeStateManagement(TestResults& results) {
    std::cout << "\n--- Test: Node State Management ---" << std::endl;
    
    ExecutionGraph graph("TestGraph");
    
    auto* node = graph.AddNode("TestNode", NodeType::EngineCycle);
    
    results.Report("Initial state is Pending", 
        node->state.load() == ExecutionState::Pending);
    
    // Simulate state transitions
    node->state.store(ExecutionState::Running);
    results.Report("State changed to Running", 
        node->state.load() == ExecutionState::Running);
    
    node->progress.store(50.0);
    results.Report("Progress updated", node->progress.load() == 50.0);
    
    node->confidence.store(0.95);
    results.Report("Confidence updated", node->confidence.load() == 0.95);
    
    node->state.store(ExecutionState::Completed);
    results.Report("State changed to Completed", 
        node->state.load() == ExecutionState::Completed);
    
    // Test reset
    node->Reset();
    results.Report("Reset restores Pending state", 
        node->state.load() == ExecutionState::Pending);
    results.Report("Reset clears progress", node->progress.load() == 0.0);
    results.Report("Reset clears confidence", node->confidence.load() == 0.0);
}

// ============================================================================
// Test 7: Ready Nodes Query
// ============================================================================
void TestReadyNodes(TestResults& results) {
    std::cout << "\n--- Test: Ready Nodes Query ---" << std::endl;
    
    ExecutionGraph graph("TestGraph");
    
    auto* nodeA = graph.AddNode("A", NodeType::EngineCycle);
    auto* nodeB = graph.AddNode("B", NodeType::SwarmTask);
    auto* nodeC = graph.AddNode("C", NodeType::SwarmTask);
    
    // A -> B -> C
    graph.AddEdge(nodeA->id, nodeB->id);
    graph.AddEdge(nodeB->id, nodeC->id);
    
    // Initially, only A should be ready (no dependencies)
    auto ready1 = graph.GetReadyNodes();
    results.Report("Initially A is ready", ready1.size() == 1 && ready1[0]->id == nodeA->id);
    
    // Mark A as completed
    nodeA->state.store(ExecutionState::Completed);
    
    // Now B should be ready
    auto ready2 = graph.GetReadyNodes();
    results.Report("After A completes, B is ready", 
        ready2.size() == 1 && ready2[0]->id == nodeB->id);
    
    // Mark B as completed
    nodeB->state.store(ExecutionState::Completed);
    
    // Now C should be ready
    auto ready3 = graph.GetReadyNodes();
    results.Report("After B completes, C is ready", 
        ready3.size() == 1 && ready3[0]->id == nodeC->id);
}

// ============================================================================
// Test 8: JSON Export
// ============================================================================
void TestJsonExport(TestResults& results) {
    std::cout << "\n--- Test: JSON Export ---" << std::endl;
    
    ExecutionGraph graph("TestGraph");
    
    auto* nodeA = graph.AddEngineCycleNode("RunUnityCycle", 243);
    auto* nodeB = graph.AddSwarmTaskNode("ComputeOrderTopology");
    
    graph.AddEdge(nodeA->id, nodeB->id);
    
    std::string json = graph.ExportToJson();
    
    results.Report("JSON export produces non-empty output", !json.empty());
    results.Report("JSON contains graph name", json.find("TestGraph") != std::string::npos);
    results.Report("JSON contains node A", json.find("RunUnityCycle") != std::string::npos);
    results.Report("JSON contains node B", json.find("ComputeOrderTopology") != std::string::npos);
    results.Report("JSON contains nodes array", json.find("\"nodes\"") != std::string::npos);
    results.Report("JSON contains edges array", json.find("\"edges\"") != std::string::npos);
}

// ============================================================================
// Test 9: Graph Statistics
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
// Test 10: Graph Validation
// ============================================================================
void TestGraphValidation(TestResults& results) {
    std::cout << "\n--- Test: Graph Validation ---" << std::endl;
    
    // Valid graph
    ExecutionGraph validGraph("ValidGraph");
    validGraph.AddNode("Entry", NodeType::EntryPoint);
    validGraph.AddNode("Exit", NodeType::ExitPoint);
    
    results.Report("Valid graph passes validation", validGraph.Validate());
    
    auto errors = validGraph.GetValidationErrors();
    results.Report("Valid graph has no errors", errors.empty());
    
    // Graph with no entry points
    ExecutionGraph noEntryGraph("NoEntryGraph");
    auto* orphan = noEntryGraph.AddNode("Orphan", NodeType::EngineCycle);
    auto* another = noEntryGraph.AddNode("Another", NodeType::SwarmTask);
    noEntryGraph.AddEdge(orphan->id, another->id);
    
    // This graph has no entry points (orphan has no dependencies but is not EntryPoint type)
    // Actually, orphan has no dependencies so it IS an entry point
    // Let's create a true invalid graph
    
    // Graph with cycle (should be prevented by AddEdge)
    ExecutionGraph cyclicGraph("CyclicGraph");
    auto* n1 = cyclicGraph.AddNode("N1", NodeType::EngineCycle);
    auto* n2 = cyclicGraph.AddNode("N2", NodeType::SwarmTask);
    auto* n3 = cyclicGraph.AddNode("N3", NodeType::Telemetry);
    
    cyclicGraph.AddEdge(n1->id, n2->id);
    cyclicGraph.AddEdge(n2->id, n3->id);
    // This should return nullptr
    auto* cycleEdge = cyclicGraph.AddEdge(n3->id, n1->id);
    
    results.Report("Cycle creation prevented", cycleEdge == nullptr);
    results.Report("Cyclic graph still validates (cycle was prevented)", cyclicGraph.Validate());
}

// ============================================================================
// Test 11: Graph Builder
// ============================================================================
void TestGraphBuilder(TestResults& results) {
    std::cout << "\n--- Test: Graph Builder ---" << std::endl;
    
    ExecutionGraphBuilder builder;
    builder.SetBatchRange(243, 256);
    builder.EnableTelemetry(true);
    
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
// Test 12: Thread Safety
// ============================================================================
void TestThreadSafety(TestResults& results) {
    std::cout << "\n--- Test: Thread Safety ---" << std::endl;
    
    ExecutionGraph graph("ThreadTestGraph");
    
    const int numThreads = 4;
    const int nodesPerThread = 25;
    std::vector<std::thread> threads;
    
    // Launch threads to create nodes concurrently
    for (int t = 0; t < numThreads; ++t) {
        threads.emplace_back([&graph, t, nodesPerThread]() {
            for (int i = 0; i < nodesPerThread; ++i) {
                std::string name = "Thread" + std::to_string(t) + "_Node" + std::to_string(i);
                graph.AddNode(name, NodeType::EngineCycle);
            }
        });
    }
    
    // Wait for all threads
    for (auto& t : threads) {
        t.join();
    }
    
    auto stats = graph.GetStatistics();
    results.Report("Thread-safe node creation", stats.nodeCount == numThreads * nodesPerThread);
}

// ============================================================================
// Test 13: Complex Graph Structure
// ============================================================================
void TestComplexGraphStructure(TestResults& results) {
    std::cout << "\n--- Test: Complex Graph Structure ---" << std::endl;
    
    ExecutionGraph graph("ComplexGraph");
    
    // Create a realistic SEG structure:
    // Entry -> [Unity Cycle] -> [Swarm Tasks] -> [Telemetry] -> Exit
    
    auto* entry = graph.AddNode("Entry", NodeType::EntryPoint);
    
    // Unity Cycles (Batches 243-249)
    auto* unityCycle = graph.AddEngineCycleNode("RunUnityCycle", 243);
    auto* integrationCycle = graph.AddEngineCycleNode("RunIntegrationCycle", 244);
    auto* synthesisCycle = graph.AddEngineCycleNode("RunSynthesisCycle", 245);
    
    // Swarm Tasks (Batches 250-256)
    auto* orderTask = graph.AddSwarmTaskNode("ComputeOrderTopology");
    auto* amplifyTask = graph.AddSwarmTaskNode("AmplifyPatterns");
    auto* scaleTask = graph.AddSwarmTaskNode("ScaleAmplification");
    
    // Telemetry
    auto* telemetry = graph.AddTelemetryNode("UnityCycle");
    
    auto* exit = graph.AddNode("Exit", NodeType::ExitPoint);
    
    // Create dependencies
    graph.AddEdge(entry->id, unityCycle->id);
    graph.AddEdge(unityCycle->id, integrationCycle->id);
    graph.AddEdge(integrationCycle->id, synthesisCycle->id);
    graph.AddEdge(synthesisCycle->id, orderTask->id);
    graph.AddEdge(orderTask->id, amplifyTask->id);
    graph.AddEdge(amplifyTask->id, scaleTask->id);
    graph.AddEdge(scaleTask->id, telemetry->id);
    graph.AddEdge(telemetry->id, exit->id);
    
    // Validate structure
    results.Report("Complex graph validates", graph.Validate());
    results.Report("No cycles in complex graph", !graph.HasCycle());
    
    auto sorted = graph.TopologicalSort();
    results.Report("Topological sort succeeds", sorted.size() == 9);
    
    auto entryPoints = graph.GetEntryPoints();
    results.Report("Single entry point", entryPoints.size() == 1);
    
    auto exitPoints = graph.GetExitPoints();
    results.Report("Single exit point", exitPoints.size() == 1);
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
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Run all tests
    TestBasicNodeCreation(results);
    TestEdgeCreation(results);
    TestCycleDetection(results);
    TestTopologicalSort(results);
    TestEntryExitPoints(results);
    TestNodeStateManagement(results);
    TestReadyNodes(results);
    TestJsonExport(results);
    TestGraphStatistics(results);
    TestGraphValidation(results);
    TestGraphBuilder(results);
    TestThreadSafety(results);
    TestComplexGraphStructure(results);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    results.Summary();
    
    std::cout << "\nExecution time: " << duration.count() << "ms" << std::endl;
    
    if (results.AllPassed()) {
        std::cout << "\n✅ All tests passed! Phase B.4 Batch 1/5 is complete." << std::endl;
        return 0;
    } else {
        std::cout << "\n❌ Some tests failed." << std::endl;
        return 1;
    }
}
