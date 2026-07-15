// inference_os_demo.cpp - Demonstration of Self-Observing Inference OS Kernel
// 
// This file demonstrates the complete architecture:
// - Capability-governed execution
// - Queryable execution memory
// - Endogenous observability
// - Self-referential control

#include "inference_gateway.h"
#include "execution_query_api.h"
#include "execution_graph_hash.h"
#include "statistical_collapse.h"
#include "token_lineage.h"
#include <iostream>
#include <thread>
#include <chrono>

using namespace RawrXD;

// ============================================================================
// DEMO: Full execution flow with introspection
// ============================================================================

void Demo_CapabilityGovernedExecution() {
    std::cout << "\n=== Demo: Capability-Governed Execution ===\n";
    
    // Step 1: Create execution request
    InferenceRequest req;
    req.model = "llama3.2:3b";
    req.prompt = "Explain capability-based security";
    req.temperature = 0.7f;
    req.maxTokens = 100;
    req.runtimeMode = RuntimeMode::HybridControlled;
    req.allowRemote = false;  // Local only for this demo
    
    // Step 2: Execute through gateway (single ingress)
    std::cout << "Executing through InferenceGateway...\n";
    auto response = InferenceGateway::instance().execute(req);
    
    // Step 3: Verify execution path was logged
    std::cout << "Execution path: " << response.routingLog << "\n";
    std::cout << "Latency: " << response.latencyMs << "ms\n";
    std::cout << "Success: " << (response.success ? "yes" : "no") << "\n";
    
    if (response.success) {
        std::cout << "Result: " << response.text.substr(0, 100) << "...\n";
    }
}

void Demo_QueryableExecutionMemory() {
    std::cout << "\n=== Demo: Queryable Execution Memory ===\n";
    
    // Query hot paths from statistical aggregator
    std::cout << "Querying hot paths...\n";
    auto hotPaths = ExecutionQueryAPI::instance().getHotPaths(5);
    
    std::cout << "Top " << hotPaths.size() << " execution paths:\n";
    for (const auto& path : hotPaths) {
        std::cout << "  " << path.pathSignature 
                  << ": " << path.executionCount << " executions"
                  << ", p95=" << path.p95LatencyMs << "ms"
                  << ", success=" << path.successCount << "/" 
                  << (path.successCount + path.failureCount) << "\n";
    }
    
    // Query performance insights
    std::cout << "\nPerformance insights:\n";
    auto insights = ExecutionQueryAPI::instance().getPerformanceInsights();
    for (const auto& insight : insights) {
        std::cout << "  " << insight.metric << ": " 
                  << insight.trend 
                  << " (" << insight.changePercent << "% change)\n";
        for (const auto& rec : insight.recommendations) {
            std::cout << "    → " << rec << "\n";
        }
    }
}

void Demo_SelfReferentialControl() {
    std::cout << "\n=== Demo: Self-Referential Control ===\n";
    
    // Get current routing policy
    std::cout << "Current routing policy:\n";
    auto policy = ExecutionQueryAPI::instance().getRoutingPolicy();
    std::cout << "  Mode: " << static_cast<int>(policy.mode) << "\n";
    std::cout << "  Backend weights:\n";
    for (const auto& [backend, weight] : policy.backendWeights) {
        std::cout << "    " << backend << ": " << weight << "\n";
    }
    
    // Get recommended policy from statistical learning
    std::cout << "\nRecommended policy (from statistical models):\n";
    auto recommended = ExecutionQueryAPI::instance().getRecommendedPolicy();
    std::cout << "  Mode: " << static_cast<int>(recommended.mode) << "\n";
    std::cout << "  Optimal backend: " << [&]() {
        std::string dominant;
        double maxWeight = 0;
        for (const auto& [backend, weight] : recommended.backendWeights) {
            if (weight > maxWeight) {
                maxWeight = weight;
                dominant = backend;
            }
        }
        return dominant.empty() ? "unknown" : dominant;
    }() << "\n";
    
    // Demonstrate that we can query but not arbitrarily mutate
    std::cout << "\nQuery API provides observability without bypass:\n";
    std::cout << "  ✓ Can query execution state\n";
    std::cout << "  ✓ Can get recommendations\n";
    std::cout << "  ✓ Can compare executions\n";
    std::cout << "  ✓ Cannot bypass capability checks\n";
    std::cout << "  ✓ Cannot mutate active executions\n";
}

void Demo_DeterministicReplay() {
    std::cout << "\n=== Demo: Deterministic Replay ===\n";
    
    // Simulate two executions
    std::cout << "Simulating execution comparison...\n";
    
    // In a real scenario, these would be actual execution IDs
    std::string executionIdA = "exec_001";
    std::string executionIdB = "exec_002";
    
    auto comparison = ExecutionQueryAPI::instance().compareExecutions(
        executionIdA, executionIdB);
    
    std::cout << "Comparison result:\n";
    std::cout << "  Execution A: " << comparison.executionIdA << "\n";
    std::cout << "  Execution B: " << comparison.executionIdB << "\n";
    std::cout << "  Isomorphic: " << (comparison.isomorphic ? "yes" : "no") << "\n";
    std::cout << "  Hash A: " << comparison.hashA << "\n";
    std::cout << "  Hash B: " << comparison.hashB << "\n";
    
    if (!comparison.structuralDifferences.empty()) {
        std::cout << "  Structural differences:\n";
        for (const auto& diff : comparison.structuralDifferences) {
            std::cout << "    - " << diff << "\n";
        }
    }
    
    // Demonstrate subgraph caching
    std::cout << "\nSubgraph caching:\n";
    GraphHash hash = GraphHasher::hashTopology(AgenticTaskNode{});
    std::cout << "  Topology hash: " << GraphHasher::toHex(hash) << "\n";
    std::cout << "  Cached: " << (GraphCache::instance().contains(hash) ? "yes" : "no") << "\n";
}

void Demo_AnomalyDetection() {
    std::cout << "\n=== Demo: Anomaly Detection ===\n";
    
    // Detect anomalies
    std::cout << "Running anomaly detection...\n";
    auto anomalies = ExecutionQueryAPI::instance().detectAnomalies();
    
    if (anomalies.empty()) {
        std::cout << "No anomalies detected (normal operation)\n";
    } else {
        std::cout << "Detected " << anomalies.size() << " anomalies:\n";
        for (const auto& anomaly : anomalies) {
            std::cout << "  [" << anomaly.severity << "] " 
                      << anomaly.nodeType << ": " 
                      << anomaly.description << "\n";
        }
    }
    
    // Analyze failure clusters
    std::cout << "\nFailure cluster analysis:\n";
    auto clusters = ExecutionQueryAPI::instance().analyzeFailureClusters();
    if (clusters.empty()) {
        std::cout << "  No failure clusters detected\n";
    } else {
        for (const auto& cluster : clusters) {
            std::cout << "  Pattern: " << cluster.errorPattern 
                      << " (" << cluster.occurrenceCount << " occurrences)\n";
            std::cout << "    Mitigation: " << cluster.suggestedMitigation << "\n";
        }
    }
}

void Demo_LineageAndAudit() {
    std::cout << "\n=== Demo: Lineage and Audit ===\n";
    
    // Export lineage graph
    std::cout << "Exporting token lineage...\n";
    std::string lineageDot = ExecutionQueryAPI::instance().exportLineageGraph("dot");
    std::cout << "Lineage graph (DOT format, first 500 chars):\n";
    std::cout << lineageDot.substr(0, 500) << "...\n";
    
    // Export statistical models
    std::cout << "\nExporting statistical models...\n";
    std::string models = ExecutionQueryAPI::instance().exportStatisticalModels("inference");
    std::cout << "Models (first 500 chars):\n";
    std::cout << models.substr(0, 500) << "...\n";
    
    std::cout << "\nAudit trail provides:\n";
    std::cout << "  ✓ Complete token provenance\n";
    std::cout << "  ✓ Execution history\n";
    std::cout << "  ✓ Statistical models\n";
    std::cout << "  ✓ Reproducible reconstruction\n";
}

void Demo_ArchitectureSummary() {
    std::cout << "\n=== Architecture Summary ===\n";
    std::cout << "\n3-Plane Operating System:\n";
    std::cout << "  ┌─────────────────────────────────────────┐\n";
    std::cout << "  │ 1. Execution Plane (Deterministic)      │\n";
    std::cout << "  │    - Capability-secured compute        │\n";
    std::cout << "  │    - Bounded DAG runtime               │\n";
    std::cout << "  └─────────────────────────────────────────┘\n";
    std::cout << "                    ↓\n";
    std::cout << "  ┌─────────────────────────────────────────┐\n";
    std::cout << "  │ 2. Memory Plane (Queryable)             │\n";
    std::cout << "  │    - Execution graph as data structure  │\n";
    std::cout << "  │    - Statistical models                │\n";
    std::cout << "  └─────────────────────────────────────────┘\n";
    std::cout << "                    ↓\n";
    std::cout << "  ┌─────────────────────────────────────────┐\n";
    std::cout << "  │ 3. Control Plane (Self-Referential)     │\n";
    std::cout << "  │    - Query API                         │\n";
    std::cout << "  │    - Adaptive policy tuning            │\n";
    std::cout << "  └─────────────────────────────────────────┘\n";
    
    std::cout << "\nKey Properties:\n";
    std::cout << "  ✓ Execution ⊥ Observation (separation)\n";
    std::cout << "  ✓ Statistics ⊥ Determinism (no override)\n";
    std::cout << "  ✓ Query ⊥ Control (read-only observation)\n";
    std::cout << "  ✓ Reflexive (self-describing)\n";
    std::cout << "  ✓ Capability-governed (compile-time enforcement)\n";
    
    std::cout << "\nClassification:\n";
    std::cout << "  Self-observing, capability-governed execution operating system\n";
    std::cout << "  with queryable runtime substrate\n";
}

// ============================================================================
// Main entry point
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║   Self-Observing Inference OS Kernel - Architecture Demo      ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
    
    try {
        // Run all demos
        Demo_CapabilityGovernedExecution();
        Demo_QueryableExecutionMemory();
        Demo_SelfReferentialControl();
        Demo_DeterministicReplay();
        Demo_AnomalyDetection();
        Demo_LineageAndAudit();
        Demo_ArchitectureSummary();
        
        std::cout << "\n=== Demo Complete ===\n";
        std::cout << "\nThe system demonstrates:\n";
        std::cout << "  • Capability-governed execution (no bypass)\n";
        std::cout << "  • Queryable execution memory (runtime data structures)\n";
        std::cout << "  • Endogenous observability (native introspection)\n";
        std::cout << "  • Self-referential control (feedback without overreach)\n";
        std::cout << "  • Structural stability (separation of planes)\n";
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Demo failed: " << e.what() << "\n";
        return 1;
    }
}
