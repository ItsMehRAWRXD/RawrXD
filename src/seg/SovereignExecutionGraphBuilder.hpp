/**
 * SovereignExecutionGraphBuilder.hpp
 * 
 * Phase B.4 Batch 2/5: Graph Builder Auto-Discovery
 * 
 * Automatically discovers:
 * - InfinitePerfectionEngine Run*Cycle methods (Batches 94-249)
 * - SovereignSwarm task kinds (Batches 250-256)
 * - Dependencies between Engine cycles and Swarm tasks
 * - Telemetry capture points
 */

#pragma once

#include "SovereignExecutionGraph.hpp"
#include <functional>
#include <vector>
#include <string>
#include <map>

// Forward declarations
namespace Sovereign {
namespace InfinitePerfection { class InfinitePerfectionEngine; }
class SovereignSwarm;
}

namespace Sovereign {
namespace SEG {

/**
 * Discovered cycle information from InfinitePerfectionEngine
 */
struct DiscoveredCycle {
    std::string name;           // e.g., "RunUnityCycle"
    int batchNumber;            // e.g., 243
    std::string description;    // Human-readable description
    std::vector<std::string> dependencies; // Names of cycles this depends on
    std::vector<std::string> outputs;        // What this cycle produces
};

/**
 * Discovered task information from SovereignSwarm
 */
struct DiscoveredTask {
    std::string name;           // e.g., "ComputeOrderTopology"
    int batchNumber;            // e.g., 250
    std::string category;       // e.g., "Order", "Resonance", "Amplification"
    std::string description;
    std::vector<std::string> dependencies;
};

/**
 * Discovery result containing all found cycles and tasks
 */
struct DiscoveryResult {
    std::vector<DiscoveredCycle> cycles;
    std::vector<DiscoveredTask> tasks;
    std::map<std::string, std::string> cycleToTaskMapping; // Which task feeds which cycle
};

/**
 * Enhanced Graph Builder with auto-discovery capabilities
 */
class SovereignExecutionGraphBuilderEnhanced {
public:
    SovereignExecutionGraphBuilderEnhanced();
    
    // Configuration
    void SetEngine(InfinitePerfection::InfinitePerfectionEngine* engine);
    void SetSwarm(SovereignSwarm* swarm);
    void SetBatchRange(int startBatch, int endBatch);
    void EnableTelemetry(bool enable) { includeTelemetry_ = enable; }
    void EnableAutoDependencies(bool enable) { autoDependencies_ = enable; }
    
    // Discovery methods
    DiscoveryResult DiscoverAll();
    std::vector<DiscoveredCycle> DiscoverEngineCycles();
    std::vector<DiscoveredTask> DiscoverSwarmTasks();
    
    // Build graph from discovery
    std::unique_ptr<ExecutionGraph> BuildFromDiscovery(const DiscoveryResult& result);
    std::unique_ptr<ExecutionGraph> BuildAuto(); // Discover + Build in one step
    
    // Dependency mapping
    void MapCycleToTask(const std::string& cycleName, const std::string& taskName);
    void AddCustomDependency(const std::string& from, const std::string& to);
    
    // Validation
    bool ValidateDiscovery(const DiscoveryResult& result) const;
    std::vector<std::string> GetDiscoveryErrors() const;
    
private:
    InfinitePerfection::InfinitePerfectionEngine* engine_{nullptr};
    SovereignSwarm* swarm_{nullptr};
    
    int startBatch_{94};
    int endBatch_{256};
    bool includeTelemetry_{true};
    bool autoDependencies_{true};
    
    std::vector<std::string> discoveryErrors_;
    std::map<std::string, std::string> customDependencies_;
    
    // Built-in cycle definitions (Batches 243-249 Unity Cycles)
    std::vector<DiscoveredCycle> GetBuiltInUnityCycles();
    
    // Built-in task definitions (Batches 250-256 Swarm Tasks)
    std::vector<DiscoveredTask> GetBuiltInSwarmTasks();
    
    // Reflection-based discovery (if RTTI available)
    std::vector<DiscoveredCycle> DiscoverCyclesViaReflection();
    std::vector<DiscoveredTask> DiscoverTasksViaReflection();
    
    // Dependency inference
    void InferDependencies(DiscoveryResult& result);
    bool WouldCreateCycle(const DiscoveryResult& result, 
                          const std::string& from, 
                          const std::string& to) const;
};

/**
 * Graph execution planner that takes a built graph and creates an execution plan
 */
class ExecutionPlanner {
public:
    struct ExecutionPlan {
        std::vector<std::vector<NodeId>> parallelStages; // Nodes that can run in parallel
        std::vector<NodeId> sequentialOrder;             // Total sequential order
        std::map<NodeId, std::vector<NodeId>> criticalPath; // Critical path per node
        int estimatedTotalTimeMs{0};
        int maxParallelism{0};
    };
    
    ExecutionPlan CreatePlan(const ExecutionGraph& graph);
    ExecutionPlan CreateOptimizedPlan(const ExecutionGraph& graph, int maxParallelism);
    
    // Plan analysis
    std::vector<NodeId> GetCriticalPath(const ExecutionGraph& graph, NodeId from, NodeId to);
    int EstimateExecutionTime(const ExecutionGraph& graph, int avgNodeTimeMs);
    
    // Plan execution order
    std::vector<NodeId> GetReadyNodes(const ExecutionGraph& graph, const ExecutionPlan& plan, int stage);
    bool IsStageComplete(const ExecutionGraph& graph, const ExecutionPlan& plan, int stage);
};

/**
 * Graph executor that runs the planned execution
 */
class GraphExecutor {
public:
    using NodeExecutor = std::function<bool(ExecutionNode&)>;
    using ProgressCallback = std::function<void(NodeId, double)>;
    using CompletionCallback = std::function<void(bool success)>;
    
    void SetNodeExecutor(NodeType type, NodeExecutor executor);
    void SetProgressCallback(ProgressCallback callback);
    void SetCompletionCallback(CompletionCallback callback);
    
    // Execute graph
    bool ExecuteSequential(ExecutionGraph& graph);
    bool ExecuteParallel(ExecutionGraph& graph, int maxConcurrency);
    bool ExecutePlanned(ExecutionGraph& graph, const ExecutionPlanner::ExecutionPlan& plan);
    
    // Execution control
    void Pause();
    void Resume();
    void Cancel();
    bool IsRunning() const { return isRunning_; }
    bool IsPaused() const { return isPaused_; }
    
private:
    std::map<NodeType, NodeExecutor> nodeExecutors_;
    ProgressCallback progressCallback_;
    CompletionCallback completionCallback_;
    
    std::atomic<bool> isRunning_{false};
    std::atomic<bool> isPaused_{false};
    std::atomic<bool> shouldCancel_{false};
    
    bool ExecuteNode(ExecutionNode& node);
    void UpdateNodeState(ExecutionNode& node, ExecutionState newState);
};

} // namespace SEG
} // namespace Sovereign
