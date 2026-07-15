#pragma once

/**
 * SovereignExecutionGraph.hpp
 * 
 * Phase B.4 Batch 1/5: Graph Model Core
 * 
 * The Sovereign Execution Graph (SEG) is the orchestration layer that unifies
 * InfinitePerfectionEngine, SovereignSwarm, and AI Runtime into a single
 * graph-driven execution model.
 * 
 * Architecture:
 *                    Sovereign Execution Graph
 *                              |
 *          +-------------------+-------------------+
 *          |                   |                   |
 *    Infinite Engine       Swarm Runtime       AI Runtime
 *          |                   |                   |
 *    94-249 Cycles       250-256 Tasks       GGUF/Kernels
 *          |
 *    Telemetry + Persistence
 */

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>

namespace Sovereign {
namespace SEG {

// Forward declarations
class ExecutionGraph;
class ExecutionNode;
class ExecutionEdge;

/**
 * Node types in the Sovereign Execution Graph
 */
enum class NodeType : uint8_t {
    EngineCycle,      // InfinitePerfectionEngine Run*Cycle()
    SwarmTask,        // SovereignSwarm task execution
    Kernel,           // Low-level compute kernel
    Agent,            // AI agent node
    Telemetry,        // Telemetry capture node
    Composite,        // Sub-graph container
    EntryPoint,       // Graph entry
    ExitPoint         // Graph exit
};

/**
 * Execution states for nodes
 */
enum class ExecutionState : uint8_t {
    Pending,          // Not yet executed
    Running,          // Currently executing
    Completed,        // Successfully completed
    Failed,           // Execution failed
    Skipped,          // Skipped due to dependencies
    Cancelled         // Cancelled by user/system
};

/**
 * Unique identifier for graph elements
 */
using NodeId = uint64_t;
using EdgeId = uint64_t;
using GraphId = uint64_t;

/**
 * Execution node in the SEG
 */
struct ExecutionNode {
    NodeId id;
    std::string name;
    NodeType type;
    
    // Dependencies and outputs
    std::vector<NodeId> dependencies;
    std::vector<NodeId> outputs;
    std::vector<EdgeId> incomingEdges;
    std::vector<EdgeId> outgoingEdges;
    
    // Execution state
    std::atomic<ExecutionState> state{ExecutionState::Pending};
    std::atomic<double> confidence{0.0};
    std::atomic<double> progress{0.0};  // 0.0 - 1.0
    
    // Timing
    int64_t scheduledTime{0};     // When node was scheduled
    int64_t startTime{0};         // When execution started
    int64_t endTime{0};           // When execution completed
    int64_t executionTimeMs{0};     // Total execution time
    
    // Type-specific metadata
    std::map<std::string, std::string> metadata;
    
    // For EngineCycle nodes: which cycle
    std::string cycleName;        // e.g., "RunUnityCycle"
    int batchNumber{0};           // e.g., 243 for Unity
    
    // For SwarmTask nodes: which task kind
    std::string taskKind;         // e.g., "ComputeOrderTopology"
    
    // Constructor
    ExecutionNode(NodeId id, const std::string& name, NodeType type)
        : id(id), name(name), type(type) {}
    
    // Check if node is ready to execute (all dependencies completed)
    bool IsReady() const;
    
    // Check if node is terminal (no outputs)
    bool IsTerminal() const { return outputs.empty(); }
    
    // Get execution duration
    int64_t GetDurationMs() const { return executionTimeMs; }
    
    // Reset state for re-execution
    void Reset();
};

/**
 * Execution edge connecting nodes
 */
struct ExecutionEdge {
    EdgeId id;
    NodeId sourceId;
    NodeId targetId;
    
    // Edge properties
    bool isDataFlow{true};        // Carries data vs control flow
    bool isRequired{true};        // Required vs optional
    double weight{1.0};           // Edge weight for pathfinding
    
    // Data transfer
    std::string dataType;         // Type of data flowing
    size_t dataSize{0};           // Size in bytes
    
    // Timing
    int64_t propagationTimeMs{0}; // Time for data to propagate
    
    // Constructor
    ExecutionEdge(EdgeId id, NodeId source, NodeId target)
        : id(id), sourceId(source), targetId(target) {}
};

/**
 * Graph statistics
 */
struct GraphStatistics {
    size_t nodeCount{0};
    size_t edgeCount{0};
    size_t cycleCount{0};         // Number of cycles (engine)
    size_t swarmTaskCount{0};     // Number of swarm tasks
    size_t kernelCount{0};        // Number of kernel nodes
    size_t agentCount{0};         // Number of agent nodes
    
    // Execution stats
    size_t completedNodes{0};
    size_t failedNodes{0};
    size_t pendingNodes{0};
    size_t runningNodes{0};
    
    // Timing
    int64_t totalExecutionTimeMs{0};
    double averageNodeTimeMs{0.0};
    
    // Convergence
    double globalHarmonyIndex{0.0};
    bool isConverged{false};
    
    std::string ToJson() const;
};

/**
 * Sovereign Execution Graph
 * 
 * The core graph structure that orchestrates all execution.
 */
class ExecutionGraph {
public:
    ExecutionGraph();
    explicit ExecutionGraph(const std::string& name);
    ~ExecutionGraph();
    
    // Graph identification
    GraphId GetId() const { return id_; }
    const std::string& GetName() const { return name_; }
    void SetName(const std::string& name) { name_ = name; }
    
    // Node management
    ExecutionNode* AddNode(const std::string& name, NodeType type);
    ExecutionNode* AddEngineCycleNode(const std::string& cycleName, int batchNumber);
    ExecutionNode* AddSwarmTaskNode(const std::string& taskKind);
    ExecutionNode* AddTelemetryNode(const std::string& telemetryType);
    
    ExecutionNode* GetNode(NodeId id) const;
    ExecutionNode* GetNodeByName(const std::string& name) const;
    const std::map<NodeId, std::unique_ptr<ExecutionNode>>& GetNodes() const { return nodes_; }
    
    bool RemoveNode(NodeId id);
    size_t GetNodeCount() const { return nodes_.size(); }
    
    // Edge management
    ExecutionEdge* AddEdge(NodeId sourceId, NodeId targetId);
    ExecutionEdge* GetEdge(EdgeId id) const;
    bool RemoveEdge(EdgeId id);
    size_t GetEdgeCount() const { return edges_.size(); }
    
    // Graph queries
    std::vector<ExecutionNode*> GetEntryPoints() const;
    std::vector<ExecutionNode*> GetExitPoints() const;
    std::vector<ExecutionNode*> GetReadyNodes() const;
    std::vector<ExecutionNode*> GetNodesByType(NodeType type) const;
    std::vector<ExecutionNode*> GetNodesByState(ExecutionState state) const;
    
    // Topological ordering
    std::vector<NodeId> TopologicalSort() const;
    bool HasCycle() const;
    
    // Pathfinding
    std::vector<NodeId> FindPath(NodeId start, NodeId end) const;
    std::vector<std::vector<NodeId>> FindAllPaths(NodeId start, NodeId end) const;
    
    // Statistics
    GraphStatistics GetStatistics() const;
    
    // Serialization
    std::string ExportToJson() const;
    bool ImportFromJson(const std::string& json);
    
    // Validation
    bool Validate() const;
    std::vector<std::string> GetValidationErrors() const;
    
    // Reset all node states
    void ResetExecution();
    
    // Event callbacks
    using NodeStateCallback = std::function<void(NodeId, ExecutionState, ExecutionState)>;
    void SetNodeStateCallback(NodeStateCallback callback) { onNodeStateChange_ = callback; }
    
private:
    GraphId id_;
    std::string name_;
    
    std::map<NodeId, std::unique_ptr<ExecutionNode>> nodes_;
    std::map<EdgeId, std::unique_ptr<ExecutionEdge>> edges_;
    
    mutable std::mutex mutex_;
    
    NodeId nextNodeId_{1};
    EdgeId nextEdgeId_{1};
    
    NodeStateCallback onNodeStateChange_;
    
    // Helper methods
    void UpdateNodeStateInternal(ExecutionNode* node, ExecutionState newState);
    bool WouldCreateCycle(NodeId sourceId, NodeId targetId) const;
    void TopologicalSortUtil(NodeId nodeId, std::map<NodeId, bool>& visited,
                              std::map<NodeId, bool>& recStack,
                              std::vector<NodeId>& result) const;
    bool HasCycleUtil(NodeId nodeId, std::map<NodeId, bool>& visited,
                      std::map<NodeId, bool>& recStack) const;
};

/**
 * Graph builder for automatic discovery
 */
class ExecutionGraphBuilder {
public:
    ExecutionGraphBuilder();
    
    // Discovery methods
    void DiscoverEngineCycles();
    void DiscoverSwarmTasks();
    void DiscoverKernels();
    void DiscoverAll();
    
    // Build the graph
    std::unique_ptr<ExecutionGraph> Build();
    
    // Configuration
    void SetIncludeTelemetry(bool include) { includeTelemetry_ = include; }
    void SetBatchRange(int startBatch, int endBatch);
    
private:
    std::unique_ptr<ExecutionGraph> graph_;
    bool includeTelemetry_{true};
    int startBatch_{94};
    int endBatch_{256};
    
    void AddEngineCycleNodes();
    void AddSwarmTaskNodes();
    void AddDependencyEdges();
    void AddTelemetryNodes();
};

} // namespace SEG
} // namespace Sovereign
