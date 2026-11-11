// Phase W.1/5: Unified Runtime Graph
// RawrXD Unified Runtime Graph - Single execution path across all subsystems

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Convergence {

// Execution node types
enum class ExecutionNodeType {
    ENTRY,          // Request entry point
    PLANNER,        // Task planning
    REASONER,       // Reasoning engine
    METACOGNITIVE,  // Meta-cognitive runtime
    TOOL_REGISTRY,  // Tool management
    MEMORY,         // Memory access
    REFLECTION,     // Reflection engine
    SCHEDULER,      // Task scheduler
    BACKEND_SELECTOR, // Backend selection
    INFERENCE,      // Model inference
    TOOL_EXECUTION, // Tool execution
    TELEMETRY,      // Telemetry collection
    VALIDATION,     // Result validation
    EXIT            // Request completion
};

// Execution node
struct ExecutionNode {
    std::string node_id;
    ExecutionNodeType type;
    std::string name;
    std::string description;
    
    // Connections
    std::vector<std::string> inputs;
    std::vector<std::string> outputs;
    std::vector<std::string> dependencies;
    
    // State
    bool is_active;
    bool is_optional;
    bool can_retry;
    uint32_t max_retries;
    
    // Performance
    std::chrono::milliseconds average_latency;
    double success_rate;
    uint64_t execution_count;
};

// Execution edge
struct ExecutionEdge {
    std::string edge_id;
    std::string from_node;
    std::string to_node;
    
    // Condition
    std::string condition;  // Expression for conditional routing
    bool is_conditional;
    
    // Data flow
    std::vector<std::string> data_mappings;
    
    // State
    bool is_active;
    uint64_t traversal_count;
};

// Execution context
struct ExecutionContext {
    std::string context_id;
    std::chrono::system_clock::time_point created_at;
    
    // Request
    std::string request_type;
    std::unordered_map<std::string, std::string> request_params;
    
    // State
    std::unordered_map<std::string, std::string> state;
    std::vector<std::string> visited_nodes;
    std::string current_node;
    
    // Results
    bool is_complete;
    bool is_successful;
    std::string result;
    std::string error_message;
    
    // Performance
    std::chrono::milliseconds total_latency;
    std::unordered_map<std::string, std::chrono::milliseconds> node_latencies;
};

// Runtime graph
struct RuntimeGraph {
    std::string graph_id;
    std::string version;
    std::string description;
    
    // Nodes and edges
    std::unordered_map<std::string, ExecutionNode> nodes;
    std::unordered_map<std::string, ExecutionEdge> edges;
    
    // Entry and exit
    std::string entry_node;
    std::vector<std::string> exit_nodes;
    
    // Validation
    bool is_validated;
    std::vector<std::string> validation_errors;
    std::chrono::system_clock::time_point validated_at;
};

// Unified runtime graph interface
class IUnifiedRuntimeGraph {
public:
    virtual ~IUnifiedRuntimeGraph() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Graph management
    virtual std::string CreateGraph(const RuntimeGraph& graph) = 0;
    virtual bool UpdateGraph(const RuntimeGraph& graph) = 0;
    virtual bool DeleteGraph(const std::string& graph_id) = 0;
    virtual std::optional<RuntimeGraph> GetGraph(const std::string& graph_id) = 0;
    virtual std::vector<RuntimeGraph> ListGraphs() = 0;
    virtual bool ActivateGraph(const std::string& graph_id) = 0;
    virtual std::optional<RuntimeGraph> GetActiveGraph() = 0;
    
    // Node management
    virtual std::string AddNode(const std::string& graph_id, const ExecutionNode& node) = 0;
    virtual bool RemoveNode(const std::string& graph_id, const std::string& node_id) = 0;
    virtual bool UpdateNode(const std::string& graph_id, const ExecutionNode& node) = 0;
    virtual std::optional<ExecutionNode> GetNode(const std::string& graph_id, const std::string& node_id) = 0;
    
    // Edge management
    virtual std::string AddEdge(const std::string& graph_id, const ExecutionEdge& edge) = 0;
    virtual bool RemoveEdge(const std::string& graph_id, const std::string& edge_id) = 0;
    virtual std::vector<ExecutionEdge> GetNodeEdges(const std::string& graph_id, const std::string& node_id) = 0;
    
    // Execution
    virtual std::string ExecuteRequest(const std::string& request_type,
                                        const std::unordered_map<std::string, std::string>& params) = 0;
    virtual std::optional<ExecutionContext> GetExecutionContext(const std::string& context_id) = 0;
    virtual bool CancelExecution(const std::string& context_id) = 0;
    virtual std::vector<ExecutionContext> GetActiveExecutions() = 0;
    
    // Validation
    virtual bool ValidateGraph(const std::string& graph_id) = 0;
    virtual std::vector<std::string> GetValidationErrors(const std::string& graph_id) = 0;
    virtual bool IsGraphValid(const std::string& graph_id) = 0;
    
    // Statistics
    virtual struct RuntimeGraphStatistics {
        uint64_t total_executions;
        uint64_t successful_executions;
        uint64_t failed_executions;
        double average_execution_time_ms;
        double success_rate;
        std::unordered_map<std::string, uint64_t> executions_by_node;
        std::unordered_map<std::string, double> average_latency_by_node;
    } GetStatistics(const std::string& graph_id = "") = 0;
};

// Local unified runtime graph
class LocalUnifiedRuntimeGraph : public IUnifiedRuntimeGraph {
public:
    LocalUnifiedRuntimeGraph();
    ~LocalUnifiedRuntimeGraph() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreateGraph(const RuntimeGraph& graph) override;
    bool UpdateGraph(const RuntimeGraph& graph) override;
    bool DeleteGraph(const std::string& graph_id) override;
    std::optional<RuntimeGraph> GetGraph(const std::string& graph_id) override;
    std::vector<RuntimeGraph> ListGraphs() override;
    bool ActivateGraph(const std::string& graph_id) override;
    std::optional<RuntimeGraph> GetActiveGraph() override;
    
    std::string AddNode(const std::string& graph_id, const ExecutionNode& node) override;
    bool RemoveNode(const std::string& graph_id, const std::string& node_id) override;
    bool UpdateNode(const std::string& graph_id, const ExecutionNode& node) override;
    std::optional<ExecutionNode> GetNode(const std::string& graph_id, const std::string& node_id) override;
    
    std::string AddEdge(const std::string& graph_id, const ExecutionEdge& edge) override;
    bool RemoveEdge(const std::string& graph_id, const std::string& edge_id) override;
    std::vector<ExecutionEdge> GetNodeEdges(const std::string& graph_id, const std::string& node_id) override;
    
    std::string ExecuteRequest(const std::string& request_type,
                                const std::unordered_map<std::string, std::string>& params) override;
    std::optional<ExecutionContext> GetExecutionContext(const std::string& context_id) override;
    bool CancelExecution(const std::string& context_id) override;
    std::vector<ExecutionContext> GetActiveExecutions() override;
    
    bool ValidateGraph(const std::string& graph_id) override;
    std::vector<std::string> GetValidationErrors(const std::string& graph_id) override;
    bool IsGraphValid(const std::string& graph_id) override;
    
    RuntimeGraphStatistics GetStatistics(const std::string& graph_id = "") override;
    
private:
    std::unordered_map<std::string, RuntimeGraph> graphs_;
    std::unordered_map<std::string, ExecutionContext> executions_;
    std::string active_graph_id_;
    bool initialized_ = false;
    
    bool ExecuteNode(ExecutionContext& context, const ExecutionNode& node);
    std::optional<std::string> GetNextNode(const ExecutionContext& context, const ExecutionNode& current);
    bool ValidateNode(const ExecutionNode& node, std::vector<std::string>& errors);
    bool ValidateEdge(const ExecutionEdge& edge, const RuntimeGraph& graph, std::vector<std::string>& errors);
};

// Global unified runtime graph
extern std::unique_ptr<IUnifiedRuntimeGraph> g_unified_runtime_graph;

// Initialize unified runtime graph
bool InitializeUnifiedRuntimeGraph(const std::string& config_path);
void ShutdownUnifiedRuntimeGraph();
bool IsUnifiedRuntimeGraphEnabled();

// Node type helpers
std::string ExecutionNodeTypeToString(ExecutionNodeType type);
ExecutionNodeType ExecutionNodeTypeFromString(const std::string& str);

} // namespace Convergence
} // namespace RawrXD
