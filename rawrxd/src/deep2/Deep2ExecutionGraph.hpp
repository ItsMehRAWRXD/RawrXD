#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace rawrxd::deep2 {

// ───────────────────────────────────────────────────────────────
// Execution node types
// ───────────────────────────────────────────────────────────────
enum class NodeType {
    Input,
    Output,
    MatMul,
    Attention,
    RMSNorm,
    SiLU,
    Embedding,
    Softmax,
    Reshape,
    Concat,
    Split,
    CustomOp
};

struct ExecNode {
    uint64_t id = 0;
    NodeType type = NodeType::CustomOp;
    std::string name;
    std::string op_type;
    std::vector<uint64_t> inputs;
    std::vector<uint64_t> outputs;
    std::map<std::string, std::string> attrs;
    uint32_t preferred_device_id = 0;
    float estimated_ms = 0.0f;
};

struct ExecEdge {
    uint64_t from = 0;
    uint64_t to = 0;
    std::string tensor_name;
    std::vector<int64_t> shape;
};

// ───────────────────────────────────────────────────────────────
// Execution graph — DAG-based inference pipeline
// ───────────────────────────────────────────────────────────────
class Deep2ExecutionGraph {
public:
    Deep2ExecutionGraph();
    ~Deep2ExecutionGraph();

    // Graph construction
    uint64_t AddNode(const ExecNode& node);
    bool RemoveNode(uint64_t node_id);
    bool AddEdge(const ExecEdge& edge);
    bool RemoveEdge(uint64_t from, uint64_t to);

    // Query
    std::optional<ExecNode> GetNode(uint64_t node_id) const;
    std::vector<ExecNode> GetNodes() const;
    std::vector<ExecEdge> GetEdges() const;
    std::vector<ExecNode> GetTopologicalOrder() const;
    std::vector<ExecNode> GetNodesByType(NodeType type) const;

    // Validation
    bool Validate() const;
    bool HasCycle() const;
    std::vector<std::string> GetErrors() const;

    // Execution
    bool Compile();
    bool IsCompiled() const;
    bool ExecuteNode(uint64_t node_id);
    bool ExecuteGraph();

    // Scheduling
    void SetDeviceAssignment(uint64_t node_id, uint32_t device_id);
    std::map<uint64_t, uint32_t> GetDeviceAssignments() const;

    // Profiling
    float GetEstimatedLatencyMs() const;
    void SetNodeLatency(uint64_t node_id, float ms);

    // Serialization
    std::string ToJSON() const;
    bool FromJSON(const std::string& json);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::deep2
