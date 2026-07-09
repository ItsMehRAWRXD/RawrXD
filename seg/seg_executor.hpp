#pragma once
#include "seg_graph.hpp"
#include "seg_memory.hpp"
#include "seg_node.hpp"
#include <cstdint>

// Forward declaration - adjust path as needed for your project
namespace RawrXD { namespace Runtime {
    class StreamingMultiLayerBackend;
}}

namespace seg {

// Execution context for a single inference step
struct ExecutionContext {
    uint32_t token_id;
    uint32_t position;
    uint32_t layer_idx;  // Current layer being executed
};

class Executor {
public:
    Executor(Memory& mem,
             RawrXD::Runtime::StreamingMultiLayerBackend& backend)
        : m_mem(mem), m_backend(backend), m_current_layer(0) {}

    // Execute full graph for one token
    void Run(const Graph& graph, uint32_t token_id, uint32_t position);
    
    // Execute individual node with telemetry
    void ExecuteNode(const Node& node, ExecutionContext& ctx);
    
    // Get current layer index (for tracking)
    uint32_t GetCurrentLayer() const { return m_current_layer; }

private:
    Memory& m_mem;
    RawrXD::Runtime::StreamingMultiLayerBackend& m_backend;
    uint32_t m_current_layer;
    
    // Node execution helpers
    void ExecuteEmbedding(const Node& node, ExecutionContext& ctx);
    void ExecuteRMSNorm(const Node& node, ExecutionContext& ctx);
    void ExecuteQKVProjection(const Node& node, ExecutionContext& ctx);
    void ExecuteAttention(const Node& node, ExecutionContext& ctx);
    void ExecuteMLP(const Node& node, ExecutionContext& ctx);
    void ExecuteResidual(const Node& node, ExecutionContext& ctx);
    void ExecuteOutputProjection(const Node& node, ExecutionContext& ctx);
    void ExecuteLogits(const Node& node, ExecutionContext& ctx);
    void ExecuteSampleToken(const Node& node, ExecutionContext& ctx);
};

} // namespace seg
