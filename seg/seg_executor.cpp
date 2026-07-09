#include "seg_executor.hpp"
#include "../runtime/streaming_multi_layer_backend.hpp"
#include "../runtime/telemetry_masm_bridge.hpp"
#include <iostream>
#include <cstring>

namespace seg {

void Executor::Run(const Graph& graph, uint32_t token_id, uint32_t position) {
    using namespace RawrXD::Runtime::Telemetry;
    
    // Full graph execution with telemetry
    MASM_TELEMETRY_SCOPE_VALUES(
        TELEMETRY_TRANSFORMER_FORWARD,
        TELEMETRY_TRANSFORMER_FORWARD + 1,
        token_id,
        position
    );
    
    // Get topological order
    auto topo = graph.TopologicalSort();
    
    // Reset layer counter
    m_current_layer = 0;
    
    // Execute each node in order
    ExecutionContext ctx{token_id, position, 0};
    
    for (NodeId nodeId : topo) {
        const Node* node = graph.GetNode(nodeId);
        if (!node) continue;
        
        ExecuteNode(*node, ctx);
    }
}

void Executor::ExecuteNode(const Node& node, ExecutionContext& ctx) {
    using namespace RawrXD::Runtime::Telemetry;
    
    // Per-node telemetry scope
    uint32_t nodePhase = TELEMETRY_LAYER_EXEC_START + static_cast<uint32_t>(node.kind);
    MASM_TELEMETRY_SCOPE_VALUES(nodePhase, nodePhase + 1, 
                                ctx.layer_idx, 
                                static_cast<uint64_t>(node.kind));
    
    switch (node.kind) {
        case NodeKind::kInputToken:
            // Input node - nothing to execute
            break;
            
        case NodeKind::kEmbedding:
            ExecuteEmbedding(node, ctx);
            break;
            
        case NodeKind::kRMSNorm:
            ExecuteRMSNorm(node, ctx);
            break;
            
        case NodeKind::kQKVProjection:
            ExecuteQKVProjection(node, ctx);
            break;
            
        case NodeKind::kAttention:
            ExecuteAttention(node, ctx);
            break;
            
        case NodeKind::kMLP:
            ExecuteMLP(node, ctx);
            break;
            
        case NodeKind::kResidual:
            ExecuteResidual(node, ctx);
            break;
            
        case NodeKind::kOutputProjection:
            ExecuteOutputProjection(node, ctx);
            break;
            
        case NodeKind::kLogits:
            ExecuteLogits(node, ctx);
            break;
            
        case NodeKind::kSampleToken:
            ExecuteSampleToken(node, ctx);
            break;
            
        default:
            std::cerr << "[SEG] Unknown node kind: " << static_cast<int>(node.kind) << "\n";
            break;
    }
}

void Executor::ExecuteEmbedding(const Node& node, ExecutionContext& ctx) {
    // Embedding is handled by backend's ExecuteToken
    // The backend loads the embedding for the token
    // For now, just track that we're at embedding phase
    (void)node;
    (void)ctx;
}

void Executor::ExecuteRMSNorm(const Node& node, ExecutionContext& ctx) {
    using namespace RawrXD::Runtime::Telemetry;
    MASM_TELEMETRY_SCOPE(TELEMETRY_OP_RMSNORM_START, TELEMETRY_OP_RMSNORM_END);
    
    // RMSNorm is part of backend's layer execution
    // In future: call dedicated RMSNorm kernel
    (void)node;
    (void)ctx;
}

void Executor::ExecuteQKVProjection(const Node& node, ExecutionContext& ctx) {
    using namespace RawrXD::Runtime::Telemetry;
    MASM_TELEMETRY_SCOPE_VALUES(TELEMETRY_OP_MATMUL_START, TELEMETRY_OP_MATMUL_END,
                                 ctx.layer_idx, 3);  // 3 projections
    
    // QKV is part of backend's layer execution
    (void)node;
    (void)ctx;
}

void Executor::ExecuteAttention(const Node& node, ExecutionContext& ctx) {
    using namespace RawrXD::Runtime::Telemetry;
    MASM_TELEMETRY_SCOPE_VALUES(TELEMETRY_OP_ATTN_START, TELEMETRY_OP_ATTN_END,
                                 ctx.position + 1, ctx.layer_idx);
    
    // Attention is part of backend's layer execution
    // Increment layer index after attention (completes one transformer block)
    ctx.layer_idx++;
    m_current_layer = ctx.layer_idx;
    
    (void)node;
}

void Executor::ExecuteMLP(const Node& node, ExecutionContext& ctx) {
    using namespace RawrXD::Runtime::Telemetry;
    MASM_TELEMETRY_SCOPE(TELEMETRY_OP_MLP_START, TELEMETRY_OP_MLP_END);
    
    // MLP is part of backend's layer execution
    (void)node;
    (void)ctx;
}

void Executor::ExecuteResidual(const Node& node, ExecutionContext& ctx) {
    // Residual connections are handled within backend
    // Future: explicit residual addition kernel
    (void)node;
    (void)ctx;
}

void Executor::ExecuteOutputProjection(const Node& node, ExecutionContext& ctx) {
    using namespace RawrXD::Runtime::Telemetry;
    MASM_TELEMETRY_SCOPE(TELEMETRY_LOGITS_PROJECTION, TELEMETRY_LOGITS_PROJECTION + 1);
    
    // Output projection is part of backend's ExecuteToken
    (void)node;
    (void)ctx;
}

void Executor::ExecuteLogits(const Node& node, ExecutionContext& ctx) {
    // Logits are computed by backend
    // This node represents the logits buffer
    (void)node;
    (void)ctx;
}

void Executor::ExecuteSampleToken(const Node& node, ExecutionContext& ctx) {
    // Token sampling is handled by backend or runtime
    // Future: call sampling kernel
    (void)node;
    (void)ctx;
}

} // namespace seg
