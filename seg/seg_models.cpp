#include "seg_models.hpp"

namespace seg {

Graph BuildLlamaForwardGraph(const LlamaGraphConfig& cfg) {
    Graph g;

    auto n_input  = g.AddNode(NodeKind::kInputToken, "input_token");
    auto n_embed  = g.AddNode(NodeKind::kEmbedding, "embedding");

    g.AddEdge(n_input, n_embed);

    NodeId prev = n_embed;
    for (uint32_t i = 0; i < cfg.num_layers; ++i) {
        auto n_norm1 = g.AddNode(NodeKind::kRMSNorm, "norm_" + std::to_string(i));
        auto n_qkv   = g.AddNode(NodeKind::kQKVProjection, "qkv_" + std::to_string(i));
        auto n_attn  = g.AddNode(NodeKind::kAttention, "attn_" + std::to_string(i));
        auto n_res1  = g.AddNode(NodeKind::kResidual, "res_" + std::to_string(i));

        g.AddEdge(prev, n_norm1);
        g.AddEdge(n_norm1, n_qkv);
        g.AddEdge(n_qkv, n_attn);
        g.AddEdge(prev, n_res1);
        g.AddEdge(n_attn, n_res1);

        auto n_norm2 = g.AddNode(NodeKind::kRMSNorm, "norm2_" + std::to_string(i));
        auto n_mlp   = g.AddNode(NodeKind::kMLP, "mlp_" + std::to_string(i));
        auto n_res2  = g.AddNode(NodeKind::kResidual, "res2_" + std::to_string(i));

        g.AddEdge(n_res1, n_norm2);
        g.AddEdge(n_norm2, n_mlp);
        g.AddEdge(n_res1, n_res2);
        g.AddEdge(n_mlp, n_res2);

        prev = n_res2;
    }

    auto n_out = g.AddNode(NodeKind::kOutputProjection, "output");
    auto n_logits = g.AddNode(NodeKind::kLogits, "logits");
    auto n_sample = g.AddNode(NodeKind::kSampleToken, "sample");

    g.AddEdge(prev, n_out);
    g.AddEdge(n_out, n_logits);
    g.AddEdge(n_logits, n_sample);

    return g;
}

} // namespace seg
