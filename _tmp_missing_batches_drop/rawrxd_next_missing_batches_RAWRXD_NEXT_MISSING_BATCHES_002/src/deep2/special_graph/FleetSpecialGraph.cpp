#include "FleetSpecialGraph.hpp"

#include <algorithm>
#include <limits>

namespace Deep2::SpecialGraph {
namespace {

RuntimeMeta mergeMeta(RuntimeMeta base, const RuntimeMeta& supplied) noexcept {
    if (supplied.layerCount) base.layerCount = supplied.layerCount;
    if (supplied.expertCount) base.expertCount = supplied.expertCount;
    if (supplied.expertsPerToken) base.expertsPerToken = supplied.expertsPerToken;
    if (supplied.sharedExperts) base.sharedExperts = supplied.sharedExperts;
    if (supplied.kvHeads) base.kvHeads = supplied.kvHeads;
    if (supplied.headDim) base.headDim = supplied.headDim;
    if (supplied.contextLength) base.contextLength = supplied.contextLength;
    if (supplied.usesMla) base.usesMla = true;
    return base;
}

std::uint32_t append(Graph& g, Op op, std::int32_t layer, std::string name) {
    const auto id = static_cast<std::uint32_t>(g.nodes.size());
    g.nodes.push_back(Node{id, op, layer, std::move(name)});
    if (id != 0) g.edges.push_back(Edge{id - 1, id});
    return id;
}

void appendDenseAttentionLayer(Graph& g, std::uint32_t layer) {
    const auto L = static_cast<std::int32_t>(layer);
    append(g, Op::PreAttentionNorm, L, "layer." + std::to_string(layer) + ".pre_attn_norm");
    append(g, Op::AttentionQKV, L, "layer." + std::to_string(layer) + ".qkv");
    append(g, Op::AttentionRoPE, L, "layer." + std::to_string(layer) + ".rope");
    append(g, Op::AttentionScores, L, "layer." + std::to_string(layer) + ".scores");
    append(g, Op::AttentionSoftmax, L, "layer." + std::to_string(layer) + ".softmax");
    append(g, Op::AttentionValue, L, "layer." + std::to_string(layer) + ".value");
    append(g, Op::AttentionOutput, L, "layer." + std::to_string(layer) + ".attn_out");
    append(g, Op::AttentionResidual, L, "layer." + std::to_string(layer) + ".attn_residual");
}

void appendMlaLayer(Graph& g, std::uint32_t layer) {
    const auto L = static_cast<std::int32_t>(layer);
    append(g, Op::PreAttentionNorm, L, "layer." + std::to_string(layer) + ".pre_attn_norm");
    append(g, Op::MLALatentProjection, L, "layer." + std::to_string(layer) + ".mla_latent");
    append(g, Op::AttentionRoPE, L, "layer." + std::to_string(layer) + ".rope");
    append(g, Op::MLAAttention, L, "layer." + std::to_string(layer) + ".mla_attention");
    append(g, Op::AttentionOutput, L, "layer." + std::to_string(layer) + ".attn_out");
    append(g, Op::AttentionResidual, L, "layer." + std::to_string(layer) + ".attn_residual");
}

void appendMoeLayer(Graph& g, std::uint32_t layer) {
    const auto L = static_cast<std::int32_t>(layer);
    append(g, Op::PreFfnNorm, L, "layer." + std::to_string(layer) + ".pre_ffn_norm");
    append(g, Op::MoERouter, L, "layer." + std::to_string(layer) + ".moe_router");
    append(g, Op::ExpertDispatch, L, "layer." + std::to_string(layer) + ".expert_dispatch");
    append(g, Op::RoutedExperts, L, "layer." + std::to_string(layer) + ".routed_experts");
    if (g.meta.sharedExperts) {
        append(g, Op::SharedExpert, L, "layer." + std::to_string(layer) + ".shared_expert");
    }
    append(g, Op::ExpertReduce, L, "layer." + std::to_string(layer) + ".expert_reduce");
    append(g, Op::FfnResidual, L, "layer." + std::to_string(layer) + ".ffn_residual");
}

} // namespace

RuntimeMeta contractDefaults(Family family) noexcept {
    // Values below are only fields explicitly present in the current RawrXD
    // fleet contracts. Unknown DeepSeek-V4 geometry remains zero and must be
    // supplied from admitted runtime GGUF metadata; it is never invented here.
    switch (family) {
        case Family::GptOss120B:
            return RuntimeMeta{36, 128, 4, 0, 0, 0, 131072, false};
        case Family::LagunaS21:
            return RuntimeMeta{48, 256, 10, 1, 8, 128, 1048576, false};
        case Family::DeepSeekV4Flash:
            return RuntimeMeta{0, 0, 0, 0, 0, 0, 1000000, true};
    }
    return {};
}

Graph build(Family family, RuntimeMeta runtimeMeta) {
    Graph g;
    g.family = family;
    g.meta = mergeMeta(contractDefaults(family), runtimeMeta);

    append(g, Op::TokenEmbedding, -1, "token_embedding");
    for (std::uint32_t layer = 0; layer < g.meta.layerCount; ++layer) {
        if (g.meta.usesMla) appendMlaLayer(g, layer);
        else appendDenseAttentionLayer(g, layer);
        appendMoeLayer(g, layer);
    }
    append(g, Op::FinalNorm, -1, "final_norm");
    append(g, Op::LMHead, -1, "lm_head");
    append(g, Op::Logits, -1, "logits");
    return g;
}

Validation validate(const Graph& g) noexcept {
    auto fail = [](const char* reason) { return Validation{false, reason}; };
    if (g.meta.layerCount == 0) return fail("layerCount missing from admitted runtime metadata");
    if (g.meta.expertCount == 0) return fail("expertCount missing from admitted runtime metadata");
    if (g.meta.expertsPerToken == 0) return fail("expertsPerToken missing from admitted runtime metadata");
    if (g.meta.expertsPerToken > g.meta.expertCount) return fail("expertsPerToken exceeds expertCount");
    if (g.meta.contextLength == 0) return fail("contextLength is zero");
    if (g.family == Family::LagunaS21 && (g.meta.kvHeads == 0 || g.meta.headDim == 0)) {
        return fail("Laguna KV-head/head-dim geometry missing");
    }
    if (g.family == Family::DeepSeekV4Flash && !g.meta.usesMla) {
        return fail("DeepSeek-V4 graph requires MLA runtime path");
    }
    if (g.nodes.empty()) return fail("graph has no nodes");
    if (g.nodes.front().op != Op::TokenEmbedding) return fail("graph does not start at embedding");
    if (g.nodes.back().op != Op::Logits) return fail("graph does not terminate at logits");
    if (g.edges.size() + 1 != g.nodes.size()) return fail("graph must be a deterministic linear execution plan");
    for (std::size_t i = 0; i < g.nodes.size(); ++i) {
        if (g.nodes[i].id != i) return fail("node IDs are not dense");
    }
    for (const auto& e : g.edges) {
        if (e.from >= g.nodes.size() || e.to >= g.nodes.size() || e.to != e.from + 1) {
            return fail("invalid graph edge");
        }
    }

    const auto countOp = [&](Op op) {
        return static_cast<std::uint32_t>(std::count_if(g.nodes.begin(), g.nodes.end(),
            [op](const Node& n) { return n.op == op; }));
    };
    if (countOp(Op::MoERouter) != g.meta.layerCount) return fail("MoE router count mismatch");
    if (countOp(Op::RoutedExperts) != g.meta.layerCount) return fail("routed expert count mismatch");
    if (g.meta.sharedExperts && countOp(Op::SharedExpert) != g.meta.layerCount) {
        return fail("shared expert count mismatch");
    }
    if (g.meta.usesMla && countOp(Op::MLAAttention) != g.meta.layerCount) {
        return fail("MLA attention count mismatch");
    }
    if (!g.meta.usesMla && countOp(Op::AttentionScores) != g.meta.layerCount) {
        return fail("dense attention count mismatch");
    }
    return {true, {}};
}

const char* toString(Family family) noexcept {
    switch (family) {
        case Family::GptOss120B: return "GPT_OSS_120B";
        case Family::LagunaS21: return "LAGUNA_S_2_1_118B";
        case Family::DeepSeekV4Flash: return "DEEPSEEK_V4_FLASH";
    }
    return "UNKNOWN";
}

const char* toString(Op op) noexcept {
    switch (op) {
        case Op::TokenEmbedding: return "TokenEmbedding";
        case Op::PreAttentionNorm: return "PreAttentionNorm";
        case Op::AttentionQKV: return "AttentionQKV";
        case Op::AttentionRoPE: return "AttentionRoPE";
        case Op::MLALatentProjection: return "MLALatentProjection";
        case Op::MLAAttention: return "MLAAttention";
        case Op::AttentionScores: return "AttentionScores";
        case Op::AttentionSoftmax: return "AttentionSoftmax";
        case Op::AttentionValue: return "AttentionValue";
        case Op::AttentionOutput: return "AttentionOutput";
        case Op::AttentionResidual: return "AttentionResidual";
        case Op::PreFfnNorm: return "PreFfnNorm";
        case Op::MoERouter: return "MoERouter";
        case Op::ExpertDispatch: return "ExpertDispatch";
        case Op::RoutedExperts: return "RoutedExperts";
        case Op::SharedExpert: return "SharedExpert";
        case Op::ExpertReduce: return "ExpertReduce";
        case Op::FfnResidual: return "FfnResidual";
        case Op::FinalNorm: return "FinalNorm";
        case Op::LMHead: return "LMHead";
        case Op::Logits: return "Logits";
    }
    return "Unknown";
}

} // namespace Deep2::SpecialGraph
