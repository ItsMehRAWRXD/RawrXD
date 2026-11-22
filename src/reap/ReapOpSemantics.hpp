// ReapOpSemantics.hpp — REAP-AutoFit R05/R06
//
// Layer-level op semantics for the DeepSeek2 family: attention (MLA-style with
// a single latent KV head) and MoE routing (router -> top-k -> expert FFN +
// shared expert). Every SemanticOp references a PHYSICAL tensor index; nothing
// is duplicated. KV-cache geometry is derived from discovered metadata
// (head_count, head_count_kv, embedding_length); exact MLA latent dims require
// additional GGUF keys and are reported separately when present.

#pragma once

#include "reap/ReapCanonicalIR.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace reap {

enum class OpRole {
    AttnQ, AttnK, AttnV, AttnOutput, AttnNorm,
    RouterInput, RouterBias, ExpertGate, ExpertUp, ExpertDown, SharedExpert,
    FfnNorm, Embedding, OutputHead, Other
};

inline OpRole FamilyToRole(const std::string& f) {
    if (f == "attention_q")      return OpRole::AttnQ;
    if (f == "attention_k")      return OpRole::AttnK;
    if (f == "attention_v")      return OpRole::AttnV;
    if (f == "attention_output") return OpRole::AttnOutput;
    if (f == "attention_norm")   return OpRole::AttnNorm;
    if (f == "router_input")     return OpRole::RouterInput;
    if (f == "router_bias")      return OpRole::RouterBias;
    if (f == "expert_gate")      return OpRole::ExpertGate;
    if (f == "expert_up")        return OpRole::ExpertUp;
    if (f == "expert_down")      return OpRole::ExpertDown;
    if (f == "shared_expert")    return OpRole::SharedExpert;
    if (f == "ffn_norm")         return OpRole::FfnNorm;
    if (f == "embedding")        return OpRole::Embedding;
    if (f == "output_head")      return OpRole::OutputHead;
    return OpRole::Other;
}

struct SemanticOp {
    OpRole   role = OpRole::Other;
    uint32_t physicalTensorIndex = 0;   // index into CanonicalIR::tensors
    uint32_t expertIndex = UINT32_MAX;  // for expert FFN ops; UINT32_MAX = n/a
};

struct LayerSemantics {
    std::vector<SemanticOp> attention;   // Q/K/V/O + norms
    std::vector<SemanticOp> moe;         // router + experts + shared expert
    uint32_t kvHeads = 0;                // attention.head_count_kv (MLA latent = 1)
    uint32_t headDim = 0;                // embedding_length / head_count
    uint64_t kvCachePerToken = 0;        // kvHeads * headDim (structural)
    uint32_t topK = 0;                   // experts routed per token
};

// Build the semantics for one physical layer from the canonical IR.
inline LayerSemantics BuildLayerSemantics(const CanonicalIR& ir, uint32_t physicalLayer) {
    LayerSemantics ls;
    ls.kvHeads = static_cast<uint32_t>(ir.geometry.attentionHeadCountKV);
    ls.headDim = ir.geometry.attentionHeadCount > 0
        ? static_cast<uint32_t>(ir.geometry.embeddingLength / ir.geometry.attentionHeadCount)
        : 0;
    ls.kvCachePerToken = static_cast<uint64_t>(ls.kvHeads) * ls.headDim;
    ls.topK = static_cast<uint32_t>(ir.geometry.expertUsedCount);

    for (size_t i = 0; i < ir.tensors.size(); ++i) {
        const auto& t = ir.tensors[i];
        if (t.layerIndex != physicalLayer) continue;
        SemanticOp op;
        op.role = FamilyToRole(t.family);
        op.physicalTensorIndex = static_cast<uint32_t>(i);
        switch (op.role) {
            case OpRole::AttnQ: case OpRole::AttnK: case OpRole::AttnV:
            case OpRole::AttnOutput: case OpRole::AttnNorm:
                ls.attention.push_back(op); break;
            case OpRole::RouterInput: case OpRole::RouterBias:
            case OpRole::ExpertGate: case OpRole::ExpertUp:
            case OpRole::ExpertDown: case OpRole::SharedExpert:
                ls.moe.push_back(op); break;
            default: break;   // norms / other handled separately
        }
    }
    return ls;
}

// Build semantics for every physical layer (0..blockCount-1).
inline std::vector<LayerSemantics> BuildAllLayerSemantics(const CanonicalIR& ir) {
    std::vector<LayerSemantics> out;
    for (uint64_t L = 0; L < ir.geometry.blockCount; ++L)
        out.push_back(BuildLayerSemantics(ir, static_cast<uint32_t>(L)));
    return out;
}

// Count attention/moe ops of a given role across all layers (diagnostic).
inline uint64_t CountRole(const std::vector<LayerSemantics>& layers, OpRole role) {
    uint64_t n = 0;
    for (const auto& ls : layers) {
        for (const auto& op : ls.attention) if (op.role == role) ++n;
        for (const auto& op : ls.moe)       if (op.role == role) ++n;
    }
    return n;
}

} // namespace reap