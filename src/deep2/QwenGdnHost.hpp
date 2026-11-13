// QwenGdnHost.hpp — Qwen3.5/3.6 GDN layout detect + product recurrence step.
// Distinct from Nemotron Mamba-2 (ssm_in/ssm_d). Fail-closed if incomplete.
#pragma once

#include "Deep2Engine.h"
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {

inline bool GdnWtOk(const WeightTensor& w) {
    return w.data != nullptr && w.sizeBytes > 0;
}

// Descriptor-only: true when GDN tensors are bound even before residency
// materializes data pointers (topology / KV sizing must not wait on acquire).
inline bool GdnWtBound(const WeightTensor& w) {
    return w.data != nullptr || w.sizeBytes != 0 || w.rows != 0 || w.cols != 0;
}

// Qwen GDN: attn_qkv + attn_gate + ssm_{a,alpha,beta,conv,dt,norm,out}; NO ssm_in.
inline bool IsQwenGdnLayer(const LayerWeights& lw) {
    return GdnWtOk(lw.wqkv) && GdnWtOk(lw.attnO) && GdnWtOk(lw.ssmA) &&
           GdnWtOk(lw.ssmAlpha) && GdnWtOk(lw.ssmBeta) && GdnWtOk(lw.ssmConv1d) &&
           GdnWtOk(lw.ssmDtBias) && GdnWtOk(lw.ssmNorm) && GdnWtOk(lw.ssmOut) &&
           !GdnWtOk(lw.ssmIn);
}

inline bool IsQwenGdnLayerBound(const LayerWeights& lw) {
    return GdnWtBound(lw.wqkv) && GdnWtBound(lw.attnO) && GdnWtBound(lw.ssmA) &&
           GdnWtBound(lw.ssmAlpha) && GdnWtBound(lw.ssmBeta) && GdnWtBound(lw.ssmConv1d) &&
           GdnWtBound(lw.ssmDtBias) && GdnWtBound(lw.ssmNorm) && GdnWtBound(lw.ssmOut) &&
           !GdnWtBound(lw.ssmIn);
}

inline bool IsNemotronSsmLayer(const LayerWeights& lw) {
    return lw.hasSSM && GdnWtOk(lw.ssmIn) && !IsQwenGdnLayer(lw);
}

struct QwenGdnMeta {
    uint32_t stateSize = 0;
    uint32_t groupCount = 0;
    uint32_t innerSize = 0;
    uint32_t convKernel = 4;
    bool bound = false;
};

// Product recurrence matching runtime_graph_executor::OpGdn (post-projection).
// On success, `recurrentOut` holds gated GDN output (pre ssm_out projection).
bool RunQwenGdnRecurrence(const LayerWeights& lw, const QwenGdnMeta& meta,
                          const std::vector<float>& qkv,
                          const std::vector<float>& gate,
                          const std::vector<float>& alpha,
                          const std::vector<float>& beta,
                          std::vector<float>& state,
                          std::vector<float>& convState,
                          uint8_t& gpuActive, uint64_t stateKey,
                          std::vector<float>& recurrentOut,
                          std::string& err);

} // namespace Deep2
