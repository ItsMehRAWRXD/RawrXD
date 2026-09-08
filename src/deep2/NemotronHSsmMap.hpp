// NemotronHSsmMap.hpp — Nemotron-H SSM tensor owners + layer kind.
#pragma once
#include "Deep2Engine.h"
#include <cstdio>

namespace Deep2 {

enum class NemotronLayerKind : uint8_t {
    Attention = 0,
    SSM = 1,
    Hybrid = 2,
    FFN = 3,
    Unknown = 4
};

inline bool WtOk(const WeightTensor& w) {
    return w.data != nullptr && w.sizeBytes > 0;
}

inline bool AttnReady(const LayerWeights& lw) {
    return WtOk(lw.wq) || WtOk(lw.wqkv) || lw.useMLA;
}

inline bool SsmNemotronComplete(const LayerWeights& lw) {
    return WtOk(lw.ssmIn) && WtOk(lw.ssmOut) && WtOk(lw.ssmA) && WtOk(lw.ssmD) &&
           WtOk(lw.ssmDtBias) && WtOk(lw.ssmConv1d) && WtOk(lw.ssmConv1dBias) &&
           WtOk(lw.ssmNorm);
}

inline bool SsmLegacyComplete(const LayerWeights& lw) {
    return WtOk(lw.ssmAlpha) && WtOk(lw.ssmBeta) && WtOk(lw.ssmOut) &&
           WtOk(lw.ssmA) && WtOk(lw.ssmDtBias);
}

inline NemotronLayerKind ClassifyLayer(const LayerWeights& lw) {
    const bool attn = AttnReady(lw);
    const bool ssm = lw.hasSSM;
    const bool ffn = WtOk(lw.wGate) || WtOk(lw.wUp);
    if (ssm && attn) return NemotronLayerKind::Hybrid;
    if (ssm && !attn) return NemotronLayerKind::SSM;
    if (attn && !ssm) return NemotronLayerKind::Attention;
    if (ffn && !attn && !ssm) return NemotronLayerKind::FFN;
    return NemotronLayerKind::Unknown;
}

inline const char* LayerKindString(NemotronLayerKind k) {
    switch (k) {
    case NemotronLayerKind::Attention: return "ATTENTION";
    case NemotronLayerKind::SSM: return "SSM";
    case NemotronLayerKind::Hybrid: return "HYBRID";
    case NemotronLayerKind::FFN: return "FFN";
    default: return "UNKNOWN";
    }
}

struct NemotronMapStatus {
    int ssmLayers = 0;
    int mapOk = 0;
    int mapFail = 0;
    int ssmInMissing = 0;
    int ssmDMissing = 0;
    int ssmConvBiasMissing = 0;
    int attnQNullLayer0 = 0;
    int hybridRoute = 0;
    int complete = 0;
};

inline NemotronMapStatus AssessNemotronSsmMap(const ModelWeights& mw) {
    NemotronMapStatus s{};
    for (size_t i = 0; i < mw.layers.size(); ++i) {
        const auto& lw = mw.layers[i];
        if (!lw.hasSSM) continue;
        ++s.ssmLayers;
        const bool ok = SsmNemotronComplete(lw) || SsmLegacyComplete(lw);
        if (ok) ++s.mapOk;
        else {
            ++s.mapFail;
            if (!WtOk(lw.ssmIn) && !WtOk(lw.ssmAlpha)) ++s.ssmInMissing;
            if (!WtOk(lw.ssmD) && !WtOk(lw.ssmBeta)) ++s.ssmDMissing;
            if (!WtOk(lw.ssmConv1dBias) && !WtOk(lw.ssmConv1d))
                ++s.ssmConvBiasMissing;
        }
        if (ClassifyLayer(lw) == NemotronLayerKind::SSM ||
            ClassifyLayer(lw) == NemotronLayerKind::Hybrid)
            ++s.hybridRoute;
    }
    if (!mw.layers.empty() && !AttnReady(mw.layers[0]))
        s.attnQNullLayer0 = 1;
    s.complete = (s.ssmLayers > 0 && s.mapFail == 0) ? 1 : 0;
    if (s.ssmLayers == 0) s.complete = 1;
    return s;
}

inline void EmitNemotronTensorMap(FILE* f, const ModelWeights& mw,
                                  const char* arch) {
    if (!f) return;
    const NemotronMapStatus s = AssessNemotronSsmMap(mw);
    const int fail = (s.ssmLayers > 0 && !s.complete) ? 1 : 0;
    std::fprintf(f, "NEMOTRON_H_TENSOR_MAP_001=%s\n", fail ? "FAIL" : "PASS");
    std::fprintf(f, "ARCH=%s\nSSM_HYBRID_LAYERS=%d\n",
                 arch ? arch : "?", s.ssmLayers);
    std::fprintf(f, "SSM_TENSOR_MAP_COMPLETE=%d\n", s.complete);
    std::fprintf(f, "SSM_IN_MISSING=%d\nSSM_D_MISSING=%d\n",
                 s.ssmInMissing > 0, s.ssmDMissing > 0);
    std::fprintf(f, "SSM_CONV_BIAS_MISSING=%d\nATTN_Q_NULL_LAYER0=%d\n",
                 s.ssmConvBiasMissing > 0, s.attnQNullLayer0);
    std::fprintf(f, "HYBRID_LAYER_ROUTE=%d\n", s.hybridRoute > 0 ? 1 : 0);
    const size_t n = mw.layers.size() < 8 ? mw.layers.size() : 8;
    for (size_t i = 0; i < n; ++i) {
        const auto& lw = mw.layers[i];
        const auto k = ClassifyLayer(lw);
        std::fprintf(f, "LAYER_%02zu_KIND=%s\nLAYER_%02zu_ATTN_READY=%d\n",
                     i, LayerKindString(k), i, AttnReady(lw) ? 1 : 0);
        std::fprintf(f, "LAYER_%02zu_SSM_READY=%d\n", i,
                     (SsmNemotronComplete(lw) || SsmLegacyComplete(lw)) ? 1 : 0);
    }
    std::fflush(f);
}

} // namespace Deep2
