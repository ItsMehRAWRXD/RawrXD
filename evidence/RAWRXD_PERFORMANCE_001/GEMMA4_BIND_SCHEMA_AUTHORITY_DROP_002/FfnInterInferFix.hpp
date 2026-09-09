#pragma once
// ============================================================================
// FfnInterInferFix.hpp
// Source-only Deep2 drop 002: stop deriving intermediateDim from doubled fused
// Phi-3/Gemma-style gate|up rows. Prefer ffn_down input width when it proves the
// half-width; sync modelWeights + config after repair.
// ============================================================================

#include "GGUFLoader.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <map>
#include <string>

namespace Deep2::ffn_inter_fix {

inline std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

inline int ParseLayerIndex(const std::string& raw) {
    const std::string s = Lower(raw);
    const char* pats[] = {"blk.", "model.layers.", "layers.", "transformer.h."};
    for (const char* p : pats) {
        const std::size_t pos = s.find(p);
        if (pos == std::string::npos) continue;
        std::size_t i = pos + std::string(p).size();
        if (i >= s.size() || !std::isdigit((unsigned char)s[i])) continue;
        int v = 0;
        while (i < s.size() && std::isdigit((unsigned char)s[i])) {
            v = v * 10 + (s[i] - '0');
            ++i;
        }
        return v;
    }
    return -1;
}

inline std::uint64_t Dim0(const TensorInfo& t) noexcept {
    return t.dimensions.size() > 0 ? (std::uint64_t)t.dimensions[0] : 0ull;
}
inline std::uint64_t Dim1(const TensorInfo& t) noexcept {
    return t.dimensions.size() > 1 ? (std::uint64_t)t.dimensions[1] : 0ull;
}

struct LayerFfnShape {
    std::uint64_t upOut = 0;    // GGUF dims [input, output] => Dim1
    std::uint64_t gateOut = 0;  // Dim1
    std::uint64_t downIn = 0;   // Dim0
    bool hasUp = false;
    bool hasGate = false;
    bool hasDown = false;
};

inline bool IsUpName(const std::string& n) {
    return n.find("ffn_up.weight") != std::string::npos ||
           n.find("mlp.up_proj.weight") != std::string::npos ||
           n.find("mlp.up.weight") != std::string::npos ||
           n.find("feed_forward.w3") != std::string::npos;
}
inline bool IsGateName(const std::string& n) {
    return n.find("ffn_gate.weight") != std::string::npos ||
           n.find("mlp.gate_proj.weight") != std::string::npos ||
           n.find("mlp.gate.weight") != std::string::npos ||
           n.find("feed_forward.w1") != std::string::npos;
}
inline bool IsDownName(const std::string& n) {
    return n.find("ffn_down.weight") != std::string::npos ||
           n.find("mlp.down_proj.weight") != std::string::npos ||
           n.find("mlp.down.weight") != std::string::npos ||
           n.find("feed_forward.w2") != std::string::npos;
}

inline std::uint64_t InferIntermediateFromTensorSet(const GGUFLoadResult& load,
                                                    const ModelMetadata& meta,
                                                    const char** reason = nullptr) {
    std::map<int, LayerFfnShape> layers;
    for (const TensorInfo& t : load.tensors) {
        if (t.dimensions.size() < 2) continue;
        const int li = ParseLayerIndex(t.name);
        if (li < 0) continue;
        const std::string n = Lower(t.name);
        auto& s = layers[li];
        if (IsUpName(n)) {
            s.hasUp = true;
            s.upOut = Dim1(t);
        } else if (IsGateName(n)) {
            s.hasGate = true;
            s.gateOut = Dim1(t);
        } else if (IsDownName(n)) {
            s.hasDown = true;
            s.downIn = Dim0(t);
        }
    }

    for (const auto& kv : layers) {
        const auto& s = kv.second;
        if (s.hasDown && s.downIn > 0) {
            if (s.hasUp && !s.hasGate && s.upOut == 2 * s.downIn) {
                if (reason) *reason = "FUSED_UP_2X_DOWN_HALF";
                return s.downIn;
            }
            if (s.hasGate && s.gateOut == s.downIn) {
                if (reason) *reason = "SPLIT_GATE_MATCHES_DOWN";
                return s.downIn;
            }
            if (!s.hasUp || s.upOut == s.downIn) {
                if (reason) *reason = "DOWN_INPUT_WIDTH";
                return s.downIn;
            }
        }
    }

    if (meta.intermediateSize > 0) {
        if (reason) *reason = "META_EXISTING";
        return meta.intermediateSize;
    }
    if (reason) *reason = "UNOBSERVED";
    return 0;
}

template <typename ModelWeightsT, typename EngineConfigT>
inline bool RepairIntermediate(GGUFLoadResult& load, ModelWeightsT& mw, EngineConfigT& cfg,
                               FILE* f = stderr) noexcept {
    const char* why = "UNSET";
    const std::uint64_t inter = InferIntermediateFromTensorSet(load, load.metadata, &why);
    if (inter == 0 || inter > std::numeric_limits<std::uint32_t>::max()) {
        if (f) std::fprintf(f, "FFN_INTER_INFERRED ok=0 why=%s\n", why ? why : "null");
        return false;
    }
    const std::uint64_t oldMeta = load.metadata.intermediateSize;
    const std::uint64_t oldMw = mw.intermediateDim;
    const std::uint64_t oldCfg = cfg.intermediateDim;
    load.metadata.intermediateSize = (std::uint32_t)inter;
    mw.intermediateDim = (std::size_t)inter;
    cfg.intermediateDim = (std::size_t)inter;
    if (f) {
        std::fprintf(f,
            "FFN_INTER_INFERRED ok=1 why=%s inter=%llu old_meta=%llu old_model=%llu old_config=%llu\n",
            why ? why : "null", (unsigned long long)inter,
            (unsigned long long)oldMeta, (unsigned long long)oldMw,
            (unsigned long long)oldCfg);
        std::fflush(f);
    }
    return true;
}

} // namespace Deep2::ffn_inter_fix
