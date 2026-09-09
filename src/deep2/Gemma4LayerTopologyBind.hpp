#pragma once
// ============================================================================
// Gemma4LayerTopologyBind.hpp
// Source-only Deep2 drop 003: Gemma4 non-uniform layer topology binder.
//
// Scope:
//   - Clears the remaining Gemma4 attn_q authority blocker when a layer uses
//     blk.N.proj.weight instead of blk.N.attn_q.weight.
//   - Treats topology per layer; it does not assume every layer is llama-style.
//   - Does not fabricate runtime PASS or promote benchmark/TPS certificates.
//   - Header-only: no new .obj, no CMake edit, no external deps.
//
// Intended slots:
//   - Real split attention remains wq/wk/wv/(wo|attnO).
//   - Real fused QKV remains wqkv + output projection.
//   - Gemma4 projector-only layer stores blk.N.proj.weight in wqkv and is
//     executed by an explicit projector block in forwardLayer before the normal
//     attention path.
// ============================================================================

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace Deep2::gemma4_topology {

inline std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

inline bool EndsWith(const std::string& s, const char* suffix) {
    const std::string x = suffix ? suffix : "";
    return s.size() >= x.size() && s.compare(s.size() - x.size(), x.size(), x) == 0;
}

inline bool Contains(const std::string& s, const char* needle) {
    return needle && s.find(needle) != std::string::npos;
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

template <typename WeightTensorT>
inline bool WtLive(const WeightTensorT& wt) noexcept {
    return wt.data != nullptr && wt.rows > 0 && wt.cols > 0 && wt.sizeBytes > 0;
}

inline bool IsProjectorName(const std::string& raw) {
    const std::string n = Lower(raw);
    // Exact Gemma4 topology signal: blk.N.proj.weight. Do not match q_proj,
    // k_proj, v_proj, o_proj, gate_proj, up_proj, or down_proj.
    return EndsWith(n, ".proj.weight") &&
           !EndsWith(n, "q_proj.weight") &&
           !EndsWith(n, "k_proj.weight") &&
           !EndsWith(n, "v_proj.weight") &&
           !EndsWith(n, "o_proj.weight") &&
           !EndsWith(n, "gate_proj.weight") &&
           !EndsWith(n, "up_proj.weight") &&
           !EndsWith(n, "down_proj.weight");
}

inline bool LooksGemma4Arch(const std::string& arch) {
    const std::string a = Lower(arch);
    return Contains(a, "gemma4") || Contains(a, "gemma-4") ||
           Contains(a, "gemma_4") || a == "gemma4";
}

template <typename LayerWeightsT, typename WeightTensorT>
inline bool TryBindLayerTensor(LayerWeightsT& lw, const std::string& name,
                               const WeightTensorT& wt, FILE* f = stderr) {
    const std::string n = Lower(name);
    bool bound = false;
    const char* slot = "";

    // Non-uniform projector block. Store in existing fused/project slot so the
    // current structure stays source-only and ABI-neutral.
    if (IsProjectorName(n)) {
        lw.wqkv = wt;
        lw.wqkv.name = name;
        slot = "topology_proj";
        bound = true;
    }

    // Keep normal aliases here too so this header can be called before the
    // legacy llama bind without relying on Gemma4SchemaBinder's ordering.
    else if (EndsWith(n, "attn_q.weight") || EndsWith(n, "self_attn.q_proj.weight") ||
             EndsWith(n, "attention.q_proj.weight")) {
        lw.wq = wt; lw.wq.name = name; slot = "attn_q"; bound = true;
    } else if (EndsWith(n, "attn_k.weight") || EndsWith(n, "self_attn.k_proj.weight") ||
               EndsWith(n, "attention.k_proj.weight")) {
        lw.wk = wt; lw.wk.name = name; slot = "attn_k"; bound = true;
    } else if (EndsWith(n, "attn_v.weight") || EndsWith(n, "self_attn.v_proj.weight") ||
               EndsWith(n, "attention.v_proj.weight")) {
        lw.wv = wt; lw.wv.name = name; slot = "attn_v"; bound = true;
    } else if (EndsWith(n, "attn_o.weight") || EndsWith(n, "attn_output.weight") ||
               EndsWith(n, "self_attn.o_proj.weight") || EndsWith(n, "attention.o_proj.weight")) {
        lw.wo = wt; lw.wo.name = name;
        lw.attnO = wt; lw.attnO.name = name;
        slot = "attn_o"; bound = true;
    } else if (EndsWith(n, "attn_qkv.weight") || EndsWith(n, "self_attn.qkv_proj.weight")) {
        lw.wqkv = wt; lw.wqkv.name = name; slot = "attn_qkv"; bound = true;
    } else if (EndsWith(n, "attn_norm.weight") || EndsWith(n, "input_layernorm.weight") ||
               EndsWith(n, "pre_attention_layernorm.weight")) {
        lw.attnNorm = wt; lw.attnNorm.name = name; slot = "attn_norm"; bound = true;
    } else if (EndsWith(n, "ffn_norm.weight") || EndsWith(n, "post_attention_layernorm.weight") ||
               EndsWith(n, "pre_feedforward_layernorm.weight")) {
        lw.ffnNorm = wt; lw.ffnNorm.name = name; slot = "ffn_norm"; bound = true;
    } else if (EndsWith(n, "ffn_gate.weight") || EndsWith(n, "mlp.gate_proj.weight")) {
        lw.wGate = wt; lw.wGate.name = name; slot = "ffn_gate"; bound = true;
    } else if (EndsWith(n, "ffn_up.weight") || EndsWith(n, "mlp.up_proj.weight")) {
        lw.wUp = wt; lw.wUp.name = name; slot = "ffn_up"; bound = true;
    } else if (EndsWith(n, "ffn_down.weight") || EndsWith(n, "mlp.down_proj.weight")) {
        lw.wDown = wt; lw.wDown.name = name; slot = "ffn_down"; bound = true;
    }

    if (bound && f && std::strcmp(slot, "topology_proj") == 0) {
        std::fprintf(f,
            "GEMMA4_LAYER_TOPOLOGY_BIND source=%s layer=%d slot=%s rows=%zu cols=%zu type=%d\n",
            name.c_str(), ParseLayerIndex(name), slot, wt.rows, wt.cols, wt.type);
    }
    return bound;
}

template <typename LayerWeightsT>
inline bool IsProjectorBlock(const LayerWeightsT& lw) noexcept {
    return WtLive(lw.wqkv) && IsProjectorName(lw.wqkv.name) &&
           !WtLive(lw.wq) && !WtLive(lw.wk) && !WtLive(lw.wv);
}

template <typename LayerWeightsT>
inline bool HasSplitAttention(const LayerWeightsT& lw) noexcept {
    return WtLive(lw.wq) && WtLive(lw.wk) && WtLive(lw.wv) &&
           (WtLive(lw.wo) || WtLive(lw.attnO));
}

template <typename LayerWeightsT>
inline bool HasFusedQkvAttention(const LayerWeightsT& lw) noexcept {
    return WtLive(lw.wqkv) && !IsProjectorName(lw.wqkv.name) &&
           (WtLive(lw.wo) || WtLive(lw.attnO));
}

template <typename LayerWeightsT>
inline bool HasFfn(const LayerWeightsT& lw) noexcept {
    return WtLive(lw.wDown) && WtLive(lw.wUp) &&
           (WtLive(lw.wGate) || (lw.wDown.cols > 0 && lw.wUp.rows == 2 * lw.wDown.cols));
}

template <typename LayerWeightsT>
inline bool LayerAttentionAuthoritySatisfied(const LayerWeightsT& lw) noexcept {
    return HasSplitAttention(lw) || HasFusedQkvAttention(lw) || IsProjectorBlock(lw);
}

template <typename LayerWeightsT>
inline const char* LayerTopology(const LayerWeightsT& lw) noexcept {
    if (HasSplitAttention(lw)) return "split_attention";
    if (HasFusedQkvAttention(lw)) return "fused_qkv_attention";
    if (IsProjectorBlock(lw)) return "projector_block";
    if (HasFfn(lw)) return "ffn_only_or_pending_attention";
    return "unknown";
}

template <typename ModelWeightsT>
inline bool GeometryReady(const ModelWeightsT& mw, std::string* why = nullptr) {
    auto fail = [&](const char* s) {
        if (why) *why = s;
        return false;
    };
    if (!WtLive(mw.tokenEmbed)) return fail("NO_TOKEN_EMBED");
    if (mw.hiddenDim == 0) return fail("NO_HIDDEN");
    if (mw.layers.empty()) return fail("NO_LAYERS");

    std::size_t attnOk = 0, proj = 0, ffnOk = 0, checked = 0;
    for (std::size_t i = 0; i < mw.layers.size(); ++i) {
        const auto& lw = mw.layers[i];
        const bool attn = LayerAttentionAuthoritySatisfied(lw);
        const bool ffn = HasFfn(lw);
        if (attn) ++attnOk;
        if (IsProjectorBlock(lw)) ++proj;
        if (ffn) ++ffnOk;
        ++checked;
        if (!attn) return fail("NO_LAYER_ATTENTION_OR_PROJECTOR_TOPOLOGY");
        if (!ffn) return fail("NO_LAYER_FFN_TOPOLOGY");
    }
    if (why) {
        *why = proj ? "GEOM_READY_NON_UNIFORM_PROJECTOR" : "GEOM_READY_UNIFORM";
    }
    return checked > 0 && attnOk == checked && ffnOk == checked;
}

template <typename ModelWeightsT>
inline void EmitSummary(const ModelWeightsT& mw, FILE* f = stderr) {
    if (!f) return;
    std::string why;
    const bool ok = GeometryReady(mw, &why);
    std::size_t split = 0, fused = 0, proj = 0, unknown = 0, ffn = 0;
    for (std::size_t i = 0; i < mw.layers.size(); ++i) {
        const auto& lw = mw.layers[i];
        if (HasSplitAttention(lw)) ++split;
        else if (HasFusedQkvAttention(lw)) ++fused;
        else if (IsProjectorBlock(lw)) ++proj;
        else ++unknown;
        if (HasFfn(lw)) ++ffn;
    }
    std::fprintf(f,
        "GEMMA4_LAYER_TOPOLOGY_BIND ok=%d why=%s layers=%zu split=%zu fused_qkv=%zu projector=%zu ffn=%zu unknown=%zu\n",
        ok ? 1 : 0, why.c_str(), mw.layers.size(), split, fused, proj, ffn, unknown);
    std::fflush(f);
}

// Use from inside Deep2Engine::forwardLayer before the normal attention path.
// The lambdas let this stay header-only while calling private engine methods.
//
// Example:
//   if (Deep2::gemma4_topology::TryExecuteProjectorBlock(
//           lw, input, output, layerTemp, hiddenDim, modelWeights.normEps,
//           [&](const WeightTensor& w, const float* x, float* y, size_t n, float eps) {
//               RMSNormW(w, x, y, n, eps);
//           },
//           [&](const WeightTensor& w, const float* x, const float* b, float* y, size_t n) {
//               LinearW(w, x, b, y, n);
//           }, stderr)) return;
//
template <typename LayerWeightsT, typename NormFn, typename LinearFn>
inline bool TryExecuteProjectorBlock(const LayerWeightsT& lw,
                                     const float* input,
                                     float* output,
                                     float* temp,
                                     std::size_t hidden,
                                     float normEps,
                                     NormFn&& normW,
                                     LinearFn&& linearW,
                                     FILE* f = stderr) {
    if (!IsProjectorBlock(lw) || !input || !output || !temp || hidden == 0) return false;
    if (lw.wqkv.cols != hidden || lw.wqkv.rows != hidden) {
        if (f) {
            std::fprintf(f,
                "GEMMA4_PROJECTOR_LAYER_EXEC=0 reason=SHAPE rows=%zu cols=%zu hidden=%zu source=%s\n",
                lw.wqkv.rows, lw.wqkv.cols, hidden, lw.wqkv.name.c_str());
            std::fflush(f);
        }
        return false;
    }

    const auto& norm = WtLive(lw.attnNorm) ? lw.attnNorm : lw.ffnNorm;
    if (WtLive(norm)) {
        normW(norm, input, temp, hidden, normEps);
    } else {
        std::memcpy(temp, input, hidden * sizeof(float));
    }

    linearW(lw.wqkv, temp, nullptr, output, hidden);
    for (std::size_t i = 0; i < hidden; ++i) output[i] += input[i];

    if (f) {
        std::fprintf(f,
            "GEMMA4_PROJECTOR_LAYER_EXEC=1 topology=projector_block hidden=%zu source=%s\n",
            hidden, lw.wqkv.name.c_str());
        std::fflush(f);
    }
    return true;
}

} // namespace Deep2::gemma4_topology
