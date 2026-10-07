#pragma once
// ============================================================================
// Gemma4SchemaBinder.hpp
// Source-only Deep2 drop: bind Gemma/HF-style tensor names into Deep2 layer slots.
//
// Scope:
//   - Clears BLOCKED_AT=GEOM when tensors are present but use non-llama names.
//   - Does not fabricate tensors; every bind is backed by a real TensorInfo/WeightTensor.
//   - Header-only, no new .obj, no CMake edit.
// ============================================================================

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace Deep2::gemma4_schema {

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

template <typename ModelWeightsT, typename WeightTensorT>
inline bool TryBindRootTensor(ModelWeightsT& mw, const std::string& name,
                              const WeightTensorT& wt, FILE* f = stderr) {
    const std::string n = Lower(name);
    bool bound = false;
    if (n == "model.embed_tokens.weight" || n == "embed_tokens.weight" ||
        n == "token_embd.weight" || n == "token_embeddings.weight") {
        mw.tokenEmbed = wt;
        bound = true;
    } else if (n == "model.norm.weight" || n == "norm.weight" ||
               n == "output_norm.weight" || n == "final_layernorm.weight") {
        mw.finalNorm = wt;
        bound = true;
    } else if (n == "lm_head.weight" || n == "output.weight" ||
               n == "language_model.lm_head.weight") {
        mw.lmHead = wt;
        bound = true;
    }
    if (bound && f) {
        std::fprintf(f, "GEMMA4_SCHEMA_BIND root=%s rows=%zu cols=%zu type=%d\n",
                     name.c_str(), wt.rows, wt.cols, wt.type);
    }
    return bound;
}

template <typename LayerWeightsT, typename WeightTensorT>
inline bool TryBindLayerTensor(LayerWeightsT& lw, const std::string& name,
                               const WeightTensorT& wt, FILE* f = stderr) {
    const std::string n = Lower(name);
    bool bound = false;
    const char* slot = "";

    // Attention aliases: GGUF llama-style and HF/Gemma-style.
    if (EndsWith(n, "self_attn.q_proj.weight") || EndsWith(n, "attention.q_proj.weight") ||
        EndsWith(n, "attn_q.weight") || EndsWith(n, "attention.wq.weight")) {
        lw.wq = wt; slot = "attn_q"; bound = true;
    } else if (EndsWith(n, "self_attn.k_proj.weight") || EndsWith(n, "attention.k_proj.weight") ||
               EndsWith(n, "attn_k.weight") || EndsWith(n, "attention.wk.weight")) {
        lw.wk = wt; slot = "attn_k"; bound = true;
    } else if (EndsWith(n, "self_attn.v_proj.weight") || EndsWith(n, "attention.v_proj.weight") ||
               EndsWith(n, "attn_v.weight") || EndsWith(n, "attention.wv.weight")) {
        lw.wv = wt; slot = "attn_v"; bound = true;
    } else if (EndsWith(n, "self_attn.o_proj.weight") || EndsWith(n, "attention.o_proj.weight") ||
               EndsWith(n, "attn_output.weight") || EndsWith(n, "attn_o.weight") ||
               EndsWith(n, "attention.wo.weight")) {
        lw.wo = wt; lw.attnO = wt; slot = "attn_o"; bound = true;
    } else if (EndsWith(n, "self_attn.qkv_proj.weight") || EndsWith(n, "attn_qkv.weight")) {
        lw.wqkv = wt; slot = "attn_qkv"; bound = true;
    }

    // Norm aliases.
    else if (EndsWith(n, "input_layernorm.weight") || EndsWith(n, "pre_attention_layernorm.weight") ||
             EndsWith(n, "attn_norm.weight")) {
        lw.attnNorm = wt; slot = "attn_norm"; bound = true;
    } else if (EndsWith(n, "post_attention_layernorm.weight") || EndsWith(n, "pre_feedforward_layernorm.weight") ||
               EndsWith(n, "ffn_norm.weight") || EndsWith(n, "post_attention_norm.weight")) {
        lw.ffnNorm = wt; slot = "ffn_norm"; bound = true;
    }

    // FFN aliases.
    else if (EndsWith(n, "mlp.gate_proj.weight") || EndsWith(n, "mlp.gate.weight") ||
             EndsWith(n, "ffn_gate.weight")) {
        lw.wGate = wt; slot = "ffn_gate"; bound = true;
    } else if (EndsWith(n, "mlp.up_proj.weight") || EndsWith(n, "mlp.up.weight") ||
               EndsWith(n, "ffn_up.weight")) {
        lw.wUp = wt; slot = "ffn_up"; bound = true;
    } else if (EndsWith(n, "mlp.down_proj.weight") || EndsWith(n, "mlp.down.weight") ||
               EndsWith(n, "ffn_down.weight")) {
        lw.wDown = wt; slot = "ffn_down"; bound = true;
    }

    if (bound && f) {
        std::fprintf(f, "GEMMA4_SCHEMA_BIND layer_slot=%s source=%s rows=%zu cols=%zu type=%d\n",
                     slot, name.c_str(), wt.rows, wt.cols, wt.type);
    }
    return bound;
}

template <typename ModelWeightsT>
inline bool GeometryReady(const ModelWeightsT& mw, std::string* why = nullptr) {
    auto fail = [&](const char* s) {
        if (why) *why = s;
        return false;
    };
    if (!WtLive(mw.tokenEmbed)) return fail("NO_TOKEN_EMBED");
    if (mw.hiddenDim == 0) return fail("NO_HIDDEN");
    if (mw.numLayers == 0 || mw.layers.empty()) return fail("NO_LAYERS");

    std::size_t checked = 0;
    for (std::size_t i = 0; i < mw.layers.size(); ++i) {
        const auto& lw = mw.layers[i];
        const bool hasSplitAttn = WtLive(lw.wq) && WtLive(lw.wk) && WtLive(lw.wv) &&
                                  (WtLive(lw.wo) || WtLive(lw.attnO));
        const bool hasFusedAttn = WtLive(lw.wqkv) && (WtLive(lw.wo) || WtLive(lw.attnO));
        const bool hasFfn = WtLive(lw.wDown) && WtLive(lw.wUp) &&
                            (WtLive(lw.wGate) || lw.wUp.rows == 2 * lw.wDown.cols);
        if (!hasSplitAttn && !hasFusedAttn) continue; // PLE-only / unbound — skip
        if (!hasFfn) return fail("NO_FFN_GEOM");
        ++checked;
        if (checked >= 2) break;
    }
    if (checked == 0) return fail("NO_ATTN_GEOM");
    if (why) *why = "GEOM_READY";
    return true;
}

template <typename ModelWeightsT>
inline void EmitSummary(const ModelWeightsT& mw, FILE* f = stderr) {
    std::string why;
    const bool ok = GeometryReady(mw, &why);
    if (f) {
        std::fprintf(f,
            "GEMMA4_SCHEMA_BINDER ok=%d why=%s hidden=%zu layers=%zu vocab=%zu tokenEmbed=%d\n",
            ok ? 1 : 0, why.c_str(), mw.hiddenDim, mw.layers.size(), mw.vocabSize,
            WtLive(mw.tokenEmbed) ? 1 : 0);
        std::fflush(f);
    }
}

} // namespace Deep2::gemma4_schema
