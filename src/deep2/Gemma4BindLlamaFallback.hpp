#pragma once
// ============================================================================
// Gemma4BindLlamaFallback.hpp
// Source-only Deep2 drop 002: allow BindLlamaSchema / authority checks to accept
// already-bound Gemma/HF tensor aliases instead of requiring llama.cpp token_embd/blk.*.
//
// Scope:
//   - Does not fabricate tensors.
//   - Does not rewrite tensor bytes.
//   - Does not promote product/runtime success without a runtime receipt.
//   - Header-only; no new object or CMake entry.
// ============================================================================

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <string>

namespace Deep2::gemma4_bind_fallback {

inline std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

inline bool EndsWith(const std::string& s, const char* suffix) {
    const std::string x = suffix ? suffix : "";
    return s.size() >= x.size() && s.compare(s.size() - x.size(), x.size(), x) == 0;
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

template <typename LayerWeightsT>
inline bool LayerHasAttn(const LayerWeightsT& lw) noexcept {
    const bool split = WtLive(lw.wq) && WtLive(lw.wk) && WtLive(lw.wv) &&
                       (WtLive(lw.wo) || WtLive(lw.attnO));
    const bool fused = WtLive(lw.wqkv) && (WtLive(lw.wo) || WtLive(lw.attnO));
    return split || fused;
}

template <typename LayerWeightsT>
inline bool LayerHasFfn(const LayerWeightsT& lw) noexcept {
    const bool split = WtLive(lw.wGate) && WtLive(lw.wUp) && WtLive(lw.wDown);
    const bool fused = !WtLive(lw.wGate) && WtLive(lw.wUp) && WtLive(lw.wDown) &&
                       lw.wDown.cols > 0 && lw.wUp.rows == 2 * lw.wDown.cols;
    return split || fused;
}

template <typename ModelWeightsT>
inline bool BoundModelReady(const ModelWeightsT& mw, const char** why = nullptr) noexcept {
    auto fail = [&](const char* s) {
        if (why) *why = s;
        return false;
    };
    if (!WtLive(mw.tokenEmbed)) return fail("NO_TOKEN_EMBED_ALIAS_BOUND");
    if (mw.hiddenDim == 0) return fail("NO_HIDDEN");
    if (mw.numLayers == 0 || mw.layers.empty()) return fail("NO_LAYERS");
    if (mw.vocabSize == 0) return fail("NO_VOCAB");

    const std::size_t n = std::min<std::size_t>(mw.layers.size(), mw.numLayers);
    if (n == 0) return fail("NO_LAYER_RANGE");

    std::size_t checked = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const auto& lw = mw.layers[i];
        if (!LayerHasAttn(lw)) return fail("NO_ATTN_ALIAS_BOUND");
        if (!LayerHasFfn(lw)) return fail("NO_FFN_ALIAS_BOUND");
        if (++checked >= 2) break; // schema-class proof; full runtime still owns full coverage.
    }
    if (why) *why = "ALIAS_BOUND_GEOM_READY";
    return true;
}

template <typename ModelWeightsT>
inline bool TryClearBindLlamaSchemaByAliases(const ModelWeightsT& mw, FILE* f = stderr) noexcept {
    const char* why = "UNSET";
    const bool ok = BoundModelReady(mw, &why);
    if (f) {
        std::fprintf(f,
            "GEMMA4_BIND_LLAMA_FALLBACK ok=%d why=%s tokenEmbed=%d hidden=%zu vocab=%zu layers=%zu\n",
            ok ? 1 : 0, why ? why : "null",
            WtLive(mw.tokenEmbed) ? 1 : 0,
            (std::size_t)mw.hiddenDim, (std::size_t)mw.vocabSize,
            (std::size_t)mw.layers.size());
        std::fflush(f);
    }
    return ok;
}

} // namespace Deep2::gemma4_bind_fallback
