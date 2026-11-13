#pragma once
/* AL10 prefill-boundary + OPEN_INTERVAL probe. Env RAWRXD_AL10=1.
   RAWRXD_AL10_MAX_TOK=N early-exits prefill after al09 tok N (default 4).
   PROMOTE=0. NOT_RUN!=PASS. */
#include "Al09Probe.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Deep2 {
namespace al10 {

inline bool On() {
    static const bool on = [] {
        const char* e = std::getenv("RAWRXD_AL10");
        return e && e[0] == '1';
    }();
    return on;
}

inline int MaxTok() {
    static const int m = [] {
        const char* e = std::getenv("RAWRXD_AL10_MAX_TOK");
        if (e && e[0]) {
            const int v = std::atoi(e);
            return v > 0 ? v : 4;
        }
        return On() ? 4 : 0;
    }();
    return m;
}

/* OPEN_INTERVAL: after LAYER17_OUT@tok3 through before L16 MoE@tok4
   = tok3 L18..61 + tok4 L0..16. */
inline bool InOpenInterval(uint32_t layer, uint32_t tok) {
    if (tok == 3u && layer >= 18u) return true;
    if (tok == 4u && layer <= 16u) return true;
    return false;
}

inline void DumpInputId(int inputId, size_t position, size_t kvLen) {
    if (!On()) return;
    std::fprintf(stderr,
                 "AL10_INPUT_ID pos=%zu id=%d kv_len=%zu al09_tok_before=%u "
                 "PROMOTE=0\n",
                 position, inputId, kvLen, al09::Tok());
    std::fflush(stderr);
}

inline void DumpLayerOut(uint32_t layer, const float* h, size_t n) {
    if (!On() || !h || !n) return;
    const uint32_t tok = al09::Tok();
    if (!InOpenInterval(layer, tok) && layer != 17u) return;
    std::fprintf(stderr,
                 "AL10_LAYER_OUT layer=%u tok=%u n=%zu fnv=%016llx "
                 "x0=%.9g x1=%.9g x2=%.9g PROMOTE=0\n",
                 layer, tok, n, (unsigned long long)al09::Fnv(h, n),
                 (double)h[0], (double)h[1], n > 2 ? (double)h[2] : 0.0);
    std::fflush(stderr);
}

inline void DumpKvDigest(uint32_t layer, const float* k, size_t n,
                         size_t writePos) {
    if (!On() || !k || !n) return;
    const uint32_t tok = al09::Tok();
    if (!InOpenInterval(layer, tok)) return;
    std::fprintf(stderr,
                 "AL10_KV_DIGEST layer=%u tok=%u write_pos=%zu n=%zu "
                 "fnv=%016llx PROMOTE=0\n",
                 layer, tok, writePos, n,
                 (unsigned long long)al09::Fnv(k, n));
    std::fflush(stderr);
}

/* After finishing a prefill token whose al09 Tok() reached MaxTok. */
inline bool ShouldStopPrefill() {
    if (!On()) return false;
    const int lim = MaxTok();
    if (lim <= 0) return false;
    return (int)al09::Tok() >= lim;
}

inline void NoteEarlyExit(size_t pos) {
    if (!On()) return;
    std::fprintf(stderr,
                 "AL10_EARLY_EXIT pos=%zu al09_tok=%u max_tok=%d "
                 "PROMOTE=0\n",
                 pos, al09::Tok(), MaxTok());
    std::fflush(stderr);
}

/* Seal: tok1-4 are chat-template PREFILL fixed IDs, not decode ARGMAX. */
inline void DumpBoundary(size_t genPos, size_t tokensGenerated,
                         size_t kvLen, int selected, int argmax,
                         float argmaxLogit, const float* logits, size_t vocab,
                         const float* hidden, size_t hiddenDim) {
    if (!On()) return;
    const uint32_t tok = al09::Tok();
    const uint64_t lFnv =
        (logits && vocab) ? al09::Fnv(logits, vocab) : 0ull;
    const uint64_t hFnv =
        (hidden && hiddenDim) ? al09::Fnv(hidden, hiddenDim) : 0ull;
    std::fprintf(stderr,
                 "AL10_BOUNDARY gen_pos=%zu tokens_gen=%zu al09_tok=%u "
                 "kv_len=%zu selected=%d argmax=%d logit=%.9g "
                 "logits_fnv=%016llx hidden_fnv=%016llx "
                 "NOTE=prefill_fixed_ids_tok1_4 PROMOTE=0\n",
                 genPos, tokensGenerated, tok, kvLen, selected, argmax,
                 (double)argmaxLogit, (unsigned long long)lFnv,
                 (unsigned long long)hFnv);
    std::fflush(stderr);
    (void)argmaxLogit;
}

inline void DumpTok4Input(int inputId, size_t kvLen, size_t position) {
    DumpInputId(inputId, position, kvLen);
}

} // namespace al10
} // namespace Deep2
