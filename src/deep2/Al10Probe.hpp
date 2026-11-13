#pragma once
/* AL10 token-boundary probe. Env RAWRXD_AL10=1. PROMOTE=0. */
#include "Al09Probe.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace Deep2 {
namespace al10 {

inline bool On() {
    static const bool on = [] {
        const char* e = std::getenv("RAWRXD_AL10");
        return e && e[0] == '1';
    }();
    return on;
}

/* After FINAL_NORM/LOGITS/ARGMAX for the current forward. */
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
                 "logits_fnv=%016llx hidden_fnv=%016llx PROMOTE=0\n",
                 genPos, tokensGenerated, tok, kvLen, selected, argmax,
                 (double)argmaxLogit, (unsigned long long)lFnv,
                 (unsigned long long)hFnv);
    if (logits && vocab >= 5) {
        int topId[5] = {};
        float topL[5];
        for (int i = 0; i < 5; ++i) topL[i] = -1e30f;
        for (size_t i = 0; i < vocab; ++i) {
            const float v = logits[i];
            if (!std::isfinite(v)) continue;
            for (int k = 0; k < 5; ++k) {
                if (v > topL[k]) {
                    for (int m = 4; m > k; --m) {
                        topL[m] = topL[m - 1];
                        topId[m] = topId[m - 1];
                    }
                    topL[k] = v;
                    topId[k] = (int)i;
                    break;
                }
            }
        }
        std::fprintf(stderr, "AL10_TOP5 al09_tok=%u", tok);
        for (int k = 0; k < 5; ++k)
            std::fprintf(stderr, " %d:%.6g", topId[k], (double)topL[k]);
        std::fputc('\n', stderr);
    }
    std::fflush(stderr);
}

inline void DumpTok4Input(int inputId, size_t kvLen, size_t position) {
    if (!On()) return;
    std::fprintf(stderr,
                 "AL10_TOK4_INPUT id=%d kv_len=%zu position=%zu "
                 "al09_tok=%u PROMOTE=0\n",
                 inputId, kvLen, position, al09::Tok());
    std::fflush(stderr);
}

} // namespace al10
} // namespace Deep2
