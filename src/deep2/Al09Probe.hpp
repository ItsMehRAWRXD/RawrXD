#pragma once
/* AL09 first-divergent MoE probes. Env RAWRXD_AL09=1. PROMOTE=0. */
#include "ReapPhysicalBank.hpp"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Deep2 {
namespace al09 {

inline bool On() {
    static const bool on = [] {
        const char* e = std::getenv("RAWRXD_AL09");
        return e && e[0] == '1';
    }();
    return on;
}

inline uint32_t& Tok() {
    static thread_local uint32_t t = 0;
    return t;
}
inline void NoteLayer0Enter() { ++Tok(); }

inline uint64_t Fnv(const float* data, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        uint32_t bits = 0;
        if (!std::isfinite(data[i])) bits = 0xFFFFFFFFu;
        else std::memcpy(&bits, &data[i], 4);
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (8 * b)) & 0xFFu;
            h *= 1099511628211ull;
        }
    }
    return h;
}

inline void DumpHidden(uint32_t layer, const char* tag, const float* h,
                       size_t n) {
    if (!On() || !h || !n) return;
    /* Router detail: L16/L17 only. LAYER_IN/OUT: all layers, or
       RAWRXD_AL09_LAYER_MIN / RAWRXD_AL09_TOK_MIN to bound stderr. */
    const bool routerish =
        std::strcmp(tag, "ROUTER_IN") == 0 || std::strcmp(tag, "MOE_IN") == 0;
    const bool layerIO =
        std::strcmp(tag, "LAYER_OUT") == 0 || std::strcmp(tag, "LAYER_IN") == 0;
    if (routerish && layer != 16u && layer != 17u) return;
    if (!routerish && !layerIO && layer != 16u && layer != 17u) return;
    if (layerIO) {
        static int layerMin = -1, tokMin = -1;
        if (layerMin < 0) {
            const char* a = std::getenv("RAWRXD_AL09_LAYER_MIN");
            const char* b = std::getenv("RAWRXD_AL09_TOK_MIN");
            layerMin = a ? std::atoi(a) : 0;
            tokMin = b ? std::atoi(b) : 0;
        }
        if ((int)layer < layerMin || (int)Tok() < tokMin) return;
    }
    std::fprintf(stderr,
                 "AL09_%s layer=%u tok=%u n=%zu fnv=%016llx "
                 "x0=%.9g x1=%.9g x2=%.9g PROMOTE=0\n",
                 tag, layer, Tok(), n, (unsigned long long)Fnv(h, n),
                 (double)h[0], (double)h[1], n > 2 ? (double)h[2] : 0.0);
}

/* Raw pre-mask logits + choice for watch IDs (full) or all slots (E<=32). */
inline void DumpRouter(uint32_t layer, size_t E, const float* raw,
                       const float* choice, const float* gate,
                       const int* topPre, size_t nPre, const int* topPost,
                       size_t nPost) {
    if (!On() || layer != 17u || !raw) return;
    std::fprintf(stderr, "AL09_ROUTER layer=17 tok=%u E=%zu PROMOTE=0\n", Tok(),
                 E);
    if (E <= 32) {
        for (size_t e = 0; e < E; ++e)
            std::fprintf(stderr,
                         "AL09_SLOT e=%zu raw=%.9g gate=%.9g choice=%.9g\n", e,
                         (double)raw[e], gate ? (double)gate[e] : 0.0,
                         choice ? (double)choice[e] : 0.0);
    } else {
        const uint32_t watch[] = {97u, 164u, 73u, 173u, 205u, 82u, 213u, 39u,
                                  9u};
        for (uint32_t id : watch) {
            if (id >= E) continue;
            std::fprintf(stderr,
                         "AL09_EID id=%u raw=%.9g gate=%.9g choice=%.9g "
                         "allow=%d\n",
                         id, (double)raw[id],
                         gate ? (double)gate[id] : 0.0,
                         choice ? (double)choice[id] : 0.0,
                         ReapPhysicalExpertAllowedAtLayer(layer, id) ? 1 : 0);
        }
    }
    std::fprintf(stderr, "AL09_TOPK_PRE n=%zu ids=", nPre);
    for (size_t i = 0; i < nPre; ++i)
        std::fprintf(stderr, "%s%d", i ? "," : "", topPre[i]);
    std::fprintf(stderr, "\nAL09_TOPK_POST n=%zu ids=", nPost);
    for (size_t i = 0; i < nPost; ++i)
        std::fprintf(stderr, "%s%d", i ? "," : "", topPost[i]);
    std::fputc('\n', stderr);
    std::fflush(stderr);
}

} // namespace al09
} // namespace Deep2
