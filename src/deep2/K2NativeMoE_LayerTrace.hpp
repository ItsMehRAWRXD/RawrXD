/* K2NativeMoE_LayerTrace.hpp — fail-closed L39 isolation breadcrumbs (≤99). */
#pragma once
#include "K2GlobalTensorIndex.hpp"
#include <cstdio>
#include <cstdlib>

namespace Deep2 {
namespace moe_ltrace {

inline uint32_t TraceLayer() {
    const char* e = std::getenv("DEEP2_K2_LAYER_TRACE");
    if (e && e[0]) return (uint32_t)std::atoi(e);
    return 39u; /* default isolation target */
}
inline bool On(uint32_t layer) { return layer == TraceLayer(); }

inline void BC(uint32_t layer, const char* tag) {
    if (!On(layer)) return;
    std::fprintf(stderr, "L%u_%s\n", layer, tag);
    std::fflush(stderr);
}
inline void BCExpert(uint32_t layer, const char* tag, int expert) {
    if (!On(layer)) return;
    std::fprintf(stderr, "L%u_%s expert=%d\n", layer, tag, expert);
    std::fflush(stderr);
}

inline void DumpTensorGeom(const GlobalTensorIndex& index, uint32_t layer,
                           const char* base) {
    char name[96];
    std::snprintf(name, sizeof(name), "blk.%u.%s", layer, base);
    auto full = index.Find(name);
    if (!full) {
        std::fprintf(stderr, "L%u_GEOM name=%s MISSING\n", layer, name);
        return;
    }
    std::fprintf(stderr,
                 "L%u_GEOM name=%s ggml=%u ne=[%llu,%llu,%llu,%llu] "
                 "byteSize=%llu expertCount=%u stride=%llu\n",
                 layer, name, full->ggmlType,
                 (unsigned long long)(full->shape.size() > 0 ? full->shape[0] : 0),
                 (unsigned long long)(full->shape.size() > 1 ? full->shape[1] : 0),
                 (unsigned long long)(full->shape.size() > 2 ? full->shape[2] : 0),
                 (unsigned long long)(full->shape.size() > 3 ? full->shape[3] : 0),
                 (unsigned long long)full->byteSize, full->expertCount,
                 (unsigned long long)full->expertStrideBytes);
    if (full->isExpertTensor && full->expertCount) {
        for (uint32_t probe : {0u, 1u, full->expertCount / 2u,
                               full->expertCount - 1u}) {
            auto sl = index.FindExpertSlice(name, probe);
            if (!sl) continue;
            const uint64_t last = sl->byteOffset + sl->byteSize;
            const int ok =
                (sl->byteOffset < full->byteSize && sl->byteSize > 0 &&
                 last <= full->byteSize)
                    ? 1
                    : 0;
            std::fprintf(stderr,
                         "L%u_SLICE name=%s eid=%u off=%llu size=%llu "
                         "last=%llu srcEnd=%llu bounds_ok=%d\n",
                         layer, name, probe,
                         (unsigned long long)sl->byteOffset,
                         (unsigned long long)sl->byteSize,
                         (unsigned long long)last,
                         (unsigned long long)full->byteSize, ok);
        }
    }
    std::fflush(stderr);
}

inline void DumpLayerPair(const GlobalTensorIndex& index, uint32_t focus) {
    static thread_local bool once = false;
    if (once || !On(focus)) return;
    once = true;
    const uint32_t lo = focus > 0 ? focus - 1 : focus;
    std::fprintf(stderr, "L%u_GEOM_DUMP_BEGIN vs L%u\n", focus, lo);
    for (uint32_t L : {lo, focus}) {
        DumpTensorGeom(index, L, "ffn_norm.weight");
        DumpTensorGeom(index, L, "ffn_gate_inp.weight");
        DumpTensorGeom(index, L, "ffn_gate_exps.weight");
        DumpTensorGeom(index, L, "ffn_up_exps.weight");
        DumpTensorGeom(index, L, "ffn_down_exps.weight");
        DumpTensorGeom(index, L, "ffn_gate_shexp.weight");
        DumpTensorGeom(index, L, "ffn_up_shexp.weight");
        DumpTensorGeom(index, L, "ffn_down_shexp.weight");
    }
    std::fprintf(stderr, "L%u_GEOM_DUMP_END\n", focus);
    std::fflush(stderr);
}

} // namespace moe_ltrace
} // namespace Deep2
