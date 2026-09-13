#pragma once
/* Shared Phase-B imbalance state (internal). */
#include "DualStickStreamWindow.hpp"
#include <cstdint>

namespace Deep2 {
namespace ds_imb {

extern uint64_t g_ewma[2];
extern int64_t g_skewBias;
extern uint64_t g_avail[2];
extern uint64_t g_predLayer[2];
extern uint64_t g_migPenBase;

inline uint64_t Cost(unsigned stick, int pref, uint64_t bytes) {
    stick &= 1u;
    uint64_t c = g_ewma[stick];
    /* #6 residency / VRAM pressure — keep sticks from over-pinning. */
    c += DualStickStickResBytes(stick) >> 14;
    if (g_skewBias > 0 && stick == 0u) c += (uint64_t)g_skewBias;
    else if (g_skewBias < 0 && stick == 1u) c += (uint64_t)(-g_skewBias);
    if (pref >= 0 && (unsigned)pref != stick) {
        uint64_t mig = g_migPenBase + (bytes ? (bytes >> 12) : 0ull);
        if (mig < g_ewma[stick]) mig = g_ewma[stick];
        c += mig;
    }
    return c;
}

} // namespace ds_imb
} // namespace Deep2
