#pragma once
/* V6 cost state — kernel EWMA + #13 transfer BW (no double-count). */
#include "DualStickImbalance_Xfer.hpp"
#include "DualStickStreamWindow.hpp"
#include <cstdint>

namespace Deep2 {
namespace ds_imb {

enum { EWMA_CAP = 64 };
struct EwmaSlot {
    uint64_t key;
    uint64_t ns;
    uint32_t n;
};
extern EwmaSlot g_tab[EWMA_CAP];
extern uint32_t g_tabN;
extern uint64_t g_avail[2];
extern uint64_t g_predLayer[2];
extern uint32_t g_nAssign[2];
extern uint32_t g_quant, g_inDim, g_outDim;

inline uint64_t PackKey(unsigned gpu, uint32_t quant, uint32_t inD,
                        uint32_t outD) {
    /* Kernel-only key (residency handled by TransferNs). */
    return ((uint64_t)(gpu & 1u)) | ((uint64_t)(quant & 0xffu) << 1) |
           ((uint64_t)(inD & 0x3fffu) << 9) |
           ((uint64_t)(outD & 0x3fffu) << 23);
}

uint64_t EwmaGet(uint64_t key, uint64_t fallback);
void EwmaNote(uint64_t key, uint64_t sampleNs);

inline uint64_t KernelCost(unsigned stick) {
    const uint64_t k = PackKey(stick, g_quant, g_inDim, g_outDim);
    return EwmaGet(k, 16ull * 1000ull * 1000ull);
}

inline uint64_t VramPenalty(unsigned stick) {
    return DualStickStickResBytes(stick & 1u) >> 14;
}

inline uint64_t FullCost(unsigned stick, int pref, uint64_t bytes, int hit) {
    stick &= 1u;
    const int res = (hit && pref >= 0 && (unsigned)pref == stick) ? 1 : 0;
    uint64_t c = KernelCost(stick) + VramPenalty(stick);
    if (!res) c += TransferNs(stick, bytes);
    return c;
}

} // namespace ds_imb
} // namespace Deep2
