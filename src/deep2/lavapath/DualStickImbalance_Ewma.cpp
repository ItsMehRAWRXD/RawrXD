/* DualStickImbalance_Ewma.cpp — keyed kernel EWMA get/note. ≤99. */
#include "DualStickImbalance_State.hpp"

namespace Deep2 {
namespace ds_imb {

EwmaSlot g_tab[EWMA_CAP];
uint32_t g_tabN = 0;
uint64_t g_avail[2] = {0, 0};
uint64_t g_predLayer[2] = {0, 0};
uint32_t g_nAssign[2] = {0, 0};
uint32_t g_quant = 14; /* Q4_K default; SetShape overrides */
uint32_t g_inDim = 7168;
uint32_t g_outDim = 2048;

uint64_t EwmaGet(uint64_t key, uint64_t fallback) {
    for (uint32_t i = 0; i < g_tabN; ++i)
        if (g_tab[i].key == key) return g_tab[i].ns;
    return fallback;
}

void EwmaNote(uint64_t key, uint64_t sampleNs) {
    if (!sampleNs) return;
    /* Outlier clip vs 16ms seed: 1/8× … 8×. */
    const uint64_t seed = 16ull * 1000ull * 1000ull;
    if (sampleNs < (seed >> 3)) sampleNs = seed >> 3;
    if (sampleNs > (seed << 3)) sampleNs = seed << 3;
    for (uint32_t i = 0; i < g_tabN; ++i) {
        if (g_tab[i].key != key) continue;
        if (g_tab[i].n < 4u)
            g_tab[i].ns = (g_tab[i].ns + sampleNs) / 2ull;
        else
            g_tab[i].ns = (g_tab[i].ns * 7ull + sampleNs) / 8ull;
        g_tab[i].n++;
        return;
    }
    if (g_tabN >= EWMA_CAP) return;
    EwmaSlot& s = g_tab[g_tabN++];
    s.key = key;
    s.ns = sampleNs;
    s.n = 1;
}

} // namespace ds_imb
} // namespace Deep2
