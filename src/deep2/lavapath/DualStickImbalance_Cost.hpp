#pragma once
/* V7 Live Expert Cost Matrix cell + lookup. ≤99. */
#include <cstdint>

namespace Deep2 {
namespace ds_imb {

enum { COST_CAP = 4096 };

struct CostSlot {
    uint64_t key;
    uint64_t ewma_kernel_ns; /* train only if attributable kern */
    uint64_t ewma_h2d_ns;    /* train only if attributable xfer */
    uint64_t last_kernel_ns;
    uint64_t last_xfer_ns;
    uint64_t variance; /* |sample-ewma| EWMA */
    uint64_t last_seen; /* monotonic sight counter */
    uint32_t samples;   /* any sighting (incl. resident-only) */
    uint32_t samp_kern;
    uint32_t samp_xfer;
    uint8_t resident;
};

extern CostSlot g_cost[COST_CAP];
extern uint32_t g_costN;
extern uint64_t g_layerPrior[2];
extern uint32_t g_layerPriorN[2];
extern uint64_t g_sightSeq;

inline uint64_t CellKey(int layer, int expert, unsigned gpu, int resident,
                        uint32_t quant, uint32_t inD, uint32_t outD) {
    const uint32_t sh =
        ((inD / 64u) & 7u) | (((outD / 64u) & 7u) << 3);
    return ((uint64_t)(layer & 0xffu) << 24) |
           ((uint64_t)(expert & 0xfffu) << 12) |
           ((uint64_t)(gpu & 1u) << 11) | ((uint64_t)(resident ? 1u : 0u) << 10) |
           ((uint64_t)(quant & 0xfu) << 6) | (uint64_t)(sh & 0x3fu);
}

/* ATTRIBUTABLE_SAMPLES_ONLY: kern/h2d update only when ns!=0. */
void CostNoteSplit(int layer, int expert, unsigned gpu, int resident,
                   uint64_t kernNs, uint64_t h2dNs, uint64_t queueNs);
uint64_t CostKernel(int layer, int expert, unsigned gpu, int resident);
uint64_t CostH2d(int layer, int expert, unsigned gpu);
uint64_t CostVar(int layer, int expert, unsigned gpu, int resident);
uint32_t CostSamples(int layer, int expert, unsigned gpu, int resident);
void CostCoverageRefresh(); /* fill MoEPlaceLive V7 cov counters */
int V7Mode();               /* 0=off 1=observe(default) 2=blend stub */

} // namespace ds_imb
} // namespace Deep2
