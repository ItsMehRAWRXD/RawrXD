/* DualStickImbalance.cpp — V6 #1#4 assign (observe in _Observe.cpp). ≤99. */
#include "DualStickImbalance.hpp"
#include "DualStickImbalance_Det.hpp"
#include "DualStickImbalance_State.hpp"
#include "MoEPlaceLiveCounters.hpp"

namespace Deep2 {

void DualStickImbalanceBeginLayer() {
    ds_imb::g_avail[0] = ds_imb::g_avail[1] = 0;
    ds_imb::g_predLayer[0] = ds_imb::g_predLayer[1] = 0;
    ds_imb::g_nAssign[0] = ds_imb::g_nAssign[1] = 0;
    ds_imb::XferBeginLayer();
}

void DualStickImbalanceSetShape(uint32_t quant, uint32_t inDim,
                                uint32_t outDim) {
    if (quant) ds_imb::g_quant = quant;
    if (inDim) ds_imb::g_inDim = inDim;
    if (outDim) ds_imb::g_outDim = outDim;
}

uint64_t DualStickImbalanceEstCost(unsigned stick, int resident,
                                   uint64_t bytes) {
    return ds_imb::FullCost(stick & 1u, resident ? (int)(stick & 1u) : -1,
                            bytes, resident);
}

unsigned DualStickImbalanceAssign(int layer, int expert, int prefStick,
                                  uint64_t bytes, int hit) {
    using namespace ds_imb;
    if (StickHashMode()) {
        unsigned pick = (hit && prefStick >= 0)
                            ? ((unsigned)prefStick & 1u)
                            : HashStickOf(layer, expert);
        if (!hit) XferNoteMiss(pick);
        g_nAssign[pick]++;
        return pick;
    }
    const uint64_t c0 = FullCost(0u, prefStick, bytes, hit);
    const uint64_t c1 = FullCost(1u, prefStick, bytes, hit);
    uint64_t f0 = g_avail[0] + c0, f1 = g_avail[1] + c1;
    unsigned pick = (f0 < f1)   ? 0u
                    : (f1 < f0) ? 1u
                    : (g_nAssign[0] <= g_nAssign[1] ? 0u : 1u);
    if (prefStick >= 0) {
        const unsigned p = (unsigned)prefStick & 1u;
        if (hit) {
            pick = p; /* never migrate hits → RELOAD=0 */
        } else {
            const uint64_t fp = g_avail[p] + FullCost(p, prefStick, bytes, 0);
            const uint64_t fo =
                g_avail[p ^ 1u] + FullCost(p ^ 1u, prefStick, bytes, 0);
            if (fo < fp) {
                pick = p ^ 1u;
                MoEPlaceLive().stick_migrations++;
                MoEPlaceLive().residency_lost_to_rebalance_bytes += bytes;
            } else
                pick = p;
        }
    }
    if (!hit) XferNoteMiss(pick);
    const uint64_t used = FullCost(pick, prefStick, bytes, hit);
    g_avail[pick] += used;
    g_predLayer[pick] = g_avail[pick];
    g_nAssign[pick]++;
    return pick;
}

uint64_t DualStickImbalancePredAvail(unsigned stick) {
    return ds_imb::g_avail[stick & 1u];
}

} // namespace Deep2
