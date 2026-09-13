/* DualStickImbalance_Observe.cpp — V6 walls + V7 shadow/coverage. ≤99. */
#include "DualStickImbalance.hpp"
#include "DualStickImbalance_Cost.hpp"
#include "DualStickImbalance_State.hpp"
#include "MoEPlaceLiveCounters.hpp"

namespace Deep2 {

void DualStickImbalanceObserveExpert(int layer, int expert, unsigned stick,
                                     int resident, uint64_t h2dNsOr0,
                                     uint64_t kernNsOr0) {
    if (ds_imb::V7Mode() == 0) return;
    if (!h2dNsOr0 && !kernNsOr0 && !resident) return;
    ds_imb::CostNoteSplit(layer, expert, stick & 1u, resident, kernNsOr0,
                          h2dNsOr0, 0ull);
}

void DualStickImbalanceObserve(uint64_t t0_ns, uint64_t t1_ns, uint32_t n0,
                               uint32_t n1, uint64_t h2d0, uint64_t h2d1) {
    using namespace ds_imb;
    const int dual = (h2d0 && h2d1) ? 1 : 0;
    auto feed = [&](unsigned st, uint64_t t, uint32_t n, uint64_t h2d) {
        if (!n || !t) return;
        const uint64_t predK = KernelCost(st) * (uint64_t)n;
        const uint64_t predX = h2d ? TransferExecNs(st, h2d) : 0ull;
        const uint64_t predQ = QueueDelayNs(st);
        uint64_t predTot = predQ + predX + predK;
        if (!predTot) predTot = 1ull;
        const uint64_t actQ = (t * predQ) / predTot;
        const uint64_t actX = (t * predX) / predTot;
        const uint64_t actK = t - actQ - actX;
        if (h2d || actQ) XferObserveSplit(st, h2d, actQ, actX, dual);
        EwmaNote(PackKey(st, g_quant, g_inDim, g_outDim), actK / (uint64_t)n);
        auto ad = [](uint64_t a, uint64_t b) { return a > b ? a - b : b - a; };
        MoEPlaceLive().pred_err_kernel_ns += ad(predK, actK);
        MoEPlaceLive().pred_err_xfer_ns += ad(predX, actX);
        MoEPlaceLive().pred_err_queue_ns += ad(predQ, actQ);
        /* Shadow NONAUTH only — never CostNoteSplit from stick wall/n. */
        if (V7Mode()) {
            const uint64_t sh = g_layerPrior[st] * (uint64_t)n;
            MoEPlaceLive().v7_shadow_err_ns += ad(sh, actK);
            MoEPlaceLive().v7_shadow_act_ns += actK;
        }
    };
    feed(0u, t0_ns, n0, h2d0);
    feed(1u, t1_ns, n1, h2d1);

    if (t0_ns <= t1_ns)
        MoEPlaceLive().gpu0_idle_at_join_ns += (t1_ns - t0_ns);
    else
        MoEPlaceLive().gpu1_idle_at_join_ns += (t0_ns - t1_ns);
    const uint64_t mx = (t0_ns > t1_ns) ? t0_ns : t1_ns;
    const uint64_t mn = (t0_ns < t1_ns) ? t0_ns : t1_ns;
    if (mx) {
        MoEPlaceLive().stick_skew_ns += (mx - mn);
        MoEPlaceLive().stick_skew_pct_sum_x100 += ((mx - mn) * 10000ull) / mx;
        MoEPlaceLive().stick_skew_samples++;
    }
    auto ad = [](uint64_t a, uint64_t b) { return a > b ? a - b : b - a; };
    MoEPlaceLive().pred_err_sum_ns +=
        ad(g_predLayer[0], t0_ns) + ad(g_predLayer[1], t1_ns);
    MoEPlaceLive().pred_actual_sum_ns += t0_ns + t1_ns;
    if (V7Mode()) CostCoverageRefresh();
}

} // namespace Deep2
