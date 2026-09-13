/* DualStickImbalance_CostCov.cpp — V7 coverage counters. ≤99. */
#include "DualStickImbalance_Cost.hpp"
#include "Deep2Missing15Observe.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include <cstdint>

namespace Deep2 {
namespace ds_imb {

void CostCoverageRefresh() {
    uint64_t samp = 0, kernC = 0, xferC = 0, attrC = 0;
    uint64_t hot = 0, hotOk = 0, minHot = ~0ull;
    uint64_t residSum = 0, residN = 0;
    for (uint32_t i = 0; i < g_costN; ++i) {
        const CostSlot& s = g_cost[i];
        samp += s.samples;
        if (s.samp_kern) kernC++;
        if (s.samp_xfer) xferC++;
        if (s.samp_kern || s.samp_xfer) attrC++;
        /* Hot = revisited (samples>=2); mature if samples>=4. */
        if (s.samples >= 2u) {
            hot++;
            if (s.samples >= 4u) hotOk++;
            if (s.samples < minHot) minHot = s.samples;
        }
        if (s.samp_kern && s.last_kernel_ns) {
            const uint64_t pred = s.ewma_kernel_ns ? s.ewma_kernel_ns : 1ull;
            const uint64_t a = s.last_kernel_ns;
            residSum += (a > pred) ? (a - pred) : (pred - a);
            residN++;
        }
    }
    if (!hot) minHot = 0;
    auto& L = MoEPlaceLive();
    L.v7_cost_cells = g_costN;
    L.v7_cost_samples = samp;
    L.v7_kernel_cells = kernC;
    L.v7_xfer_cells = xferC;
    L.v7_attr_cells = attrC;
    L.v7_hot_cells = hot;
    L.v7_hot_cells_ge4 = hotOk;
    L.v7_min_hot_samples = hot ? minHot : 0ull;
    L.v7_cell_cov_x100 =
        g_costN ? (attrC * 100ull) / (uint64_t)g_costN : 0ull;
    L.v7_hot_cov_x100 = hot ? (hotOk * 100ull) / hot : 0ull;
    L.v7_residual_sum_ns = residSum;
    L.v7_residual_n = residN;
    L.v7_attrib_only = 1ull;
    L.v7_compute_xfer_split = 1ull;
    L.v7_blend_w_x100 = 0ull;
    L.v7_observe_only = (V7Mode() == 1) ? 1ull : 0ull;
    (void)d2m15_obs::confidence_q10;
    (void)d2m15_obs::execution_cost_ns;
}

} // namespace ds_imb
} // namespace Deep2
