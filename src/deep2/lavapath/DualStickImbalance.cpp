/* DualStickImbalance.cpp — #1 EWMA · #2 finish assign · #3 skew · #6 mig. */
#include "DualStickImbalance.hpp"
#include "DualStickImbalance_State.hpp"
#include "MoEPlaceLiveCounters.hpp"

namespace Deep2 {
namespace ds_imb {
uint64_t g_ewma[2] = {8ull * 1000ull * 1000ull, 8ull * 1000ull * 1000ull};
int64_t g_skewBias = 0;
uint64_t g_avail[2] = {0, 0};
uint64_t g_predLayer[2] = {0, 0};
uint64_t g_migPenBase = 4ull * 1000ull * 1000ull;
} // namespace ds_imb

void DualStickImbalanceBeginLayer() {
    ds_imb::g_avail[0] = ds_imb::g_avail[1] = 0;
    ds_imb::g_predLayer[0] = ds_imb::g_predLayer[1] = 0;
}

unsigned DualStickImbalanceAssign(int prefStick, uint64_t bytes, int hit) {
    using namespace ds_imb;
    unsigned pick = (g_avail[0] + Cost(0u, prefStick, bytes) <=
                     g_avail[1] + Cost(1u, prefStick, bytes))
                        ? 0u
                        : 1u;
    if (prefStick >= 0) {
        const unsigned p = (unsigned)prefStick & 1u;
        const unsigned o = p ^ 1u;
        if (hit) {
            pick = p; /* never migrate hits → reload_miss stays 0 */
        } else {
            const uint64_t fp = g_avail[p] + Cost(p, prefStick, bytes);
            const uint64_t fo = g_avail[o] + Cost(o, prefStick, bytes);
            if (fo >= fp) pick = p;
            else {
                pick = o;
                MoEPlaceLive().stick_migrations++;
                MoEPlaceLive().residency_lost_to_rebalance_bytes += bytes;
            }
        }
    }
    g_avail[pick] += Cost(pick, prefStick, bytes);
    g_predLayer[pick] = g_avail[pick];
    return pick;
}

uint64_t DualStickImbalancePredAvail(unsigned stick) {
    return ds_imb::g_avail[stick & 1u];
}

void DualStickImbalanceObserve(uint64_t t0_ns, uint64_t t1_ns, uint32_t n0,
                               uint32_t n1) {
    using namespace ds_imb;
    if (n0) g_ewma[0] = (g_ewma[0] * 7ull + t0_ns / n0) / 8ull;
    if (n1) g_ewma[1] = (g_ewma[1] * 7ull + t1_ns / n1) / 8ull;
        g_skewBias += (int64_t)((t0_ns - t1_ns) / 8ull);
        g_skewBias -= (int64_t)((t1_ns - t0_ns) / 8ull);
    if (g_skewBias > (int64_t)g_ewma[0]) g_skewBias = (int64_t)g_ewma[0];
    if (g_skewBias < -(int64_t)g_ewma[1]) g_skewBias = -(int64_t)g_ewma[1];

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
    auto absdiff = [](uint64_t a, uint64_t b) {
        return (a > b) ? (a - b) : (b - a);
    };
    MoEPlaceLive().pred_err_sum_ns +=
        absdiff(g_predLayer[0], t0_ns) + absdiff(g_predLayer[1], t1_ns);
    MoEPlaceLive().pred_actual_sum_ns += t0_ns + t1_ns;
}

} // namespace Deep2
