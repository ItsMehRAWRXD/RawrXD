#pragma once
/* DualStickImbalance — Phase B finish-time sched (#1#2#3#6#10). ≤99. */
#include <cstdint>

namespace Deep2 {

struct MoEPlacePlan;

void DualStickImbalanceBeginLayer();
/* pref=-1 cold; hit=1 retain path. Returns stick 0|1; updates avail. */
unsigned DualStickImbalanceAssign(int prefStick, uint64_t bytes, int hit);
/* #10: steal from heavy → light while pred skew >5% and mig wins. */
void DualStickImbalanceSteal(MoEPlacePlan& plan, int layer);
/* Observe actual stick walls; EWMA + skew feedback + idle/skew counters. */
void DualStickImbalanceObserve(uint64_t t0_ns, uint64_t t1_ns, uint32_t n0,
                               uint32_t n1);
uint64_t DualStickImbalancePredAvail(unsigned stick);

} // namespace Deep2
