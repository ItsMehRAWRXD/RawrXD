#pragma once
/* DualStickImbalance — V6 cost-predictor calibration. ≤99. */
#include <cstdint>

namespace Deep2 {

struct MoEPlacePlan;

void DualStickImbalanceBeginLayer();
void DualStickImbalanceSetShape(uint32_t quant, uint32_t inDim,
                                uint32_t outDim);
/* Est kernel+miss+xfer cost for stick (no queue bump). */
uint64_t DualStickImbalanceEstCost(unsigned stick, int resident,
                                   uint64_t bytes);
/* pref=-1 cold; hit=1 retain. argmin finish; count-second on ties. */
unsigned DualStickImbalanceAssign(int prefStick, uint64_t bytes, int hit);
void DualStickImbalanceSteal(MoEPlacePlan& plan, int layer); /* held */
/* #7+#13: stick walls + H2D bytes → kernel EWMA + transfer BW EWMA. */
void DualStickImbalanceObserve(uint64_t t0_ns, uint64_t t1_ns, uint32_t n0,
                               uint32_t n1, uint64_t h2d0, uint64_t h2d1);
uint64_t DualStickImbalancePredAvail(unsigned stick);

} // namespace Deep2
