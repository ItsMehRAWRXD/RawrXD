// FusedLiveController_Cheap.cpp — stall/queue emergency probe (no full sensors)
#include "FusedLiveController.hpp"

namespace Deep2 {

FusedDecision& Fused_LastMut();
FusedCounters& Fused_CtrMut();
bool& Fused_HavePrevMut();

bool Fused_TryCheapBypass(uint64_t stall, uint32_t queuePeak, bool trailEmerg,
                          bool plasmaAbsent) {
    (void)plasmaAbsent;
    if (stall != 0 || queuePeak != 0 || trailEmerg) return false;
    auto& have = Fused_HavePrevMut();
    auto& last = Fused_LastMut();
    // First tick must take full Decide to seed cache/hit state.
    if (!have) return false;
    if (!last.bypass && last.brake) return false;
    FusedDecision d = last;
    d.bypass = true;
    d.speculativeEnable = true;
    d.brake = false;
    d.evictCold = false;
    d.urgentAcquire = false;
    d.warmupEnable = false;
    last = d;
    auto& ctr = Fused_CtrMut();
    ctr.fastBypass++;
    ctr.decisionsSkipped++;
    return true;
}

} // namespace Deep2
