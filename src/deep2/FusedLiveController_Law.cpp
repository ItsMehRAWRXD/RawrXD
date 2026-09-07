// FusedLiveController_Law.cpp — pressure arbitration (called only off bypass)
#include "FusedLiveController.hpp"

namespace Deep2 {

namespace {
uint32_t& Depth() { static uint32_t d = 0; return d; }
uint32_t& Rev() { static uint32_t r = 0; return r; }
}

void Fused_LawResetDepth() { Depth() = 0; Rev() = 0; }

FusedDecision Fused_Arbitrate(const FusedSignals& s, uint32_t& conflicts) {
    FusedDecision d{};
    conflicts = 0;
    const bool pinballWant = s.pinballBounce >= 180;
    const bool reversalWant = s.reversalUs >= 800.f;
    const bool stallHigh =
        s.cycloneStall > 0 &&
        (s.cycloneActive == 0 || s.cycloneStall * 2 >= s.cycloneActive);
    const bool waitHigh = s.gpuCopyWaitUs > 2000;
    const bool overlapGood = s.gpuCopyOverlapUs > 0 &&
        s.gpuCopyOverlapUs * 2 >= s.gpuCopyWaitUs;
    const bool reloadHeavy =
        s.weightReloads > 0 && s.weightHits * 2 < s.weightReloads;

    // Plasma absent → zero thermal policy contribution
    const bool hot = !s.plasmaAbsent && (s.plasmaHot || s.plasmaThrottle > 0.5f);

    if (hot) {
        Depth() = 0; Rev() = 2; d.brake = true;
        if (pinballWant || reversalWant || stallHigh) ++conflicts;
    } else if (s.trailbrakeWant) {
        Depth() = 0;
        if (Rev() < 1) ++Rev();
        d.brake = true;
        if (pinballWant || reversalWant) ++conflicts;
    } else if (s.vramPressure) {
        Depth() = 0;
        if (Rev() < 2) ++Rev();
        d.evictCold = true;
        if (pinballWant || reversalWant) ++conflicts;
    } else if (stallHigh || (waitHigh && !overlapGood)) {
        if (Depth() < 2) ++Depth();
        if (Rev() > 0) --Rev();
        d.urgentAcquire = true;
    } else if (reloadHeavy) {
        if (Rev() < 2) ++Rev();
        if (Depth() > 0) --Depth();
    } else if (overlapGood && !waitHigh) {
        if (pinballWant && s.ramHeadroom && Depth() < 2) ++Depth();
    } else if (pinballWant && s.ramHeadroom) {
        if (Depth() < 1) Depth() = 1;
    }

    d.prefetchDepth = Depth();
    d.reverseDepth = Rev();
    d.speculativeEnable = (Rev() < 2);
    d.warmupEnable = (s.warmupMisses > s.warmupHits) || stallHigh || waitHigh;
    if (Rev() >= 2) d.speculativeEnable = false;
    return d;
}

} // namespace Deep2
