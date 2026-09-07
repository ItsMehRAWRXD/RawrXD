// FusedLiveController_Decide.cpp — fast-bypass + change-gated decide (002)
#include "FusedLiveController.hpp"
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

FusedDecision Fused_Arbitrate(const FusedSignals& s, uint32_t& conflicts);
bool& Fused_OnRef();
FusedDecision& Fused_LastMut();
FusedCounters& Fused_CtrMut();
FusedSignals& Fused_PrevMut();
bool& Fused_HavePrevMut();

namespace {
static uint64_t NowUs() {
#ifdef _WIN32
    static LARGE_INTEGER f{};
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (uint64_t)((t.QuadPart * 1000000ull) / (uint64_t)f.QuadPart);
#else
    return 0;
#endif
}
static bool Healthy(const FusedSignals& s) {
    const bool hitOk =
        s.cacheHitRate >= 0.99 || (s.liveCacheBytes == 0 && s.cycloneStall == 0);
    const bool budgetOk =
        s.liveCacheBudget == 0 || s.liveCacheBytes * 4ull < s.liveCacheBudget * 3ull;
    return s.cycloneStall == 0 && s.cycloneQueuePeak == 0 && hitOk && budgetOk &&
           !s.plasmaHot && !s.trailbrakeWant && !s.vramPressure;
}
static bool Changed(const FusedSignals& a, const FusedSignals& b) {
    return a.cycloneStall != b.cycloneStall || a.cycloneQueuePeak != b.cycloneQueuePeak ||
           a.plasmaHot != b.plasmaHot || a.trailbrakeWant != b.trailbrakeWant ||
           a.vramPressure != b.vramPressure || a.pinballBounce != b.pinballBounce ||
           (a.reversalUs >= 800.f) != (b.reversalUs >= 800.f) ||
           a.gpuCopyWaitUs != b.gpuCopyWaitUs || a.weightReloads != b.weightReloads;
}
} // namespace

FusedDecision Fused_Decide(const FusedSignals& s) {
    auto& last = Fused_LastMut();
    auto& ctr = Fused_CtrMut();
    auto& prev = Fused_PrevMut();
    auto& have = Fused_HavePrevMut();
    const uint64_t t0 = NowUs();
    if (Healthy(s) && (!have || !Changed(prev, s))) {
        FusedDecision d = last;
        d.bypass = true;
        d.speculativeEnable = true;
        d.brake = false;
        d.evictCold = false;
        d.urgentAcquire = false;
        d.warmupEnable = false;
        ctr.fastBypass++;
        ctr.decisionsSkipped++;
        ctr.totalControlUs += NowUs() - t0;
        last = d;
        prev = s;
        have = true;
        return d;
    }
    if (have && Changed(prev, s)) ctr.signalChanges++;
    uint32_t conflicts = 0;
    FusedDecision d = Fused_Arbitrate(s, conflicts);
    const uint64_t dt = NowUs() - t0;
    ctr.decisionUs += dt;
    ctr.totalControlUs += dt;
    if (d.brake) ctr.brakeUs += dt;
    if (!d.speculativeEnable) ctr.suppressionUs += dt;
    ctr.decisions++;
    ctr.prefetchDepthSum += d.prefetchDepth;
    ctr.reverseDepthSum += d.reverseDepth;
    if (d.prefetchDepth > ctr.prefetchDepthMax) ctr.prefetchDepthMax = d.prefetchDepth;
    if (d.reverseDepth > ctr.reverseDepthMax) ctr.reverseDepthMax = d.reverseDepth;
    if (d.urgentAcquire) ctr.urgentAcquires++;
    if (!d.speculativeEnable) ctr.speculativeSuppressed++;
    if (d.warmupEnable) ctr.warmupEnables++;
    if (d.brake) ctr.brakes++;
    ctr.conflictsAvoided += conflicts;
    if (s.cycloneQueuePeak > ctr.queuePeak) ctr.queuePeak = s.cycloneQueuePeak;
    if (d.prefetchDepth != last.prefetchDepth || d.reverseDepth != last.reverseDepth ||
        d.speculativeEnable != last.speculativeEnable || d.brake != last.brake)
        ctr.policyChanges++;
    last = d;
    prev = s;
    have = true;
    return d;
}

} // namespace Deep2
