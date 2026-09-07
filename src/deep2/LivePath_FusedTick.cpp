// LivePath_FusedTick.cpp — cheap bypass first; full gather only under pressure
#include "Deep2LivePath.hpp"
#include "Deep2LivePath_Internal.hpp"
#include "FusedLiveController.hpp"
#include "CycloneScheduler.hpp"
#include "ElasticResidencyManager.hpp"
#include "ElasticDynamicBudget.hpp"
#include "PlasmaGovernor.hpp"
#include "TrailBrake.hpp"
#include "GpuTransferCounters.hpp"
#include "K2LivePathTensorCache.hpp"
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

rawrxd::PlasmaGovernor*& LivePath_MechPlasma();
ElasticResidencyManager* LivePath_MechElastic();
bool Fused_TryCheapBypass(uint64_t stall, uint32_t queuePeak, bool trailEmerg,
                          bool plasmaAbsent);

void LivePath_FusedTick() {
    if (!Fused_Enabled() || !LivePath_Active()) return;
    uint64_t stall = 0;
    uint32_t q = 0;
    if (auto* cyc = LivePath_ActiveCyclone()) {
        auto t = cyc->GetTelemetry();
        stall = t.stallCyclesTotal;
        q = t.queuePeak;
    }
    const bool tbEmerg = LivePath_MechOn(LP_MECH_TRAILBRAKE) &&
                         GetTrailBrake().GetState() == BrakeState::EMERGENCY;
    const bool plasmaAbs = (LivePath_Ctr().plasmaAbsence != 0);
    if (Fused_TryCheapBypass(stall, q, tbEmerg, plasmaAbs)) return;

    FusedSignals s{};
    s.pinballBounce = LivePath_PinballBounce();
    s.reversalUs = LivePath_Ctr().reversalUsPerToken;
    s.plasmaAbsent = plasmaAbs;
    s.trailbrakeWant = tbEmerg;
    s.cycloneStall = stall;
    s.cycloneQueuePeak = q;
    if (auto* cyc = LivePath_ActiveCyclone())
        s.cycloneActive = cyc->GetTelemetry().activeCyclesTotal;
    if (!plasmaAbs) {
        if (auto* p = LivePath_MechPlasma()) {
            s.plasmaThrottle = p->currentThrottle();
            s.plasmaHot = p->isEmergencyStopped() || s.plasmaThrottle > 0.5f;
        }
    }
#ifdef _WIN32
    MEMORYSTATUSEX mx{};
    mx.dwLength = sizeof(mx);
    if (GlobalMemoryStatusEx(&mx) && mx.ullTotalPhys)
        s.ramHeadroom = (double)mx.ullAvailPhys / (double)mx.ullTotalPhys > 0.15;
#else
    s.ramHeadroom = true;
#endif
    s.vramPressure = false;
    if (auto* el = LivePath_MechElastic()) {
        const size_t hot = el->GetConfig().maxHotBytes;
        s.vramPressure =
            hot && LivePath_Ctr().vramPeak > (hot * 3 / 4);
    } else {
        s.vramPressure = LivePath_Ctr().vramPeak > (384ull << 20);
    }
    auto g = GpuTransfer_Snapshot();
    s.gpuCopyWaitUs = g.waitUs;
    s.gpuCopyOverlapUs = g.overlapUs;
    s.weightHits = g.weightHits;
    s.weightReloads = g.redundantUploads;
    auto lc = K2LiveCache_Snapshot();
    s.liveCacheBytes = lc.bytes;
    s.liveCacheBudget = lc.budget;
    const uint64_t tot = lc.hits + lc.misses;
    s.cacheHitRate = tot ? (double)lc.hits / (double)tot : 1.0;
    auto d = Fused_Decide(s);
    if (auto* el = LivePath_MechElastic()) {
        // Hot lookahead tracks fused depth live — not a reverse-static 2.
        ElasticResidencyConfig caps = el->GetConfig();
        caps.prefetchLookahead =
            d.prefetchDepth ? d.prefetchDepth
                            : (d.brake || d.evictCold ? 0u : caps.prefetchLookahead);
        if (s.vramPressure && caps.maxHotBytes > (512ull << 20))
            caps.maxHotBytes = caps.maxHotBytes * 85 / 100;
        el->ApplyDynamicCaps(caps);
        if (auto* cyc = LivePath_ActiveCyclone())
            cyc->SetPrefetchLookahead(caps.prefetchLookahead);
    }
    if (d.evictCold) {
        if (auto* el = LivePath_MechElastic()) {
            el->EvictLeastRecentlyUsed(16ull << 20);
            Fused_NoteEviction();
        }
    }
}

bool LivePath_FusedWarmupEnabled() {
    if (!Fused_Enabled()) return LivePath_MechOn(LP_MECH_WARMUP);
    if (Fused_Last().bypass) return LivePath_MechOn(LP_MECH_WARMUP);
    return Fused_Last().warmupEnable;
}

bool LivePath_FusedSpeculativeEnabled() {
    if (!Fused_Enabled()) return true;
    return Fused_Last().speculativeEnable;
}

} // namespace Deep2
