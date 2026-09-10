// Deep2LivePath.cpp â€” per-request live-path ownership + mechanism mask
#include "Deep2LivePath.hpp"
#include "Deep2LivePath_Internal.hpp"
#include "CycloneScheduler.hpp"
#include "Deep2ThreadTuning.hpp"
#include "TrailBrake.hpp"
#include "StreamTransferCounters.hpp"
#include "GpuTransferCounters.hpp"
#include "FusedLiveController.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <chrono>
#ifdef _WIN32
#include <string.h>
#endif

namespace Deep2 {

bool LivePath_InstallTrampoline();
void LivePath_UninstallTrampoline();
uint32_t LivePath_TrampolineHits();
void LivePath_PinballArm();
void LivePath_PinballDisarm();
uint32_t LivePath_PinballSamples();
void LivePath_FusedTick();

namespace {
std::mutex g_mu;
LivePathCounters g_ctr{};
bool g_active = false;
bool g_brake = false;
CycloneScheduler* g_cyclone = nullptr;
bool g_enhancements = true;
uint32_t g_mechMask = LP_MECH_ALL;
uint64_t g_expectedTokens = 0;
bool g_mechAppliedPending = false;
} // namespace

LivePathCounters& LivePath_Ctr() { return g_ctr; }

void LivePath_SetEnhancementsEnabled(bool enabled) { g_enhancements = enabled; }
bool LivePath_EnhancementsEnabled() { return g_enhancements; }
void LivePath_SetMechanismMask(uint32_t mask) { g_mechMask = mask; }
uint32_t LivePath_MechanismMask() { return g_mechMask; }
bool LivePath_MechOn(uint32_t bit) {
    return g_enhancements && (g_mechMask & bit) != 0;
}
void LivePath_SetFusedEnabled(bool on) { Fused_SetEnabled(on); }
bool LivePath_FusedEnabled() { return Fused_Enabled(); }

bool LivePath_Wanted() {
    const char* e = std::getenv("DEEP2_LIVE_PATH");
    if (!e || !e[0]) return true;
    if (e[0] == '0' && e[1] == 0) return false;
#ifdef _WIN32
    if (_stricmp(e, "off") == 0 || _stricmp(e, "false") == 0 || _stricmp(e, "no") == 0)
        return false;
#endif
    return true;
}

static void OrName(uint32_t& m, const char* tok, size_t n) {
    auto eq = [&](const char* s) -> bool {
        const size_t L = std::strlen(s);
        if (n != L) return false;
#ifdef _WIN32
        return _strnicmp(tok, s, (unsigned)n) == 0;
#else
        return strncasecmp(tok, s, n) == 0;
#endif
    };
    if (eq("vacuum")) m |= LP_MECH_VACUUM;
    else if (eq("trampoline")) m |= LP_MECH_TRAMPOLINE;
    else if (eq("cyclone")) m |= LP_MECH_CYCLONE;
    else if (eq("elastic")) m |= LP_MECH_ELASTIC;
    else if (eq("pinball")) m |= LP_MECH_PINBALL;
    else if (eq("trailbrake") || eq("trail")) m |= LP_MECH_TRAILBRAKE;
    else if (eq("reversal")) m |= LP_MECH_REVERSAL;
    else if (eq("warmup")) m |= LP_MECH_WARMUP;
    else if (eq("stream") || eq("nvme") || eq("plasma")) m |= LP_MECH_STREAM;
}

uint32_t LivePath_ForceRandomMechMask() {
    static const uint32_t kBits[] = {
        LP_MECH_VACUUM, LP_MECH_TRAMPOLINE, LP_MECH_CYCLONE, LP_MECH_ELASTIC,
        LP_MECH_PINBALL, LP_MECH_TRAILBRAKE, LP_MECH_REVERSAL, LP_MECH_WARMUP,
        LP_MECH_STREAM};
    const uint64_t t =
        (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
    uint32_t seed = (uint32_t)(t ^ (t >> 32) ^ (uint32_t)(uintptr_t)&g_ctr);
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    uint32_t m = 0;
    for (uint32_t b : kBits) {
        seed = seed * 1664525u + 1013904223u;
        if (seed & 1u) m |= b;
    }
    // Never arm an empty stack — always keep trampoline as the hotpatch gate.
    if (m == 0) m = LP_MECH_TRAMPOLINE | LP_MECH_PINBALL;
    g_mechMask = m;
    return m;
}

uint32_t LivePath_LastMechMask() { return g_mechMask; }

void LivePath_ApplyMechEnv() {
    const char* e = std::getenv("DEEP2_LIVE_MECH");
    // Force random every generate unless explicitly pinned.
    if (!e || !e[0] || _stricmp(e, "random") == 0) {
        LivePath_ForceRandomMechMask();
        g_mechAppliedPending = true;
        return;
    }
    if (_stricmp(e, "all") == 0) {
        g_mechMask = LP_MECH_ALL;
        g_mechAppliedPending = true;
        return;
    }
    if (_stricmp(e, "none") == 0 || _stricmp(e, "off") == 0) {
        g_mechMask = 0;
        g_mechAppliedPending = true;
        return;
    }
    uint32_t m = 0;
    const char* p = e;
    while (*p) {
        while (*p == ',' || *p == ' ') ++p;
        const char* s = p;
        while (*p && *p != ',' && *p != ' ') ++p;
        if (p > s) OrName(m, s, (size_t)(p - s));
    }
    g_mechMask = m;
    g_mechAppliedPending = true;
}

void LivePath_BeginGenerate(size_t expectedTokens,
                            ElasticResidencyManager* elastic,
                            CycloneScheduler** cycloneOut) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_active) {
        LivePath_PinballDisarm();
        LivePath_UninstallTrampoline();
        g_active = false;
        g_cyclone = nullptr;
    }
    if (!g_mechAppliedPending)
        LivePath_ApplyMechEnv();
    g_mechAppliedPending = false;
    // Print mask only — HotPatcher validate re-locks its mutex via PatchSafety
    // (resource_deadlock) and previously aborted the trampoline stream.
    {
        const char* me = std::getenv("DEEP2_LIVE_MECH");
        const int isRand = (!me || !me[0] || _stricmp(me, "random") == 0) ? 1 : 0;
        printf("[LivePath] GENERATE_ALG_MASK=0x%08X random=%d\n", g_mechMask, isRand);
        fflush(stdout);
    }
    if (const char* fe = std::getenv("DEEP2_LIVE_FUSED")) {
        if (fe[0] == '1' && fe[1] == 0) Fused_SetEnabled(true);
        else if (fe[0] == '0' && fe[1] == 0) Fused_SetEnabled(false);
    }
    g_ctr = {};
    g_ctr.enhancementsEnabled = g_enhancements ? 1u : 0u;
    g_brake = false;
    g_expectedTokens = expectedTokens;
    g_active = true;
    g_cyclone = (cycloneOut && *cycloneOut) ? *cycloneOut : nullptr;
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    Fused_Reset();

    if (LivePath_MechOn(LP_MECH_VACUUM)) {
        Deep2ThreadTuning::VacuumSequestrationOS();
        Deep2ThreadTuning::LockComputePipeline(0, false);
        g_ctr.vacuumArmed = 1;
    }
    if (LivePath_MechOn(LP_MECH_TRAILBRAKE)) {
        GetTrailBrake().Initialize();
        GetTrailBrake().SetExpectedTokens(static_cast<uint64_t>(expectedTokens));
        if (!GetTrailBrake().DropAnchor("live_generate", "Deep2Engine::generate").empty())
            g_ctr.trailbrakeAnchors = 1;
    }
    if (LivePath_MechOn(LP_MECH_TRAMPOLINE)) {
        if (LivePath_InstallTrampoline())
            g_ctr.trampolineInstalled = 1;
        LivePath_TouchGate();
        g_ctr.trampolineHits = LivePath_TrampolineHits();
    }
    if (LivePath_MechOn(LP_MECH_PINBALL))
        LivePath_PinballArm();
    if (LivePath_MechOn(LP_MECH_CYCLONE) && g_cyclone)
        g_ctr.cycloneArmed = 1;
    if (LivePath_MechOn(LP_MECH_ELASTIC) || LivePath_MechOn(LP_MECH_STREAM) ||
        LivePath_MechOn(LP_MECH_REVERSAL))
        LivePath_MechArm(elastic);
    LivePath_FusedTick();
}

void LivePath_OnLayerStart(CycloneScheduler* cyclone, uint32_t layer, uint64_t seq) {
    if (!g_active) return;
    LivePath_FusedTick();
    if (LivePath_MechOn(LP_MECH_TRAMPOLINE)) LivePath_TouchGate();
    if (LivePath_MechOn(LP_MECH_STREAM) || LivePath_MechOn(LP_MECH_ELASTIC))
        LivePath_MechLayer(layer);
    if (!LivePath_MechOn(LP_MECH_CYCLONE) || !cyclone) return;
    /* Fused speculative-off: drop cyclone elastic queue (wall-only demands).
     * STREAM no longer vetoes OnLayerStart — reverse bunnyhop hops via
     * MechArm/MechToken; DualStick PASSIVE elastic leaves cyclone.elastic_=null. */
    if (Fused_Enabled() && !LivePath_FusedSpeculativeEnabled()) {
        Fused_NoteDroppedPrefetch();
        g_ctr.cycloneLayerStarts++;
        (void)layer;
        (void)seq;
        if (LivePath_MechOn(LP_MECH_TRAMPOLINE))
            g_ctr.trampolineHits = LivePath_TrampolineHits();
        return;
    }
    cyclone->OnLayerStart(layer, seq, nullptr, 0);
    g_ctr.cycloneLayerStarts++;
    if (LivePath_MechOn(LP_MECH_TRAMPOLINE))
        g_ctr.trampolineHits = LivePath_TrampolineHits();
}

void LivePath_OnLayerEnd(CycloneScheduler* cyclone, uint32_t layer, uint64_t seq,
                         uint64_t latencyUs) {
    if (!g_active || !LivePath_MechOn(LP_MECH_CYCLONE) || !cyclone) return;
    cyclone->OnLayerComplete(layer, seq, latencyUs);
    g_ctr.cycloneLayerEnds++;
}

void LivePath_OnToken(uint64_t tokensSoFar) {
    if (!g_active) return;
    if (LivePath_MechOn(LP_MECH_TRAMPOLINE)) LivePath_TouchGate();
    if (LivePath_MechOn(LP_MECH_STREAM)) LivePath_MechToken();
    if (LivePath_MechOn(LP_MECH_TRAILBRAKE)) {
        GetTrailBrake().ReportActualTokens(tokensSoFar);
        g_ctr.trailbrakeReports++;
        g_ctr.trailbrakeChecks++;
        if (!GetTrailBrake().ShouldProceed() ||
            GetTrailBrake().GetBrakeIntensity() > 0.85f) {
            g_brake = true;
            g_ctr.trailbrakeTriggered++;
            if (g_expectedTokens > tokensSoFar)
                g_ctr.trailbrakeTokensAvoided =
                    (uint32_t)(g_expectedTokens - tokensSoFar);
        }
    }
    if (LivePath_MechOn(LP_MECH_TRAMPOLINE))
        g_ctr.trampolineHits = LivePath_TrampolineHits();
    if (LivePath_MechOn(LP_MECH_PINBALL)) {
        g_ctr.pinballSamples = LivePath_PinballSamples();
        g_ctr.pinballBounce = LivePath_PinballBounce();
        g_ctr.pinballEarnedBits = LivePath_PinballEarnedBits();
    }
    LivePath_FusedTick();
    if (Fused_Enabled() && Fused_Last().brake) {
        g_brake = true;
    }
}

void LivePath_EndGenerate(CycloneScheduler* cyclone) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_active) return;
    if (LivePath_MechOn(LP_MECH_PINBALL)) {
        g_ctr.pinballSamples = LivePath_PinballSamples();
        g_ctr.pinballBounce = LivePath_PinballBounce();
        g_ctr.pinballEarnedBits = LivePath_PinballEarnedBits();
    }
    if (LivePath_MechOn(LP_MECH_TRAMPOLINE))
        g_ctr.trampolineHits = LivePath_TrampolineHits();
    if (cyclone && LivePath_MechOn(LP_MECH_CYCLONE)) {
        auto snap = cyclone->GetTelemetry();
        g_ctr.cycloneAcquires = static_cast<uint32_t>(snap.demandsIssued);
        g_ctr.cyclonePrefetchHits = snap.prefetchHits;
        g_ctr.cyclonePrefetchMisses = snap.prefetchMisses;
        g_ctr.cycloneActiveCycles = snap.activeCyclesTotal;
        g_ctr.cycloneStallCycles = snap.stallCyclesTotal;
        g_ctr.cycloneQueuePeak = snap.queuePeak;
    }
    if (LivePath_MechOn(LP_MECH_REVERSAL) || LivePath_MechOn(LP_MECH_STREAM))
        LivePath_MechEnd();
    // STC = physical transfer this run (â‰  GGUF corpus size).
    {
        const auto x = StreamTransfer_Snapshot();
        if (x.bytesRead || x.readOps || x.gpuUploadOps) {
            g_ctr.streamBytesRead = x.bytesRead;
            g_ctr.streamBytesToGpu = x.bytesToGpu;
            g_ctr.streamBytesReconstructed = x.bytesReconstructed;
            g_ctr.streamReadOps = x.readOps;
            g_ctr.streamGpuUploadOps = x.gpuUploadOps;
            g_ctr.streamCacheHits = x.cacheHits;
            g_ctr.streamCacheMisses = x.cacheMisses;
        }
    }
    if (LivePath_MechOn(LP_MECH_PINBALL)) LivePath_PinballDisarm();
    if (LivePath_MechOn(LP_MECH_TRAMPOLINE)) LivePath_UninstallTrampoline();
    if (LivePath_MechOn(LP_MECH_TRAILBRAKE)) GetTrailBrake().PruneAnchors(1);
    g_cyclone = nullptr;
    g_active = false;
}

const LivePathCounters& LivePath_Counters() { return g_ctr; }
bool LivePath_Active() { return g_active; }
CycloneScheduler* LivePath_ActiveCyclone() { return g_cyclone; }
bool LivePath_ShouldBrake() {
    const char* lim = std::getenv("TRAILBRAKE_TPS_LIMIT");
    if (!lim || lim[0] == '0' || std::strcmp(lim, "OFF") == 0)
        return false;
    if (Fused_Enabled())
        return Fused_Last().brake && LivePath_MechOn(LP_MECH_TRAILBRAKE);
    return g_brake && LivePath_MechOn(LP_MECH_TRAILBRAKE);
}
uint32_t LivePath_PrefetchBoost() {
    // Healthy bypass â†’ independent Pinball/Reversal; else fused sole owner.
    const bool fusedOwns =
        Fused_Enabled() && !Fused_Last().bypass;
    if (fusedOwns) {
        const uint32_t n = Fused_Last().prefetchDepth ? 1u : 0u;
        if (n > g_ctr.pinballLookaheadMax) g_ctr.pinballLookaheadMax = n;
        if (n) g_ctr.pinballBoostTriggers++;
        return n;
    }
    if (!LivePath_MechOn(LP_MECH_PINBALL) && !LivePath_MechOn(LP_MECH_REVERSAL))
        return 0;
    uint32_t n = 0;
    if (LivePath_MechOn(LP_MECH_PINBALL) && LivePath_PinballBounce() >= 180) {
        g_ctr.pinballBoostTriggers++;
        n = 1u;
    } else if (LivePath_MechOn(LP_MECH_REVERSAL) &&
               g_ctr.reversalUsPerToken >= 800.f) {
        g_ctr.pinballBoostTriggers++;
        n = 1u;
    }
    if (n > g_ctr.pinballLookaheadMax) g_ctr.pinballLookaheadMax = n;
    return n;
}

void LivePath_NotePrefetchPromotions(uint32_t n) {
    g_ctr.cyclonePrefetchHits += n;
}

void LivePath_NoteResidencyPeak(uint64_t bytes) {
    if (bytes > g_ctr.vramPeak) g_ctr.vramPeak = bytes;
    if (bytes > g_ctr.residentWeightPeak) g_ctr.residentWeightPeak = bytes;
}

void LivePath_NoteNvmeAbsence(uint32_t code) {
    g_ctr.nvmeAbsence = code;
}

} // namespace Deep2
