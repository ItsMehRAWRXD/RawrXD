// LivePathEffect.hpp — A/B effectiveness snapshot + deltas
#pragma once
#include "Deep2LivePath.hpp"
#include <cstdio>

namespace Deep2 {

struct LivePathEffectSnap {
    // PERF
    double wallMs = 0;
    double decodeTps = 0;
    double prefillMs = 0;
    uint32_t tokens = 0;
    uint32_t layerDepth = 0;
    // TRANSFER
    uint64_t streamBytesRead = 0;
    uint64_t streamBytesToGpu = 0;
    uint64_t streamBytesRecon = 0;
    uint64_t streamReadOps = 0;
    uint64_t streamGpuUploadOps = 0;
    double streamBytesPerToken = 0;
    // RESIDENCY
    uint64_t vramPeak = 0;
    uint64_t residentWeightPeak = 0;
    uint64_t residentWeightGrowth = 0;
    uint64_t cacheHits = 0;
    uint64_t cacheMisses = 0;
    // CYCLONE
    uint64_t prefetchRequests = 0;
    uint64_t prefetchPromotions = 0;
    uint64_t activeCycles = 0;
    uint64_t stallCycles = 0;
    // PINBALL / REVERSAL / TRAILBRAKE
    uint32_t pinballSamples = 0;
    uint32_t pinballBoostTriggers = 0;
    uint32_t pinballLookaheadMax = 0;
    double reversalUsTotal = 0;
    uint32_t reversalPrefetchBoosts = 0;
    uint32_t trailbrakeChecks = 0;
    uint32_t trailbrakeTriggered = 0;
    uint32_t trailbrakeTokensAvoided = 0;
    // WARMUP
    uint64_t expertAccesses = 0;
    uint64_t expertPrefetches = 0;
    uint64_t expertHits = 0;
    // BOUNDS
    uint32_t queuePeak = 0;
    uint64_t perTokenAllocs = 0;
    uint64_t fallbackCount = 0;
    // ABSENCE
    uint32_t nvmeHops = 0;
    uint32_t nvmeAbsence = 0;   // 0 ok, 1 unavailable, 2 exhausted
    uint32_t plasmaSamples = 0;
    uint32_t plasmaAbsence = 0; // 0 ok, 1 adl_unavailable
    uint32_t enhancements = 0;
};

struct LivePathEffectDelta {
    double tpsDelta = 0;
    double bytesPerTokenDelta = 0;
    double stallDelta = 0;
    int64_t vramPeakDelta = 0;
    double cacheHitDelta = 0;
    double prefetchEfficiency = 0;
};

void LivePath_FillEffectFromCounters(LivePathEffectSnap& s);
void LivePath_EmitEffect(FILE* f, const char* label, const LivePathEffectSnap& s);
LivePathEffectDelta LivePath_ComputeDelta(const LivePathEffectSnap& a,
                                          const LivePathEffectSnap& b);
void LivePath_EmitDelta(FILE* f, const LivePathEffectDelta& d);

} // namespace Deep2
