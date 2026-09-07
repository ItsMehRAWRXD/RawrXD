// FusedLiveController.hpp — ONE signal → ONE policy → ONE actuator
#pragma once
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct FusedSignals {
    uint16_t pinballBounce = 0;
    uint64_t cycloneStall = 0;
    uint64_t cycloneActive = 0;
    uint32_t cycloneQueuePeak = 0;
    float reversalUs = 0.f;
    float plasmaThrottle = 0.f;
    bool plasmaHot = false;
    bool plasmaAbsent = false;
    bool trailbrakeWant = false; // actionable stop only
    bool vramPressure = false;
    bool ramHeadroom = false;
    uint64_t warmupMisses = 0;
    uint64_t warmupHits = 0;
    uint64_t gpuCopyWaitUs = 0;
    uint64_t gpuCopyOverlapUs = 0;
    uint64_t weightHits = 0;
    uint64_t weightReloads = 0;
    double cacheHitRate = 1.0;
    uint64_t liveCacheBytes = 0;
    uint64_t liveCacheBudget = 0;
};

struct FusedDecision {
    uint32_t prefetchDepth = 0;
    uint32_t reverseDepth = 0;
    bool urgentAcquire = false;
    bool speculativeEnable = true;
    bool evictCold = false;
    bool warmupEnable = false;
    bool brake = false;
    bool bypass = false;
};

struct FusedCounters {
    uint32_t decisions = 0;
    uint32_t prefetchDepthSum = 0;
    uint32_t prefetchDepthMax = 0;
    uint32_t reverseDepthSum = 0;
    uint32_t reverseDepthMax = 0;
    uint32_t urgentAcquires = 0;
    uint32_t speculativeSuppressed = 0;
    uint32_t evictions = 0;
    uint32_t warmupEnables = 0;
    uint32_t brakes = 0;
    uint32_t conflictsAvoided = 0;
    uint32_t prefetchRequestsDropped = 0;
    uint32_t duplicatePrefetches = 0;
    uint32_t queuePeak = 0;
    uint32_t fastBypass = 0;
    uint32_t signalChanges = 0;
    uint32_t policyChanges = 0;
    uint32_t decisionsSkipped = 0;
    uint64_t decisionUs = 0;
    uint64_t brakeUs = 0;
    uint64_t suppressionUs = 0;
    uint64_t totalControlUs = 0;
};

void Fused_Reset();
void Fused_SetEnabled(bool on);
bool Fused_Enabled();
FusedDecision Fused_Decide(const FusedSignals& s);
const FusedDecision& Fused_Last();
const FusedCounters& Fused_Counters();
void Fused_Emit(FILE* f);
void Fused_NoteDroppedPrefetch();
void Fused_NoteDuplicatePrefetch();
void Fused_NoteEviction();

} // namespace Deep2
