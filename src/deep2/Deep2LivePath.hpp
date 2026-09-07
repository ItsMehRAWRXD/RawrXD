// Deep2LivePath.hpp — live generate owns vacuum/trampoline/cyclone/pinball/trailbrake
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstddef>

namespace rawrxd { class PlasmaGovernor; }

namespace Deep2 {

struct LivePathCounters {
    uint32_t vacuumArmed = 0;
    uint32_t trampolineInstalled = 0;
    uint32_t trampolineHits = 0;
    uint32_t cycloneArmed = 0;
    uint32_t cycloneLayerStarts = 0;
    uint32_t cycloneLayerEnds = 0;
    uint32_t cycloneAcquires = 0;
    uint32_t pinballSamples = 0;
    uint32_t trailbrakeAnchors = 0;
    uint32_t trailbrakeReports = 0;
    uint16_t pinballBounce = 0;
    float pinballEarnedBits = 0.f;
    uint32_t elasticArmed = 0;
    uint32_t streamArmed = 0;
    uint32_t streamAlive = 0;
    uint32_t nvmeHops = 0;
    uint32_t plasmaSamples = 0;
    float reversalUsPerToken = 0.f;
    uint32_t pinballBoostTriggers = 0;
    uint32_t pinballLookaheadMax = 0;
    uint32_t trailbrakeChecks = 0;
    uint32_t trailbrakeTriggered = 0;
    uint32_t trailbrakeTokensAvoided = 0;
    uint64_t streamBytesRead = 0;
    uint64_t streamBytesToGpu = 0;
    uint64_t streamBytesReconstructed = 0;
    uint64_t streamReadOps = 0;
    uint64_t streamGpuUploadOps = 0;
    uint64_t streamCacheHits = 0;
    uint64_t streamCacheMisses = 0;
    uint64_t vramPeak = 0;
    uint64_t residentWeightPeak = 0;
    uint64_t perTokenAllocs = 0;
    uint64_t fallbackCount = 0;
    uint64_t cyclonePrefetchHits = 0;
    uint64_t cyclonePrefetchMisses = 0;
    uint64_t cycloneActiveCycles = 0;
    uint64_t cycloneStallCycles = 0;
    uint32_t cycloneQueuePeak = 0;
    uint32_t enhancementsEnabled = 1;
    // 0=ok, 1=unavailable, 2=exhausted
    uint32_t nvmeAbsence = 0;
    // 0=ok, 1=adl_unavailable
    uint32_t plasmaAbsence = 0;
};

class CycloneScheduler;
class ElasticResidencyManager;
class NVMeStream;

// Mechanism bits for LIVE_PATH_INTERACTION_BOUNDS_001 isolation
enum : uint32_t {
    LP_MECH_VACUUM     = 1u << 0,
    LP_MECH_TRAMPOLINE = 1u << 1,
    LP_MECH_CYCLONE    = 1u << 2,
    LP_MECH_ELASTIC    = 1u << 3,
    LP_MECH_PINBALL    = 1u << 4,
    LP_MECH_TRAILBRAKE = 1u << 5,
    LP_MECH_REVERSAL   = 1u << 6,
    LP_MECH_WARMUP     = 1u << 7,
    LP_MECH_STREAM     = 1u << 8, // StreamEngine / NVMe / plasma hops
    LP_MECH_ALL        = 0xFFFFFFFFu
};

void LivePath_SetEnhancementsEnabled(bool enabled);
bool LivePath_EnhancementsEnabled();
void LivePath_SetMechanismMask(uint32_t mask);
uint32_t LivePath_MechanismMask();
bool LivePath_MechOn(uint32_t bit);
bool LivePath_Wanted();
// Parse DEEP2_LIVE_MECH=vacuum,cyclone,elastic,... | all | none
void LivePath_ApplyMechEnv();
// Force a fresh random mechanism mask (hotpatch generate algo) each call.
// Env: DEEP2_LIVE_MECH=all|none|list pins; unset/"random" → random every generate.
uint32_t LivePath_ForceRandomMechMask();
uint32_t LivePath_LastMechMask();

void LivePath_BindOwners(ElasticResidencyManager* elastic, NVMeStream* nvme,
                         rawrxd::PlasmaGovernor* plasma, uint32_t numLayers,
                         uint32_t numHeads);
void LivePath_BeginGenerate(size_t expectedTokens,
                            ElasticResidencyManager* elastic,
                            CycloneScheduler** cycloneOut);
void LivePath_OnLayerStart(CycloneScheduler* cyclone, uint32_t layer, uint64_t seq);
void LivePath_OnLayerEnd(CycloneScheduler* cyclone, uint32_t layer, uint64_t seq,
                         uint64_t latencyUs);
void LivePath_OnToken(uint64_t tokensSoFar);
void LivePath_RecordPinball(float residualL2, float scale);
void LivePath_TouchGate();
void LivePath_EndGenerate(CycloneScheduler* cyclone);
void LivePath_Emit(FILE* f);
const LivePathCounters& LivePath_Counters();
uint16_t LivePath_PinballBounce();
float LivePath_PinballEarnedBits();
bool LivePath_Active();
CycloneScheduler* LivePath_ActiveCyclone();
bool LivePath_ShouldBrake();
uint32_t LivePath_PrefetchBoost();
void LivePath_NotePrefetchPromotions(uint32_t n);
void LivePath_NoteResidencyPeak(uint64_t bytes);
void LivePath_NoteNvmeAbsence(uint32_t code); // 0 ok, 1 unavailable, 2 exhausted

void LivePath_MechArm(ElasticResidencyManager* elastic);
void LivePath_MechLayer(uint32_t layer);
void LivePath_MechToken();
void LivePath_MechEnd();

// Fused control (LIVE_PATH_FUSED_CONTROL_001)
void LivePath_SetFusedEnabled(bool on);
bool LivePath_FusedEnabled();
void LivePath_FusedTick();
bool LivePath_FusedWarmupEnabled();
bool LivePath_FusedSpeculativeEnabled();
ElasticResidencyManager* LivePath_MechElastic();

} // namespace Deep2
