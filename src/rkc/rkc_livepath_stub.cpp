// LivePath stub for standalone rkc_smoke link when InferenceEngine unavailable
#include "deep2/Deep2LivePath.hpp"

namespace Deep2 {
static LivePathCounters g_c{};
const LivePathCounters& LivePath_Counters() { return g_c; }
bool LivePath_Active() { return false; }
bool LivePath_ShouldBrake() { return false; }
uint32_t LivePath_PrefetchBoost() { return 0; }
CycloneScheduler* LivePath_ActiveCyclone() { return nullptr; }
void LivePath_SetEnhancementsEnabled(bool) {}
bool LivePath_EnhancementsEnabled() { return false; }
bool LivePath_Wanted() { return false; }
void LivePath_SetMechanismMask(uint32_t) {}
uint32_t LivePath_MechanismMask() { return 0; }
bool LivePath_MechOn(uint32_t) { return false; }
void LivePath_ApplyMechEnv() {}
void LivePath_SetFusedEnabled(bool) {}
bool LivePath_FusedEnabled() { return false; }
void LivePath_FusedTick() {}
bool LivePath_FusedWarmupEnabled() { return false; }
bool LivePath_FusedSpeculativeEnabled() { return true; }
ElasticResidencyManager* LivePath_MechElastic() { return nullptr; }
void LivePath_BindOwners(ElasticResidencyManager*, NVMeStream*,
                         rawrxd::PlasmaGovernor*, uint32_t, uint32_t) {}
void LivePath_BeginGenerate(size_t, ElasticResidencyManager*, CycloneScheduler**) {}
void LivePath_OnLayerStart(CycloneScheduler*, uint32_t, uint64_t) {}
void LivePath_OnLayerEnd(CycloneScheduler*, uint32_t, uint64_t, uint64_t) {}
void LivePath_OnToken(uint64_t) {}
void LivePath_RecordPinball(float, float) {}
void LivePath_TouchGate() {}
void LivePath_EndGenerate(CycloneScheduler*) {}
void LivePath_Emit(FILE*) {}
void LivePath_MechArm(ElasticResidencyManager*) {}
void LivePath_MechLayer(uint32_t) {}
void LivePath_MechToken() {}
void LivePath_MechEnd() {}
uint16_t LivePath_PinballBounce() { return 0; }
float LivePath_PinballEarnedBits() { return 0.f; }
}
