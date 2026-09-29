// EffectiveTpsAuthority.h — RAWRXD_EFFECTIVE_TPS_AUTHORITY_001
// Separates physical TPS from effective/visible/cached/speculative TPS.
// Prevents fake "unlimited TPS" claims while allowing real speed breakthroughs.
#pragma once
#include <string>
#include <cstdint>

namespace rawrxd { namespace perf {

enum class TpsClass : uint8_t {
    PhysicalModel,       // actual model-computed tokens/sec
    EffectiveAccepted,   // useful accepted tokens/sec incl cache/speculation
    VisibleStream,       // tokens shown to user/sec
    CacheReplay,         // tokens served from previous computation
    SpeculativeAccepted, // draft tokens accepted by verifier
    SyntheticInvalid,    // fake/non-model output — must hard-fail
    DebugContaminated    // TPS measured under debug spam — not valid baseline
};

void recordPhysicalToken();
void recordPredictedToken();
void recordCachedToken();
void recordReplayedToken();
void recordVisibleToken();
void recordSpeculativeAccepted(int count);
void recordSyntheticToken();  // should never be called in cert

double getPhysicalTps(double elapsedSec);
double getEffectiveTps(double elapsedSec);
double getVisibleTps(double elapsedSec);

void writeEffectiveTpsReceipt(const std::string& path, double elapsedSec);

}} // namespace rawrxd::perf