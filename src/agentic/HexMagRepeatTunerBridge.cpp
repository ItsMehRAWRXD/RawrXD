// =============================================================================
// HexMagRepeatTunerBridge.cpp — real adaptive repeat/strategy tuner.
// =============================================================================
// Deterministic strategy progression per request: initial profile, then
// Next() escalates strategy/specialist on failure masks. FNV-1a fingerprints
// and a monotonic generation id. No randomness, no external deps.
// =============================================================================
#include "HexMagRepeatTunerBridge.hpp"

#include <mutex>
#include <string>
#include <unordered_map>

using namespace rawrxd::agentic::hexmag;

namespace {

std::mutex g_mu;
std::unordered_map<std::uint64_t, GenProfile> g_profiles;
std::uint32_t g_maxAttempts = 3;
std::uint64_t g_generation = 0;
GenProfile g_last{};

std::uint64_t Fnv1a(const std::string& s) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

}  // namespace

extern "C" {

std::uint32_t HexMag_Tuner_Init(std::uint32_t maxAttempts) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_maxAttempts = maxAttempts > 0 ? maxAttempts : 1;
    g_profiles.clear();
    // Authoritative convention (HexMagRepeatTunerBridge.hpp RepeatSession):
    // 0 = success; nonzero = failure. The MASM fixed variant returns 0.
    return 0;
}

std::uint32_t HexMag_Tuner_Reset(std::uint64_t requestIdHash) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_profiles.erase(requestIdHash);
    return 1;
}

std::uint64_t HexMag_Tuner_Initial(std::uint64_t requestIdHash,
                                   GenProfile* out) {
    std::lock_guard<std::mutex> lock(g_mu);
    GenProfile p;
    p.strategy = HX_STRAT_DIRECT;
    p.specialist = HX_SPEC_GENERALIST;
    p.tempMilli = 700;
    p.topPMilli = 950;
    p.candidateCount = 1;
    // RepeatSession::valid() contract: blocking queue with 3 passes and a
    // zero weight delta at initialization.
    p.blockingPasses = 3;
    p.queuePolicy = HX_QUEUE_Q_BLOCKING;
    g_profiles[requestIdHash] = p;
    g_last = p;
    if (out) *out = p;
    return ++g_generation;
}

std::uint64_t HexMag_Tuner_Next(std::uint64_t requestIdHash,
                                std::uint32_t failKindMask,
                                std::uint32_t attempt, GenProfile* out) {
    std::lock_guard<std::mutex> lock(g_mu);
    GenProfile p = g_profiles.count(requestIdHash)
        ? g_profiles[requestIdHash]
        : GenProfile{};
    // Escalate strategy on failure.
    if (failKindMask & HX_FAIL_COUNTEREXAMPLE) p.strategy = HX_STRAT_COUNTEREXAMPLE;
    else if (failKindMask & HX_FAIL_TEST) p.strategy = HX_STRAT_REPAIR;
    else if (failKindMask & HX_FAIL_CONTRADICTION) p.strategy = HX_STRAT_DECOMPOSE;
    else if (failKindMask & HX_FAIL_STAGNATION) p.strategy = HX_STRAT_REVERSE;
    else if (attempt > 0) p.strategy = HX_STRAT_DECOMPOSE;
    if (attempt >= g_maxAttempts) p.strategy = HX_STRAT_EVIDENCE_GUARD;
    p.specialist = (p.strategy == HX_STRAT_DIRECT)
        ? HX_SPEC_GENERALIST
        : (p.strategy == HX_STRAT_REPAIR ? HX_SPEC_TEST_DRIVEN
                                         : HX_SPEC_PLANNER);
    p.candidateCount = 1 + (attempt % 4);
    p.mutationNonce = attempt;
    p.blockingPasses = 3;
    p.queuePolicy = HX_QUEUE_Q_BLOCKING;
    g_profiles[requestIdHash] = p;
    g_last = p;
    if (out) *out = p;
    return ++g_generation;
}

std::uint64_t HexMag_Tuner_Fingerprint(const GenProfile* profile) {
    if (!profile) return 0;
    const std::string key = std::to_string(profile->strategy) + ":" +
                            std::to_string(profile->specialist) + ":" +
                            std::to_string(profile->tempMilli) + ":" +
                            std::to_string(profile->candidateCount);
    return Fnv1a(key);
}

std::uint64_t HexMag_Tuner_GenerationId() {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_generation;
}

std::uint32_t HexMag_Tuner_GetProfile(GenProfile* out) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (out) *out = g_last;
    return 1;
}

std::uint32_t HexMag_Tuner_WeightDelta() {
    std::lock_guard<std::mutex> lock(g_mu);
    // Weight delta is the mutation nonce: 0 at initialization, then the
    // attempt index (RepeatSession::valid() requires 0 initially).
    return g_last.mutationNonce;
}

std::uint32_t HexMag_Tuner_Attempt() {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_last.mutationNonce;
}

std::uint32_t HexMag_Tuner_Strategy() {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_last.strategy;
}

}  // extern "C"