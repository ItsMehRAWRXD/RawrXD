// EffectiveTpsAuthority.cpp — RAWRXD_EFFECTIVE_TPS_AUTHORITY_001
#include "EffectiveTpsAuthority.h"
#include "ReceiptAuthority.h"
#include <atomic>
#include <cstdio>
#include <cmath>

namespace rawrxd { namespace perf {

static std::atomic<uint64_t> g_physicalTokens{0};
static std::atomic<uint64_t> g_cachedTokens{0};
static std::atomic<uint64_t> g_replayedTokens{0};
static std::atomic<uint64_t> g_visibleTokens{0};
static std::atomic<uint64_t> g_specAccepted{0};
static std::atomic<uint64_t> g_syntheticTokens{0};

void recordPhysicalToken()         { g_physicalTokens.fetch_add(1, std::memory_order_relaxed); }
void recordPredictedToken()        { /* counted in speculative */ }
void recordCachedToken()           { g_cachedTokens.fetch_add(1, std::memory_order_relaxed); }
void recordReplayedToken()         { g_replayedTokens.fetch_add(1, std::memory_order_relaxed); }
void recordVisibleToken()          { g_visibleTokens.fetch_add(1, std::memory_order_relaxed); }
void recordSpeculativeAccepted(int count) { g_specAccepted.fetch_add(count, std::memory_order_relaxed); }
void recordSyntheticToken()        { g_syntheticTokens.fetch_add(1, std::memory_order_relaxed); }

double getPhysicalTps(double elapsedSec) {
    return (elapsedSec > 0.0) ? (double)g_physicalTokens.load() / elapsedSec : 0.0;
}
double getEffectiveTps(double elapsedSec) {
    uint64_t effective = g_physicalTokens.load() + g_cachedTokens.load() +
                         g_replayedTokens.load() + g_specAccepted.load();
    return (elapsedSec > 0.0) ? (double)effective / elapsedSec : 0.0;
}
double getVisibleTps(double elapsedSec) {
    return (elapsedSec > 0.0) ? (double)g_visibleTokens.load() / elapsedSec : 0.0;
}

void writeEffectiveTpsReceipt(const std::string& path, double elapsedSec) {
    rawrxd::receipt::beginGate(path, "RAWRXD_EFFECTIVE_TPS_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueFloat(path, "PHYSICAL_TPS", getPhysicalTps(elapsedSec));
    rawrxd::receipt::writeKeyValueFloat(path, "VISIBLE_TPS", getVisibleTps(elapsedSec));
    rawrxd::receipt::writeKeyValueFloat(path, "EFFECTIVE_TPS", getEffectiveTps(elapsedSec));
    rawrxd::receipt::writeKeyValueInt(path, "CACHED_TOKEN_COUNT", (int64_t)g_cachedTokens.load());
    rawrxd::receipt::writeKeyValueInt(path, "SPECULATIVE_ACCEPTED_COUNT", (int64_t)g_specAccepted.load());
    rawrxd::receipt::writeKeyValueInt(path, "REPLAYED_TOKEN_COUNT", (int64_t)g_replayedTokens.load());
    rawrxd::receipt::writeKeyValueInt(path, "MODEL_COMPUTED_TOKEN_COUNT", (int64_t)g_physicalTokens.load());
    rawrxd::receipt::writeKeyValueInt(path, "SYNTHETIC_TOKEN_COUNT", (int64_t)g_syntheticTokens.load());
    const char* tpsClass = g_syntheticTokens.load() > 0 ? "synthetic_invalid" :
                           g_cachedTokens.load() > 0 ? "cached" :
                           g_specAccepted.load() > 0 ? "speculative" : "physical";
    rawrxd::receipt::writeKeyValue(path, "TPS_CLAIM_CLASS", tpsClass);
    rawrxd::receipt::endGate(path, g_syntheticTokens.load() == 0 ? "PASS" : "FAIL");
}

}} // namespace rawrxd::perf