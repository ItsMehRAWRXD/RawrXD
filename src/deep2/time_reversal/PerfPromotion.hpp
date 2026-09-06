// PerfPromotion.hpp — generation G → G+1 promotion gates
#pragma once
#include "TimeReversalTypes.hpp"
#include <cstdint>

namespace Deep2 {
namespace TimeReversal {

struct PerfPromotionRecord {
    uint64_t baselineGeneration = 0;
    uint64_t candidateGeneration = 0;
    Hash256 baselineStateSha{};
    Hash256 candidateStateSha{};
    Hash256 policySha{};
    Hash256 authoritySha{};
    Hash256 rulesetSha{};

    double baselineMedianTps = 0.0;
    double candidateMedianTps = 0.0;
    double baselineP95MsToken = 0.0;
    double candidateP95MsToken = 0.0;
    double realSpeedup = 1.0;
    double disappearedMsPerToken = 0.0;
    uint64_t measurementDurationMs = 0;
    uint64_t measuredTokens = 0;

    bool outputEquivalent = false;
    bool sustained = false;
    bool promotable = false;
};

struct PerfPromotionGates {
    bool outputEquivalent = false;
    bool measurementWindowSufficient = false;
    bool realSpeedupGt1 = false;
    bool p95LatencyNotRegressed = false;
    bool residencyCapNotRegressed = false;
    bool noResourceLeak = false;
    bool authorityUnchanged = false;
    bool stateGenerationExact = false;

    bool allPass() const {
        return outputEquivalent && measurementWindowSufficient &&
               realSpeedupGt1 && p95LatencyNotRegressed &&
               residencyCapNotRegressed && noResourceLeak &&
               authorityUnchanged && stateGenerationExact;
    }
};

inline PerfPromotionGates EvaluatePromotionGates(
    const PerfPromotionRecord& rec,
    uint64_t minDurationMs, uint64_t minTokens,
    bool residencyOk, bool noLeak,
    bool authoritySame, bool stateGenExact) {
    PerfPromotionGates g;
    g.outputEquivalent = rec.outputEquivalent;
    g.measurementWindowSufficient =
        rec.measurementDurationMs >= minDurationMs &&
        rec.measuredTokens >= minTokens;
    g.realSpeedupGt1 = rec.realSpeedup > 1.0 && rec.disappearedMsPerToken > 0.0;
    g.p95LatencyNotRegressed =
        rec.candidateP95MsToken <= rec.baselineP95MsToken * 1.01 + 1e-9;
    g.residencyCapNotRegressed = residencyOk;
    g.noResourceLeak = noLeak;
    g.authorityUnchanged = authoritySame;
    g.stateGenerationExact = stateGenExact;
    return g;
}

} // namespace TimeReversal
} // namespace Deep2
