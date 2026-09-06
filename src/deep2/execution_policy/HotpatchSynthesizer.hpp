// ============================================================================
// HotpatchSynthesizer.hpp — compile latency/speedup INTENT into hotpatches
//
// TARGET_LATENCY / TARGET_SPEEDUP
//   → Intent → Attribution → DiscoverRemovableWork → PatchSynthesizer
//   → HotpatchCandidate[] → Verifier → Benchmark → Promote / Rollback
//
// Installation is temporary until correctness, authority, and real wall win.
// ============================================================================
#pragma once

#include "LatencyIntent.hpp"
#include "ExecutionObservation.hpp"
#include "ExecutionPolicy.hpp"
#include "EvolutionState.hpp"
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

using PatchId = uint64_t;

enum class PatchKind : uint8_t {
    Skip = 0,
    Reuse,
    Residency,
    Quant,
    Stream,
    Prefetch,
    Fuse,
    Kernel,
    Route,
    Cache
};

struct VerificationPlan {
    bool requireOutputEquivalent = true;
    bool requireAuthorityPreserved = true;
    bool blacklistOnIncorrect = true;
    uint32_t reproduceRuns = 1;
};

struct HotpatchCandidate {
    PatchId id = 0;
    PatchKind kind = PatchKind::Reuse;
    double predictedSavedUs = 0.0;
    double predictedSavedMs = 0.0;
    double predictedSpeedup = 1.0;
    bool touchesWeights = false;
    bool persistent = false;
    bool violatesLocks = false;
    VerificationPlan verifier;
    std::string note;
};

struct HotpatchPlan {
    LatencyIntent latency;
    PerformanceIntent speedup;
    double requiredSavingsUs = 0.0;
    double predictedGrossSavedUs = 0.0;
    double predictedVerifierOverheadUs = 0.0;
    double predictedNetSavedUs = 0.0;
    double predictedSpeedup = 1.0;
    bool targetMetByPrediction = false;
    bool reachable = false;
    std::vector<HotpatchCandidate> selected;
    std::vector<HotpatchCandidate> rejected;
    std::string report;
};

// Distinct from MARS::HotpatchResult (redirect status).
struct HotpatchEvalResult {
    bool outputEquivalent = false;
    bool authorityPreserved = false;
    double baselineWallUs = 0.0;
    double patchedWallUs = 0.0;
    double realSpeedup = 1.0;
    double measuredLatencyMs = 0.0;
    bool promotable = false;     // passed min gain + correctness
    bool targetReached = false;  // met latency/speedup goal
    bool promoted = false;
    CandidateVerdict verdict = CandidateVerdict::Reject;
    std::string note;
};

struct SpeedupIntent {
    double targetRealSpeedup = 1.0;
    bool autoTarget = true;
    double minAcceptedGain = 1.01;
    double maxRegression = 0.0;
};

inline SpeedupIntent SpeedupIntentFromLatency(const LatencyIntent& L) {
    SpeedupIntent s;
    s.targetRealSpeedup = L.requiredSpeedup;
    s.autoTarget = L.autoTarget;
    s.minAcceptedGain = L.minAcceptedGain;
    s.maxRegression = L.maxRegression;
    return s;
}

inline const char* PatchKindName(PatchKind k) {
    switch (k) {
    case PatchKind::Skip: return "HOTPATCH_SKIP";
    case PatchKind::Reuse: return "HOTPATCH_REUSE";
    case PatchKind::Residency: return "HOTPATCH_RESIDENCY";
    case PatchKind::Quant: return "HOTPATCH_QUANT";
    case PatchKind::Stream: return "HOTPATCH_STREAM";
    case PatchKind::Prefetch: return "HOTPATCH_PREFETCH";
    case PatchKind::Fuse: return "HOTPATCH_FUSE";
    case PatchKind::Kernel: return "HOTPATCH_KERNEL";
    case PatchKind::Route: return "HOTPATCH_ROUTE";
    case PatchKind::Cache: return "HOTPATCH_CACHE";
    }
    return "HOTPATCH_UNKNOWN";
}

inline bool CandidateViolatesPolicy(const HotpatchCandidate& c,
                                    const ExecutionPolicy& policy) {
    if (c.violatesLocks) return true;
    if (c.touchesWeights && policy.hotpatch.enabled.present &&
        !policy.hotpatch.enabled.value)
        return true;
    // UserLocked persist: never auto-persist weight-touching patches.
    if (c.persistent && c.touchesWeights &&
        policy.hotpatch.persistLearnedPlan.present &&
        policy.hotpatch.persistLearnedPlan.authority >=
            SettingAuthority::UserLocked &&
        !policy.hotpatch.persistLearnedPlan.value)
        return true;
    return false;
}

inline std::vector<HotpatchCandidate>
SynthesizeHotpatches(const LatencyAttribution& attr, double baselineWallUs) {
    std::vector<HotpatchCandidate> out;
    PatchId next = 1;
    const double baseMs = attr.intent.baselineMs;
    const double baseUs =
        baselineWallUs > 0.0 ? baselineWallUs : baseMs * 1000.0;

    auto add = [&](PatchKind kind, double saveMs, bool weights, bool persist,
                   const char* note) {
        if (saveMs <= 0.0) return;
        HotpatchCandidate c;
        c.id = next++;
        c.kind = kind;
        c.predictedSavedMs = saveMs;
        c.predictedSavedUs = saveMs * 1000.0;
        const double candWall =
            (std::max)(baseUs - c.predictedSavedUs, 1.0);
        c.predictedSpeedup = baseUs / candWall;
        c.touchesWeights = weights;
        c.persistent = persist;
        c.note = note;
        out.push_back(c);
    };

    const auto& r = attr.removable;
    add(PatchKind::Reuse, r.ffnMs * 0.85, false, true, "REUSE_FFN_REGION");
    add(PatchKind::Skip, r.ffnMs * 0.15, false, false, "SKIP_REDUNDANT_FFN");
    add(PatchKind::Kernel, r.attentionMs * 0.70, false, false,
        "GEMV_SPECIALIZATION");
    add(PatchKind::Residency, r.memoryStallMs * 0.55, false, true,
        "PIN_LAYER_RANGE");
    add(PatchKind::Prefetch, r.nvmeMs * 0.45, false, false,
        "PREFETCH_WINDOW_CHANGE");
    add(PatchKind::Stream, r.nvmeMs * 0.35, false, true, "STREAM_REUSE");
    add(PatchKind::Route, r.migrationMs * 0.80, false, true,
        "MIGRATION_ELIMINATION");
    add(PatchKind::Fuse, r.otherMs * 0.50 + r.syncMs * 0.40, false, false,
        "FUSED_EXECUTION");
    add(PatchKind::Cache, r.memoryStallMs * 0.20, false, true,
        "PERSISTENT_CACHE_RULE");
    add(PatchKind::Quant, r.ffnMs * 0.10, true, false,
        "RUNTIME_QUANT_SPECIALIZATION");

    // TTFT-biased extras
    if (attr.intent.kind == LatencyKind::TtftMs) {
        add(PatchKind::Residency, r.nvmeMs * 0.25, false, true,
            "PREFILL_RESIDENCY");
        add(PatchKind::Prefetch, r.migrationMs * 0.20, false, false,
            "KV_INIT_PREFETCH");
    }
    return out;
}

// Helper: map wall µs to latency ms for the active kind.
inline double baseMsFromWall(double baselineWallUs, const LatencyIntent& lat) {
    if (lat.baselineMs > 0.0) return lat.baselineMs;
    return baselineWallUs / 1000.0;
}

inline HotpatchPlan SelectPatchSet(std::vector<HotpatchCandidate> candidates,
                                   double requiredSavingsUs,
                                   double baselineWallUs,
                                   const LatencyIntent& lat,
                                   const PerformanceIntent& speed) {
    HotpatchPlan plan;
    plan.latency = lat;
    plan.speedup = speed;
    plan.requiredSavingsUs = requiredSavingsUs;

    std::sort(candidates.begin(), candidates.end(),
              [](const HotpatchCandidate& a, const HotpatchCandidate& b) {
                  return a.predictedSavedUs > b.predictedSavedUs;
              });

    double accumulated = 0.0;
    for (auto& c : candidates) {
        if (accumulated + 1e-9 >= requiredSavingsUs &&
            requiredSavingsUs > 0.0) {
            plan.rejected.push_back(c);
            continue;
        }
        plan.selected.push_back(c);
        accumulated += c.predictedSavedUs;
    }

    plan.predictedGrossSavedUs = accumulated;
    plan.predictedVerifierOverheadUs =
        plan.selected.empty() ? 0.0 : requiredSavingsUs * 0.05;
    plan.predictedNetSavedUs =
        plan.predictedGrossSavedUs - plan.predictedVerifierOverheadUs;
    const double predWall =
        (std::max)(baselineWallUs - plan.predictedNetSavedUs, 1.0);
    plan.predictedSpeedup =
        baselineWallUs > 0.0 ? (baselineWallUs / predWall) : 1.0;
    const double predLatMs =
        baseMsFromWall(baselineWallUs, lat) - plan.predictedNetSavedUs / 1000.0;
    plan.targetMetByPrediction =
        (plan.predictedSpeedup + 1e-9 >= lat.requiredSpeedup) ||
        (lat.targetMs > 0.0 && predLatMs <= lat.targetMs + 1e-9);
    plan.reachable = plan.targetMetByPrediction;

    char buf[320];
    std::snprintf(
        buf, sizeof(buf),
        "patches=%zu rejected=%zu requiredUs=%.1f netUs=%.1f predSpeedup=%.3fx "
        "meetsTarget=%s",
        plan.selected.size(), plan.rejected.size(), plan.requiredSavingsUs,
        plan.predictedNetSavedUs, plan.predictedSpeedup,
        plan.targetMetByPrediction ? "yes" : "no");
    plan.report = buf;
    return plan;
}

inline HotpatchPlan EngineerLatencyIntoHotpatch(
    const LatencyPolicy& latencyPol, const SpeedupPolicy& speedPol,
    const ExecutionObservation& obs, const ExecutionPolicy& policy,
    double e2eWallUs) {
    HotpatchPlan empty;
    const LatencyBaseline base =
        BaselineFromObservation(obs.tokensPerSecond, obs.ttftMs,
                                e2eWallUs / 1000.0);
    PhysicalWorkCensus census = CensusFromObservation(obs, e2eWallUs);
    const LatencyAttribution attr =
        AttributeLatency(latencyPol, base, census);

    // Prefer latency-derived required savings; fall back to speedup ratio.
    PerformanceIntent perf = PerformanceIntentFromLatency(attr.intent);
    if (attr.intent.requiredSpeedup <= 1.0 &&
        speedPol.targetRealSpeedup.present) {
        const ReverseSolveResult rs = ReverseSolve(speedPol, census);
        perf = rs.intent;
    }

    const double baselineWallUs =
        e2eWallUs > 0.0
            ? e2eWallUs
            : (attr.intent.baselineMs > 0.0 ? attr.intent.baselineMs * 1000.0
                                            : 0.0);
    const double requiredUs =
        perf.requiredNetRemovalUs > 0.0
            ? perf.requiredNetRemovalUs
            : attr.intent.requiredSavingsMs * 1000.0;

    auto candidates = SynthesizeHotpatches(attr, baselineWallUs);
    std::vector<HotpatchCandidate> ok;
    std::vector<HotpatchCandidate> bad;
    for (auto& c : candidates) {
        if (CandidateViolatesPolicy(c, policy)) {
            c.violatesLocks = true;
            bad.push_back(c);
        } else {
            ok.push_back(c);
        }
    }

    HotpatchPlan plan =
        SelectPatchSet(ok, requiredUs, baselineWallUs, attr.intent, perf);
    plan.rejected.insert(plan.rejected.end(), bad.begin(), bad.end());
    plan.reachable = attr.reachable && plan.targetMetByPrediction;
    plan.report = attr.report + "\n" + plan.report;
    return plan;
}

// Convenience: speedup-ratio intent path (still compiles to hotpatches).
inline HotpatchPlan EngineerSpeedupIntoHotpatch(
    const SpeedupIntent& intent, const ExecutionObservation& obs,
    const ExecutionPolicy& policy, double wallUs) {
    LatencyPolicy lp = MakeDefaultLatencyPolicy();
    lp.autoTarget.force(false, SettingAuthority::Session,
                        SettingMutability::Immediate);
    SpeedupPolicy sp = MakeDefaultSpeedupPolicy();
    sp.autoTarget.force(false, SettingAuthority::Session,
                        SettingMutability::Immediate);
    sp.targetRealSpeedup.force(intent.targetRealSpeedup,
                               SettingAuthority::Session,
                               SettingMutability::Immediate);
    sp.minimumAcceptedGain.force(intent.minAcceptedGain,
                                 SettingAuthority::Session,
                                 SettingMutability::Immediate);

    // Encode ratio as decode target when TPS known.
    if (obs.tokensPerSecond > 0.0 && intent.targetRealSpeedup > 1.0) {
        const double baseMs = MsPerTokenFromTps(obs.tokensPerSecond);
        lp.targetDecodeMs.force(baseMs / intent.targetRealSpeedup,
                                SettingAuthority::Session,
                                SettingMutability::Immediate);
    }
    return EngineerLatencyIntoHotpatch(lp, sp, obs, policy, wallUs);
}

// Transactional evaluate: SNAPSHOT semantics live in EvolutionState baseline.
inline HotpatchEvalResult EvaluateHotpatchTransaction(
    EvolutionState& evo, const HotpatchPlan& plan, const SpeedupIntent& intent,
    const PhysicalWorkCensus& candidate, bool outputEquivalent,
    bool authorityPreserved) {
    HotpatchEvalResult r;
    r.outputEquivalent = outputEquivalent;
    r.authorityPreserved = authorityPreserved;
    r.baselineWallUs = evo.baseline.wallUs;
    r.patchedWallUs = candidate.wallUs;
    r.realSpeedup =
        ComputeRealSpeedup(r.baselineWallUs, r.patchedWallUs);
    r.measuredLatencyMs =
        (plan.latency.kind == LatencyKind::DecodeMsPerToken &&
         r.patchedWallUs > 0.0)
            ? (plan.latency.baselineMs > 0.0
                   ? plan.latency.baselineMs *
                         (r.patchedWallUs / (std::max)(r.baselineWallUs, 1.0))
                   : r.patchedWallUs / 1000.0)
            : r.patchedWallUs / 1000.0;

    if (!outputEquivalent) {
        r.verdict = CandidateVerdict::Reject;
        r.note = "OUTPUT_NOT_EQUIVALENT → ROLLBACK";
        return r;
    }
    if (!authorityPreserved) {
        r.verdict = CandidateVerdict::Reject;
        r.note = "AUTHORITY_NOT_PRESERVED → ROLLBACK";
        return r;
    }
    if (r.realSpeedup + 1e-12 < intent.minAcceptedGain) {
        r.verdict = CandidateVerdict::Reject;
        r.note = "BELOW_MIN_ACCEPTED_GAIN → ROLLBACK";
        return r;
    }

    r.promotable = true;
    r.targetReached =
        LatencyTargetReached(plan.latency, r.measuredLatencyMs) ||
        (intent.targetRealSpeedup > 1.0 &&
         r.realSpeedup + 1e-12 >= intent.targetRealSpeedup);

    // Promote local improvement even if goal not yet reached.
    const EvolutionStepRecord step =
        StepEvolution(evo, candidate, outputEquivalent, authorityPreserved);
    r.verdict = step.verdict;
    r.promoted = (step.verdict == CandidateVerdict::Promote);
    if (r.promoted) {
        r.note = r.targetReached ? "PROMOTED_TARGET_REACHED"
                                 : "PROMOTED_TARGET_NOT_REACHED_CONTINUE_SEARCH";
    } else {
        r.note = step.note;
    }
    return r;
}

} // namespace Exec
} // namespace Deep2
