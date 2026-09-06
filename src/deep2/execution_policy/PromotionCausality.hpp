// ============================================================================
// PromotionCausality.hpp — did G+1 cause the measured improvement?
//
// EXPERIMENTS MAY REGRESS; PROMOTED FRONTIER MAY NOT.
// localSpeedup  = previousGenerationWall / candidateWall
// rootSpeedup   = originalBaselineWall  / candidateWall  (final authority)
// ============================================================================
#pragma once

#include "RealtimeKernel.hpp"
#include "PhysicalWorkCensus.hpp"
#include "SpeedupAttribution.hpp"
#include "EvolutionState.hpp"
#include <cstdio>
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

struct WorkloadIdentity {
    std::string modelFingerprint;
    int context = 0;
    int batchSize = 0;
    uint64_t promptHash = 0;
};

struct HardwareIdentity {
    std::string hardwareFingerprint;
    uint64_t deviceMask = 0;
};

struct GenerationComparison {
    TokenProvenance baseline;
    TokenProvenance candidate;

    double baselineWallUs = 0.0;
    double candidateWallUs = 0.0;
    double realSpeedup = 0.0; // local: baselineWall / candidateWall

    PhysicalWorkDelta delta{};
    SpeedupAttribution attribution{};

    WorkloadIdentity workloadBase{};
    WorkloadIdentity workloadCand{};
    HardwareIdentity hardwareBase{};
    HardwareIdentity hardwareCand{};

    bool outputEquivalent = false;
    bool workloadEquivalent = false;
    bool hardwareEquivalent = false;
    bool authorityEquivalent = false;
    bool imageShaDistinct = false;
    bool physicalWorkDeltaObserved = false;
    bool attributionReferencesCandidateRules = false;
    bool noHiddenConfigChange = false;
    bool noUnaccountedAuthorityChange = false;

    bool promotable = false;
    std::string firstFalse;
    std::string report;
};

struct PromotionFrontier {
    TokenProvenance rootBaseline;     // GEN 0 provenance
    TokenProvenance promoted;         // current accepted frontier
    PhysicalWorkCensus rootCensus{};
    PhysicalWorkCensus promotedCensus{};
    double rootBaselineWallUs = 0.0;
    double localSpeedup = 1.0;        // vs previous promoted
    double rootSpeedup = 1.0;         // vs GEN 0 (authoritative)
    uint64_t promotedGeneration = 0;
    std::vector<uint64_t> history;    // monotonic promoted gens
    std::string lastNote;

    void seed(const TokenProvenance& prov, const PhysicalWorkCensus& census) {
        rootBaseline = prov;
        promoted = prov;
        rootCensus = census;
        promotedCensus = census;
        rootBaselineWallUs = census.wallUs;
        localSpeedup = 1.0;
        rootSpeedup = 1.0;
        promotedGeneration = prov.stateGeneration;
        history.clear();
        history.push_back(prov.stateGeneration);
        lastNote = "seeded root baseline";
    }
};

inline bool WorkloadEqual(const WorkloadIdentity& a, const WorkloadIdentity& b) {
    return a.modelFingerprint == b.modelFingerprint && a.context == b.context &&
           a.batchSize == b.batchSize && a.promptHash == b.promptHash;
}

inline bool HardwareEqual(const HardwareIdentity& a, const HardwareIdentity& b) {
    return a.hardwareFingerprint == b.hardwareFingerprint &&
           a.deviceMask == b.deviceMask;
}

// Attribution must cite candidate ruleset (or physical delta under that image).
inline bool AttributionReferencesRules(const TokenProvenance& cand,
                                       const SpeedupAttribution& attr,
                                       const PhysicalWorkDelta& delta) {
    if (cand.rulesetSha == 0 && cand.proofSetSha == 0)
        return false;
    if (attr.realSpeedup <= 1.0) return false;
    if (delta.physicalWorkDisappearedScore <= 0.0 && delta.netTimeSavedUs <= 0.0)
        return false;
    return true;
}

inline GenerationComparison CompareGenerations(
    const TokenProvenance& baselineProv, const PhysicalWorkCensus& baseline,
    const TokenProvenance& candidateProv, const PhysicalWorkCensus& candidate,
    const WorkloadIdentity& wlBase, const WorkloadIdentity& wlCand,
    const HardwareIdentity& hwBase, const HardwareIdentity& hwCand,
    bool outputEquivalent) {
    GenerationComparison c;
    c.baseline = baselineProv;
    c.candidate = candidateProv;
    c.baselineWallUs = baseline.wallUs;
    c.candidateWallUs = candidate.wallUs;
    c.workloadBase = wlBase;
    c.workloadCand = wlCand;
    c.hardwareBase = hwBase;
    c.hardwareCand = hwCand;
    c.outputEquivalent = outputEquivalent;

    c.workloadEquivalent = WorkloadEqual(wlBase, wlCand);
    c.hardwareEquivalent = HardwareEqual(hwBase, hwCand);
    c.authorityEquivalent =
        (baselineProv.authoritySha != 0 &&
         baselineProv.authoritySha == candidateProv.authoritySha);
    c.imageShaDistinct =
        (baselineProv.stateImageSha != 0 && candidateProv.stateImageSha != 0 &&
         baselineProv.stateImageSha != candidateProv.stateImageSha);
    c.noUnaccountedAuthorityChange = c.authorityEquivalent;
    // Hidden config = policy SHA drift without corresponding image change account.
    c.noHiddenConfigChange =
        (baselineProv.policySha == candidateProv.policySha) ||
        c.imageShaDistinct;

    c.delta = DiffCensus(baseline, candidate);
    c.attribution = AttributionFromDelta(baseline, candidate, c.delta);
    c.realSpeedup = c.delta.realSpeedup;
    c.physicalWorkDeltaObserved =
        (c.delta.physicalWorkDisappearedScore > 0.0);
    c.attributionReferencesCandidateRules =
        AttributionReferencesRules(candidateProv, c.attribution, c.delta);

    auto fail = [&](const char* pred) {
        if (c.firstFalse.empty())
            c.firstFalse = pred;
    };

    if (baselineProv.stateGeneration == 0 && baselineProv.stateImageSha == 0)
        fail("BASELINE_GENERATION_PINNED");
    else if (baselineProv.stateImageSha == 0)
        fail("BASELINE_GENERATION_PINNED");

    if (candidateProv.stateGeneration == 0 &&
        candidateProv.stateImageSha == 0)
        fail("CANDIDATE_GENERATION_PINNED");
    else if (candidateProv.stateImageSha == 0)
        fail("CANDIDATE_GENERATION_PINNED");
    else if (candidateProv.stateGeneration <= baselineProv.stateGeneration)
        fail("CANDIDATE_GENERATION_PINNED");

    if (!c.imageShaDistinct) fail("BASELINE_IMAGE_SHA_DISTINCT");
    if (!c.workloadEquivalent) fail("WORKLOAD_IDENTICAL");
    if (!c.hardwareEquivalent) fail("HARDWARE_IDENTICAL");
    if (!c.authorityEquivalent) fail("POLICY_AUTHORITY_UNCHANGED");
    if (!c.outputEquivalent) fail("OUTPUT_EQUIVALENT");
    if (!c.physicalWorkDeltaObserved) fail("PHYSICAL_WORK_DELTA_OBSERVED");
    if (!c.attributionReferencesCandidateRules)
        fail("ATTRIBUTION_REFERENCES_CANDIDATE_RULES");
    if (!(c.candidateWallUs > 0.0 && c.baselineWallUs > 0.0 &&
          c.candidateWallUs < c.baselineWallUs))
        fail("CANDIDATE_WALL_LT_BASELINE");
    if (!(c.realSpeedup > 1.0)) fail("REAL_SPEEDUP_GT_1");
    if (!(c.delta.netTimeSavedUs > 0.0)) fail("NET_TIME_SAVED_GT_ZERO");
    if (!c.noHiddenConfigChange) fail("NO_HIDDEN_CONFIG_CHANGE");
    if (!c.noUnaccountedAuthorityChange)
        fail("NO_UNACCOUNTED_AUTHORITY_CHANGE");

    c.promotable = c.firstFalse.empty();

    char buf[512];
    std::snprintf(
        buf, sizeof(buf),
        "GEN %llu -> %llu  local=%.3fx  netUs=%.1f  promotable=%s\n"
        "imageSha %llx -> %llx  ruleset %llx -> %llx  proof %llx -> %llx\n"
        "%s",
        (unsigned long long)baselineProv.stateGeneration,
        (unsigned long long)candidateProv.stateGeneration, c.realSpeedup,
        c.delta.netTimeSavedUs, c.promotable ? "yes" : "no",
        (unsigned long long)baselineProv.stateImageSha,
        (unsigned long long)candidateProv.stateImageSha,
        (unsigned long long)baselineProv.rulesetSha,
        (unsigned long long)candidateProv.rulesetSha,
        (unsigned long long)baselineProv.proofSetSha,
        (unsigned long long)candidateProv.proofSetSha,
        c.promotable ? "PROMOTION PASS" : c.firstFalse.c_str());
    c.report = buf;
    return c;
}

enum class PromotionAction : uint8_t {
    Reject = 0,
    Rollback,
    Promote
};

struct PromotionDecision {
    PromotionAction action = PromotionAction::Reject;
    double localSpeedup = 1.0;
    double rootSpeedup = 1.0;
    TokenProvenance restored{}; // set on rollback
    std::string note;
};

// Promote only if comparison passes; otherwise reject (or rollback if applied).
inline PromotionDecision EvaluatePromotion(PromotionFrontier& frontier,
                                           const GenerationComparison& cmp,
                                           bool candidateWasApplied) {
    PromotionDecision d;
    d.localSpeedup =
        ComputeRealSpeedup(frontier.promotedCensus.wallUs, cmp.candidateWallUs);
    d.rootSpeedup =
        ComputeRealSpeedup(frontier.rootBaselineWallUs, cmp.candidateWallUs);

    if (!cmp.promotable) {
        if (candidateWasApplied) {
            d.action = PromotionAction::Rollback;
            d.restored = frontier.promoted;
            d.note = "REGRESSION_OR_GATE_FAIL → ROLLBACK: " + cmp.firstFalse;
        } else {
            d.action = PromotionAction::Reject;
            d.note = "FAILED_CANDIDATE_NOT_PROMOTED: " + cmp.firstFalse;
        }
        return d;
    }

    // Frontier may not regress vs currently promoted wall.
    if (cmp.candidateWallUs >= frontier.promotedCensus.wallUs) {
        d.action = candidateWasApplied ? PromotionAction::Rollback
                                       : PromotionAction::Reject;
        d.restored = frontier.promoted;
        d.note = "PROMOTED_FRONTIER_MAY_NOT_REGRESS";
        return d;
    }

    d.action = PromotionAction::Promote;
    d.note = "PROMOTED_GEN_BECOMES_NEW_BASELINE";
    return d;
}

inline bool ApplyPromotion(PromotionFrontier& frontier,
                           const GenerationComparison& cmp,
                           const PhysicalWorkCensus& candidateCensus,
                           const PromotionDecision& d) {
    if (d.action != PromotionAction::Promote) return false;
    frontier.localSpeedup = d.localSpeedup;
    frontier.rootSpeedup = d.rootSpeedup;
    frontier.promoted = cmp.candidate;
    frontier.promotedCensus = candidateCensus;
    frontier.promotedGeneration = cmp.candidate.stateGeneration;
    frontier.history.push_back(cmp.candidate.stateGeneration);
    frontier.lastNote = d.note;
    return true;
}

inline bool ApplyRollback(PromotionFrontier& frontier,
                          const TokenProvenance& priorProv,
                          const PhysicalWorkCensus& priorCensus) {
    frontier.promoted = priorProv;
    frontier.promotedCensus = priorCensus;
    frontier.promotedGeneration = priorProv.stateGeneration;
    frontier.localSpeedup = 1.0;
    frontier.rootSpeedup =
        ComputeRealSpeedup(frontier.rootBaselineWallUs, priorCensus.wallUs);
    frontier.lastNote = "ROLLBACK_RESTORES_PRIOR_IMAGE_SHA";
    return frontier.promoted.stateImageSha == priorProv.stateImageSha;
}

inline std::string FormatPromotionProvenanceView(
    const GenerationComparison& cmp) {
    char buf[768];
    const double baseMs = cmp.baselineWallUs / 1000.0;
    const double candMs = cmp.candidateWallUs / 1000.0;
    const double disappearedMs = (cmp.baselineWallUs - cmp.candidateWallUs) / 1000.0;
    std::snprintf(
        buf, sizeof(buf),
        "GENERATION          %llu -> %llu\n"
        "RULESET_SHA         %016llx -> %016llx\n"
        "PROOF_SET_SHA       %016llx -> %016llx\n"
        "\n"
        "BASELINE            %.1f ms\n"
        "CANDIDATE           %.1f ms\n"
        "DISAPPEARED         %.1f ms\n"
        "\n"
        "REAL_SPEEDUP        %.3fx\n"
        "PROMOTION           %s\n",
        (unsigned long long)cmp.baseline.stateGeneration,
        (unsigned long long)cmp.candidate.stateGeneration,
        (unsigned long long)cmp.baseline.rulesetSha,
        (unsigned long long)cmp.candidate.rulesetSha,
        (unsigned long long)cmp.baseline.proofSetSha,
        (unsigned long long)cmp.candidate.proofSetSha, baseMs, candMs,
        disappearedMs, cmp.realSpeedup,
        cmp.promotable ? "PASS" : "FAIL");
    return buf;
}

} // namespace Exec
} // namespace Deep2
