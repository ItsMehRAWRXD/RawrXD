// ============================================================================
// P1_UNSTATIC_PROMOTION_CAUSALITY_001 — G+1 caused the measured improvement
// EXPERIMENTS MAY REGRESS; PROMOTED FRONTIER MAY NOT.
// Exit: 0 all PASS, 1 otherwise.
// ============================================================================
#include "execution_policy/PromotionCausality.hpp"
#include "execution_policy/RealtimeKernel.hpp"

#include <cstdio>
#include <cmath>

using namespace Deep2::Exec;

static int g_fail = 0;
#define PRED(cond, name)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("[CERT_FAIL] %s\n", name);                              \
            ++g_fail;                                                          \
        } else {                                                               \
            std::printf("[CERT_PASS] %s\n", name);                              \
        }                                                                      \
    } while (0)

static PhysicalWorkCensus MakeCensus(double wallUs, uint64_t nvmePhys,
                                     uint64_t churn, uint32_t mig,
                                     double verifyUs = 0) {
    PhysicalWorkCensus c;
    c.wallUs = wallUs;
    c.wallValid = true;
    c.outputValid = true;
    c.nvmePhysicalReadBytes = nvmePhys;
    c.nvmeUsefulPayloadBytes = nvmePhys / 2;
    c.streamChurnBytes = churn;
    c.bytesHostToGpu = 8ULL << 20;
    c.migrations = mig;
    c.residencyMisses = 10;
    c.runWorkingSetPeak = 2ULL << 30;
    c.peakVramBytes = 3ULL << 30;
    c.verifierOverheadUs = verifyUs;
    return c;
}

static RealtimeStateSnapshot Snap(RealtimeKernel* k, uint64_t token,
                                  uint64_t proof, const char* policy) {
    RealtimeStateSnapshot s;
    s.expectedSchemaHash = k->schemaHash;
    s.expectedAuthorityHash = k->authorityHash;
    s.source = "causality-cert";
    s.state.timing.baselineDecodeMs = 250.0;
    s.state.timing.targetDecodeMs = 100.0;
    s.state.telemetry.tokenIndex = token;
    s.state.policySha = policy;
    if (proof)
        s.state.patches.active.push_back(
            CompileReuseRule(proof, 1, 0xCAFEULL, proof, 18000.0));
    return s;
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_UNSTATIC_PROMOTION_CAUSALITY_001 ===\n");

    RealtimeKernel* kernel = MakeSealedKernel();
    RealtimeEngine engine(kernel);

    WorkloadIdentity wl{"model-fp-A", 4096, 1, 0xABCDEF01ULL};
    HardwareIdentity hw{"hw-fp-A", 0x3ULL};

    // GEN 0 baseline
    CommitResult c0 = engine.CommitRealtimeState(Snap(kernel, 0, 0, "pol-v1"));
    PRED(c0.ok, "ROOT_COMMIT");
    RealtimeReadView v0 = engine.AcquireState();
    TokenProvenance p0 = ProvenanceFromView(v0);
    PhysicalWorkCensus census0 =
        MakeCensus(250000.0, 10ULL << 20, 6ULL << 20, 20, 0);

    PromotionFrontier frontier;
    frontier.seed(p0, census0);
    PRED(frontier.rootBaselineWallUs == 250000.0, "ROOT_BASELINE_SEEDED");

    // GEN 1 candidate — faster, distinct rules, same workload/hw/authority
    CommitResult c1 =
        engine.CommitRealtimeState(Snap(kernel, 1, 101, "pol-v1"));
    PRED(c1.ok, "CANDIDATE_COMMIT");
    RealtimeReadView v1 = engine.AcquireState();
    TokenProvenance p1 = ProvenanceFromView(v1);
    PhysicalWorkCensus census1 =
        MakeCensus(219300.0, (10ULL << 20) - (700ULL << 10), (6ULL << 20) / 2,
                   5, 2300.0);

    GenerationComparison cmp = CompareGenerations(
        p0, census0, p1, census1, wl, wl, hw, hw, /*outputEquivalent=*/true);

    PRED(p0.stateImageSha != 0, "BASELINE_GENERATION_PINNED");
    PRED(p1.stateImageSha != 0 && p1.stateGeneration > p0.stateGeneration,
         "CANDIDATE_GENERATION_PINNED");
    PRED(cmp.imageShaDistinct, "BASELINE_IMAGE_SHA_DISTINCT");
    PRED(cmp.workloadEquivalent, "WORKLOAD_IDENTICAL");
    PRED(cmp.hardwareEquivalent, "HARDWARE_IDENTICAL");
    PRED(cmp.authorityEquivalent, "POLICY_AUTHORITY_UNCHANGED");
    PRED(cmp.outputEquivalent, "OUTPUT_EQUIVALENT");
    PRED(cmp.physicalWorkDeltaObserved, "PHYSICAL_WORK_DELTA_OBSERVED");
    PRED(cmp.attributionReferencesCandidateRules,
         "ATTRIBUTION_REFERENCES_CANDIDATE_RULES");
    PRED(cmp.candidateWallUs < cmp.baselineWallUs, "CANDIDATE_WALL_LT_BASELINE");
    PRED(cmp.realSpeedup > 1.0, "REAL_SPEEDUP_GT_1");
    PRED(cmp.delta.netTimeSavedUs > 0.0, "NET_TIME_SAVED_GT_ZERO");
    PRED(cmp.noHiddenConfigChange, "NO_HIDDEN_CONFIG_CHANGE");
    PRED(cmp.noUnaccountedAuthorityChange, "NO_UNACCOUNTED_AUTHORITY_CHANGE");
    PRED(cmp.promotable, "COMPARISON_PROMOTABLE");

    PromotionDecision d =
        EvaluatePromotion(frontier, cmp, /*candidateWasApplied=*/false);
    PRED(d.action == PromotionAction::Promote, "PROMOTE_DECISION");
    PRED(ApplyPromotion(frontier, cmp, census1, d),
         "PROMOTED_GEN_BECOMES_NEW_BASELINE");
    PRED(frontier.promoted.stateImageSha == p1.stateImageSha,
         "PROMOTED_IMAGE_SHA");
    PRED(std::fabs(frontier.localSpeedup - cmp.realSpeedup) < 1e-9,
         "LOCAL_SPEEDUP");
    PRED(std::fabs(frontier.rootSpeedup - cmp.realSpeedup) < 1e-9,
         "ROOT_SPEEDUP_GEN1");

    const auto view = FormatPromotionProvenanceView(cmp);
    PRED(view.find("PROMOTION") != std::string::npos, "PROVENANCE_VIEW");
    std::printf("--- promotion view ---\n%s\n", view.c_str());

    // --- failed candidate not promoted ---
    CommitResult cBad =
        engine.CommitRealtimeState(Snap(kernel, 2, 202, "pol-v1"));
    PRED(cBad.ok, "SLOW_CANDIDATE_PUBLISHED");
    RealtimeReadView vBad = engine.AcquireState();
    TokenProvenance pBad = ProvenanceFromView(vBad);
    PhysicalWorkCensus censusBad =
        MakeCensus(240000.0, 9ULL << 20, 5ULL << 20, 8, 500.0); // still faster
    // Force regression vs promoted frontier: slower than GEN1
    censusBad.wallUs = 230000.0; // slower than 219300

    GenerationComparison cmpBad = CompareGenerations(
        frontier.promoted, frontier.promotedCensus, pBad, censusBad, wl, wl, hw,
        hw, true);
    // May or may not be promotable on absolute gates — frontier must reject
    PromotionDecision dBad =
        EvaluatePromotion(frontier, cmpBad, /*candidateWasApplied=*/false);
    PRED(dBad.action != PromotionAction::Promote,
         "FAILED_CANDIDATE_NOT_PROMOTED");
    PRED(frontier.promoted.stateImageSha == p1.stateImageSha,
         "FRONTIER_UNCHANGED_AFTER_REJECT");

    // --- output-inequivalent never promotes ---
    PhysicalWorkCensus censusFast =
        MakeCensus(200000.0, 4ULL << 20, 1ULL << 20, 1, 100.0);
    CommitResult cFast =
        engine.CommitRealtimeState(Snap(kernel, 3, 303, "pol-v1"));
    TokenProvenance pFast = ProvenanceFromView(engine.AcquireState());
    GenerationComparison cmpOut = CompareGenerations(
        frontier.promoted, frontier.promotedCensus, pFast, censusFast, wl, wl,
        hw, hw, /*outputEquivalent=*/false);
    PRED(!cmpOut.promotable, "OUTPUT_FAIL_NOT_PROMOTABLE");
    PromotionDecision dOut =
        EvaluatePromotion(frontier, cmpOut, /*candidateWasApplied=*/true);
    PRED(dOut.action == PromotionAction::Rollback, "REGRESSION_ROLLS_BACK");
    const TokenProvenance prior = frontier.promoted;
    const PhysicalWorkCensus priorCensus = frontier.promotedCensus;
    PRED(ApplyRollback(frontier, prior, priorCensus),
         "ROLLBACK_RESTORES_PRIOR_IMAGE_SHA");
    PRED(frontier.promoted.stateImageSha == p1.stateImageSha,
         "ROLLBACK_IMAGE_MATCHES_GEN1");

    // --- authority change blocked ---
    TokenProvenance pAuth = pFast;
    pAuth.authoritySha ^= 0x1ULL;
    GenerationComparison cmpAuth = CompareGenerations(
        frontier.promoted, frontier.promotedCensus, pAuth, censusFast, wl, wl,
        hw, hw, true);
    PRED(!cmpAuth.promotable &&
             cmpAuth.firstFalse == "POLICY_AUTHORITY_UNCHANGED",
         "AUTHORITY_DRIFT_BLOCKS_PROMOTION");

    // --- workload mismatch blocked ---
    WorkloadIdentity wl2 = wl;
    wl2.promptHash ^= 1;
    GenerationComparison cmpWl = CompareGenerations(
        frontier.promoted, frontier.promotedCensus, pFast, censusFast, wl, wl2,
        hw, hw, true);
    PRED(!cmpWl.promotable, "WORKLOAD_MISMATCH_BLOCKS");

    // --- GEN 2 continual improve: local vs root ---
    CommitResult c2 =
        engine.CommitRealtimeState(Snap(kernel, 4, 404, "pol-v1"));
    TokenProvenance p2 = ProvenanceFromView(engine.AcquireState());
    PhysicalWorkCensus census2 =
        MakeCensus(203000.0, 3ULL << 20, (1ULL << 20) / 2, 0, 800.0);
    GenerationComparison cmp2 = CompareGenerations(
        frontier.promoted, frontier.promotedCensus, p2, census2, wl, wl, hw, hw,
        true);
    PRED(cmp2.promotable, "GEN2_PROMOTABLE");
    PromotionDecision d2 =
        EvaluatePromotion(frontier, cmp2, /*candidateWasApplied=*/false);
    PRED(d2.action == PromotionAction::Promote, "GEN2_PROMOTE");
    ApplyPromotion(frontier, cmp2, census2, d2);
    PRED(frontier.localSpeedup > 1.0, "GEN2_LOCAL_SPEEDUP");
    PRED(frontier.rootSpeedup >
             ComputeRealSpeedup(250000.0, 219300.0) - 1e-9,
         "GEN2_ROOT_COMPOUNDS");
    PRED(frontier.rootSpeedup ==
             ComputeRealSpeedup(frontier.rootBaselineWallUs, census2.wallUs),
         "ROOT_SPEEDUP_FROM_EXTERNAL_BASELINE");
    PRED(frontier.history.size() == 3, "HISTORY_GEN0_1_2");

    std::printf("--- frontier local=%.3fx root=%.3fx gen=%llu ---\n",
                frontier.localSpeedup, frontier.rootSpeedup,
                (unsigned long long)frontier.promotedGeneration);
    std::printf("--- cmp report ---\n%s\n", cmp.report.c_str());

    delete kernel;
    std::printf("=== %s: %s (%d fail) ===\n",
                "P1_UNSTATIC_PROMOTION_CAUSALITY_001",
                g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
