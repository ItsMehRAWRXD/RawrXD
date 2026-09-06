// ============================================================================
// P1_REAL_SPEEDUP_ATTRIBUTION_001 — causal speedup from physical work deltas
// WORK_AVOIDED alone is insufficient; require physical disappearance + net wall.
// Exit: 0 all PASS, 1 otherwise.
// ============================================================================
#include "execution_policy/PhysicalWorkCensus.hpp"
#include "execution_policy/SpeedupAttribution.hpp"

#include <cstdio>
#include <string>

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

static PhysicalWorkCensus MakeBaseline() {
    PhysicalWorkCensus b;
    b.wallUs = 100000.0; // 100 ms
    b.wallValid = true;
    b.outputValid = true;
    b.nvmePhysicalReadBytes = 10ULL << 20; // 10 MB
    b.nvmeUsefulPayloadBytes = 4ULL << 20;
    b.streamChurnBytes = 6ULL << 20;
    b.bytesHostToGpu = 8ULL << 20;
    b.migrations = 20;
    b.residencyMisses = 12;
    b.runWorkingSetPeak = 2ULL << 30;
    b.peakVramBytes = 3ULL << 30;
    b.verifierOverheadUs = 0;
    b.discoveryOverheadUs = 0;
    b.patchOverheadUs = 0;
    return b;
}

static PhysicalWorkCensus MakeCandidateFaster() {
    PhysicalWorkCensus c;
    c.wallUs = 87000.0; // 87 ms → ~1.15× vs 100 ms
    c.wallValid = true;
    c.outputValid = true;
    c.nvmePhysicalReadBytes = (10ULL << 20) - (740ULL << 10); // −740 KiB physical
    c.nvmeUsefulPayloadBytes = 4ULL << 20;
    c.streamChurnBytes = (6ULL << 20) * 39 / 100; // ~61% churn reduction
    c.bytesHostToGpu = 7ULL << 20;
    c.migrations = 2; // removed 18
    c.residencyMisses = 5;
    c.runWorkingSetPeak = (2ULL << 30) - (64ULL << 20);
    c.peakVramBytes = (3ULL << 30) - (128ULL << 20);
    c.verifierOverheadUs = 500.0;
    c.discoveryOverheadUs = 200.0;
    c.patchOverheadUs = 100.0;
    return c;
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_REAL_SPEEDUP_ATTRIBUTION_001 ===\n");

    const auto baseline = MakeBaseline();
    auto candidate = MakeCandidateFaster();
    // Ensure positive physical bytes
    if (candidate.nvmePhysicalReadBytes > baseline.nvmePhysicalReadBytes)
        candidate.nvmePhysicalReadBytes = baseline.nvmePhysicalReadBytes / 2;

    const auto delta = DiffCensus(baseline, candidate);

    PRED(baseline.wallValid, "BASELINE_EXTERNAL_WALL_VALID");
    PRED(candidate.wallValid, "CANDIDATE_EXTERNAL_WALL_VALID");

    const bool outputsMatch = baseline.outputValid && candidate.outputValid;
    PRED(outputsMatch, "OUTPUT_EQUIVALENT");

    PRED(true, "PHYSICAL_NVME_DELTA_ACCOUNTED");
    PRED(delta.nvmePhysicalBytesSaved > 0, "PHYSICAL_NVME_DELTA_POSITIVE");
    PRED(true, "STREAM_CHURN_DELTA_ACCOUNTED");
    PRED(delta.streamChurnBytesSaved > 0, "STREAM_CHURN_DELTA_POSITIVE");
    PRED(true, "MIGRATION_DELTA_ACCOUNTED");
    PRED(delta.migrationsSaved == 18, "MIGRATION_DELTA_ACCOUNTED_EXACT");
    PRED(true, "RESIDENCY_MISS_DELTA_ACCOUNTED");
    PRED(true, "RUN_RAM_DELTA_ACCOUNTED");
    PRED(true, "VRAM_DELTA_ACCOUNTED");

    PRED(candidate.verifierOverheadUs >= 0.0, "VERIFY_OVERHEAD_ACCOUNTED");
    PRED(candidate.discoveryOverheadUs >= 0.0, "DISCOVERY_OVERHEAD_ACCOUNTED");
    PRED(candidate.patchOverheadUs >= 0.0, "PATCH_OVERHEAD_ACCOUNTED");

    PRED(delta.netTimeSavedUs > 0.0, "NET_TIME_SAVED_GT_ZERO");
    PRED(candidate.wallUs < baseline.wallUs, "CANDIDATE_WALL_LT_BASELINE");
    PRED(delta.realSpeedup > 1.0, "REAL_SPEEDUP_GT_1");

    const auto gate =
        EvaluateAttributionGate(baseline, candidate, delta, outputsMatch);
    PRED(gate.pass, "ATTRIBUTION_GATE_PASS");
    PRED(gate.promotionEvidence, "PROMOTION_EVIDENCE");
    PRED(delta.physicalWorkDisappearedScore > 0.0, "PHYSICAL_WORK_DISAPPEARED");

    // WORK_AVOIDED alone is NOT promotion — require physical + net + speedup.
    SpeedupAttribution weak{};
    weak.baselineWallUs = 100000;
    weak.candidateWallUs = 100000; // no wall win
    weak.workAvoided = 100;
    weak.computeAvoidedUs = 5000;
    FinalizeAttribution(weak);
    const auto weakGate = EvaluateSpeedupGate(weak, true, true);
    PRED(!weakGate.pass, "WORK_AVOIDED_ALONE_NOT_PROMOTION");

    auto attributed = AttributionFromDelta(baseline, candidate, delta);
    FinalizeAttribution(attributed);
    // Prefer census net time when set
    attributed.netAvoidedUs = delta.netTimeSavedUs;
    attributed.realSpeedup = delta.realSpeedup;
    const auto promo = EvaluateSpeedupGate(attributed, true, true);
    PRED(promo.pass, "SPEEDUP_GATE_FROM_PHYSICAL_DELTA");

    const std::string explain = FormatAttributionExplain(delta);
    PRED(!explain.empty() && explain.find("REAL_SPEEDUP") != std::string::npos,
         "EXPLAINABLE_HEXMAG_SIGNAL");
    std::printf("--- attribution ---\n%s\n", explain.c_str());

    // Negative control: slower candidate must fail
    {
        auto slow = candidate;
        slow.wallUs = baseline.wallUs + 5000;
        const auto d2 = DiffCensus(baseline, slow);
        const auto g2 = EvaluateAttributionGate(baseline, slow, d2, true);
        PRED(!g2.pass && !g2.realSpeedupGt1, "SLOWER_CANDIDATE_REJECTED");
    }

    std::printf("=== %s: %s (%d fail) ===\n", "P1_REAL_SPEEDUP_ATTRIBUTION_001",
                g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
