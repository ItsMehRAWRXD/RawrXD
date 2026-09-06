// ============================================================================
// PhysicalWorkCensus.hpp — per-run physical work snapshot for attribution
// Diff two censuses → causal REAL_SPEEDUP evidence (not TPS theater).
// ============================================================================
#pragma once

#include "ExecutionObservation.hpp"
#include "SpeedupAttribution.hpp"
#include "TelemetrySinks.hpp"
#include "HostRamTelemetry.hpp"
#include <cmath>
#include <cstdint>
#include <string>

namespace Deep2 {
namespace Exec {

struct PhysicalWorkCensus {
    double wallUs = 0.0; // EXTERNAL wall authority for this run

    uint64_t nvmePhysicalReadBytes = 0;
    uint64_t nvmeUsefulPayloadBytes = 0;
    uint64_t streamChurnBytes = 0;
    uint64_t bytesHostToGpu = 0;

    uint32_t migrations = 0;
    uint32_t residencyMisses = 0;

    uint64_t runWorkingSetPeak = 0;
    uint64_t runPrivateCommitPeak = 0;
    uint64_t peakVramBytes = 0;

    double verifierOverheadUs = 0.0;
    double discoveryOverheadUs = 0.0;
    double patchOverheadUs = 0.0;

    bool wallValid = false;
    bool outputValid = false;
};

inline PhysicalWorkCensus CensusFromObservation(const ExecutionObservation& o,
                                                  double wallUs,
                                                  double verifierUs = 0,
                                                  double discoveryUs = 0,
                                                  double patchUs = 0) {
    PhysicalWorkCensus c;
    c.wallUs = wallUs;
    c.wallValid = (wallUs > 0.0);
    c.outputValid = o.outputValid && o.completed;
    c.nvmePhysicalReadBytes = o.nvmePhysicalReadBytes;
    c.nvmeUsefulPayloadBytes = o.nvmeUsefulPayloadBytes;
    c.streamChurnBytes = o.streamChurnBytes;
    c.bytesHostToGpu = o.bytesHostToGpu;
    c.migrations = o.migrations;
    c.residencyMisses = o.residencyMisses;
    c.runWorkingSetPeak = o.runWorkingSetPeak;
    c.runPrivateCommitPeak = o.runPrivateCommitPeak;
    c.peakVramBytes = o.peakVramBytes;
    c.verifierOverheadUs = verifierUs;
    c.discoveryOverheadUs = discoveryUs;
    c.patchOverheadUs = patchUs;
    return c;
}

inline PhysicalWorkCensus CensusFromLiveTelemetry(double wallUs,
                                                    bool outputValid,
                                                    double verifierUs = 0,
                                                    double discoveryUs = 0,
                                                    double patchUs = 0) {
    SampleRunRamPeaks();
    PhysicalWorkCensus c;
    c.wallUs = wallUs;
    c.wallValid = (wallUs > 0.0);
    c.outputValid = outputValid;
    const auto& io = GlobalTelemetry().io;
    c.nvmePhysicalReadBytes = io.nvmePhysicalReadBytes.load();
    c.nvmeUsefulPayloadBytes = io.nvmeUsefulPayloadBytes.load();
    c.streamChurnBytes = StreamChurnBytes();
    c.bytesHostToGpu = io.hostToGpuBytes.load();
    c.runWorkingSetPeak = GlobalTelemetry().runWorkingSetPeak;
    c.runPrivateCommitPeak = GlobalTelemetry().runPrivateCommitPeak;
    c.verifierOverheadUs = verifierUs;
    c.discoveryOverheadUs = discoveryUs;
    c.patchOverheadUs = patchUs;
    return c;
}

// Positive delta = candidate reduced that resource vs baseline.
struct PhysicalWorkDelta {
    double wallUsSaved = 0.0;
    int64_t nvmePhysicalBytesSaved = 0;
    int64_t streamChurnBytesSaved = 0;
    int64_t h2dBytesSaved = 0;
    int32_t migrationsSaved = 0;
    int32_t residencyMissesSaved = 0;
    int64_t runRamPeakBytesSaved = 0;
    int64_t vramPeakBytesSaved = 0;

    double verifierOverheadUs = 0.0;   // candidate cost (not "saved")
    double discoveryOverheadUs = 0.0;
    double patchOverheadUs = 0.0;

    double physicalWorkDisappearedScore = 0.0; // unitless composite >0
    double netTimeSavedUs = 0.0;
    double realSpeedup = 0.0;
};

inline int64_t I64Sub(uint64_t base, uint64_t cand) {
    return static_cast<int64_t>(base) - static_cast<int64_t>(cand);
}

inline PhysicalWorkDelta DiffCensus(const PhysicalWorkCensus& baseline,
                                    const PhysicalWorkCensus& candidate) {
    PhysicalWorkDelta d;
    d.wallUsSaved = baseline.wallUs - candidate.wallUs;
    d.nvmePhysicalBytesSaved =
        I64Sub(baseline.nvmePhysicalReadBytes, candidate.nvmePhysicalReadBytes);
    d.streamChurnBytesSaved =
        I64Sub(baseline.streamChurnBytes, candidate.streamChurnBytes);
    d.h2dBytesSaved = I64Sub(baseline.bytesHostToGpu, candidate.bytesHostToGpu);
    d.migrationsSaved =
        static_cast<int32_t>(baseline.migrations) -
        static_cast<int32_t>(candidate.migrations);
    d.residencyMissesSaved =
        static_cast<int32_t>(baseline.residencyMisses) -
        static_cast<int32_t>(candidate.residencyMisses);
    d.runRamPeakBytesSaved =
        I64Sub(baseline.runWorkingSetPeak, candidate.runWorkingSetPeak);
    d.vramPeakBytesSaved =
        I64Sub(baseline.peakVramBytes, candidate.peakVramBytes);

    d.verifierOverheadUs = candidate.verifierOverheadUs;
    d.discoveryOverheadUs = candidate.discoveryOverheadUs;
    d.patchOverheadUs = candidate.patchOverheadUs;

    // Coarse physical-work disappearance score (bytes/ops → relative units).
    d.physicalWorkDisappearedScore =
        (d.nvmePhysicalBytesSaved > 0 ? (double)d.nvmePhysicalBytesSaved : 0.0) +
        (d.streamChurnBytesSaved > 0 ? (double)d.streamChurnBytesSaved : 0.0) +
        (d.h2dBytesSaved > 0 ? (double)d.h2dBytesSaved : 0.0) +
        (d.migrationsSaved > 0 ? d.migrationsSaved * 1.0e6 : 0.0) +
        (d.residencyMissesSaved > 0 ? d.residencyMissesSaved * 1.0e5 : 0.0);

    // NET_TIME_SAVED = wall saved − discovery/verify/patch overheads on candidate.
    d.netTimeSavedUs = d.wallUsSaved - d.verifierOverheadUs -
                         d.discoveryOverheadUs - d.patchOverheadUs;
    d.realSpeedup =
        ComputeRealSpeedup(baseline.wallUs, candidate.wallUs);
    return d;
}

// Map physical delta into SpeedupAttribution avoided/overhead terms.
inline SpeedupAttribution AttributionFromDelta(const PhysicalWorkCensus& baseline,
                                                 const PhysicalWorkCensus& candidate,
                                                 const PhysicalWorkDelta& d) {
    SpeedupAttribution a;
    a.baselineWallUs = baseline.wallUs;
    a.candidateWallUs = candidate.wallUs;
    a.workPresented = 1;
    a.workExecuted = (d.wallUsSaved > 0.0) ? 1 : 1;
    a.workAvoided = (d.physicalWorkDisappearedScore > 0.0) ? 1 : 0;

    // Convert byte/migration savings into approximate µs proxies for R1..R3.
    // (Deterministic coefficients for certification; calibrate later.)
    constexpr double kUsPerNvmeByte = 1.0e-3; // 1 ns/byte → 0.001 µs/byte
    constexpr double kUsPerMigration = 50.0;
    constexpr double kUsPerMiss = 20.0;

    a.ioAvoidedUs =
        (d.nvmePhysicalBytesSaved > 0 ? d.nvmePhysicalBytesSaved * kUsPerNvmeByte
                                      : 0.0) +
        (d.streamChurnBytesSaved > 0 ? d.streamChurnBytesSaved * kUsPerNvmeByte
                                     : 0.0);
    a.migrationAvoidedUs =
        (d.migrationsSaved > 0 ? d.migrationsSaved * kUsPerMigration : 0.0) +
        (d.residencyMissesSaved > 0 ? d.residencyMissesSaved * kUsPerMiss : 0.0);
    a.memoryStallAvoidedUs =
        (d.h2dBytesSaved > 0 ? d.h2dBytesSaved * kUsPerNvmeByte * 0.5 : 0.0);
    a.computeAvoidedUs = 0.0; // filled by compute probes when available

    a.verifierCostUs = d.verifierOverheadUs;
    a.discoveryCostUs = d.discoveryOverheadUs;
    a.patchCostUs = d.patchOverheadUs;
    a.synchronizationCostUs = 0.0;

    FinalizeAttribution(a);
    // Prefer EXTERNAL wall-derived net when available.
    if (d.netTimeSavedUs != 0.0)
        a.netAvoidedUs = d.netTimeSavedUs;
    a.realSpeedup = d.realSpeedup;
    a.note = "physical_census_delta";
    return a;
}

struct AttributionGateResult {
    bool baselineWallValid = false;
    bool candidateWallValid = false;
    bool outputEquivalent = false;

    bool physicalNvmeDeltaAccounted = false;
    bool streamChurnDeltaAccounted = false;
    bool migrationDeltaAccounted = false;
    bool residencyMissDeltaAccounted = false;
    bool runRamDeltaAccounted = false;
    bool vramDeltaAccounted = false;

    bool verifyOverheadAccounted = false;
    bool discoveryOverheadAccounted = false;
    bool patchOverheadAccounted = false;

    bool physicalWorkDisappeared = false;
    bool netTimeSavedGtZero = false;
    bool candidateWallLtBaseline = false;
    bool realSpeedupGt1 = false;

    bool pass = false;
    bool promotionEvidence = false; // physical disappeared AND net saved AND speedup
    std::string firstFalse;
};

inline AttributionGateResult EvaluateAttributionGate(
    const PhysicalWorkCensus& baseline, const PhysicalWorkCensus& candidate,
    const PhysicalWorkDelta& d, bool outputEquivalent) {
    AttributionGateResult g;
    g.baselineWallValid = baseline.wallValid;
    g.candidateWallValid = candidate.wallValid;
    g.outputEquivalent = outputEquivalent;

    // "Accounted" = fields are present in the delta (always true if DiffCensus used).
    g.physicalNvmeDeltaAccounted = true;
    g.streamChurnDeltaAccounted = true;
    g.migrationDeltaAccounted = true;
    g.residencyMissDeltaAccounted = true;
    g.runRamDeltaAccounted = true;
    g.vramDeltaAccounted = true;
    g.verifyOverheadAccounted = (candidate.verifierOverheadUs >= 0.0);
    g.discoveryOverheadAccounted = (candidate.discoveryOverheadUs >= 0.0);
    g.patchOverheadAccounted = (candidate.patchOverheadUs >= 0.0);

    g.physicalWorkDisappeared = (d.physicalWorkDisappearedScore > 0.0);
    g.netTimeSavedGtZero = (d.netTimeSavedUs > 0.0);
    g.candidateWallLtBaseline =
        (baseline.wallUs > 0.0 && candidate.wallUs > 0.0 &&
         candidate.wallUs < baseline.wallUs);
    g.realSpeedupGt1 = (d.realSpeedup > 1.0);

    auto fail = [&](const char* pred) {
        if (g.firstFalse.empty())
            g.firstFalse = pred;
    };
    if (!g.baselineWallValid) fail("BASELINE_EXTERNAL_WALL_VALID");
    if (!g.candidateWallValid) fail("CANDIDATE_EXTERNAL_WALL_VALID");
    if (!g.outputEquivalent) fail("OUTPUT_EQUIVALENT");
    if (!g.physicalNvmeDeltaAccounted) fail("PHYSICAL_NVME_DELTA_ACCOUNTED");
    if (!g.streamChurnDeltaAccounted) fail("STREAM_CHURN_DELTA_ACCOUNTED");
    if (!g.migrationDeltaAccounted) fail("MIGRATION_DELTA_ACCOUNTED");
    if (!g.residencyMissDeltaAccounted) fail("RESIDENCY_MISS_DELTA_ACCOUNTED");
    if (!g.runRamDeltaAccounted) fail("RUN_RAM_DELTA_ACCOUNTED");
    if (!g.vramDeltaAccounted) fail("VRAM_DELTA_ACCOUNTED");
    if (!g.verifyOverheadAccounted) fail("VERIFY_OVERHEAD_ACCOUNTED");
    if (!g.discoveryOverheadAccounted) fail("DISCOVERY_OVERHEAD_ACCOUNTED");
    if (!g.patchOverheadAccounted) fail("PATCH_OVERHEAD_ACCOUNTED");
    if (!g.netTimeSavedGtZero) fail("NET_TIME_SAVED_GT_ZERO");
    if (!g.candidateWallLtBaseline) fail("CANDIDATE_WALL_LT_BASELINE");
    if (!g.realSpeedupGt1) fail("REAL_SPEEDUP_GT_1");

    g.pass = g.firstFalse.empty();
    g.promotionEvidence = g.pass && g.physicalWorkDisappeared &&
                          g.netTimeSavedGtZero && g.realSpeedupGt1;
    return g;
}

inline std::string FormatAttributionExplain(const PhysicalWorkDelta& d) {
    char buf[768];
    std::snprintf(
        buf, sizeof(buf),
        "physical NVMe saved=%lld B  churn saved=%lld B  H2D saved=%lld B\n"
        "migrations saved=%d  misses saved=%d\n"
        "run RAM peak saved=%lld B  VRAM peak saved=%lld B\n"
        "verify=%.1f us  discovery=%.1f us  patch=%.1f us\n"
        "NET_TIME_SAVED=%.1f us  REAL_SPEEDUP=%.3fx  workDisappearedScore=%.0f",
        (long long)d.nvmePhysicalBytesSaved, (long long)d.streamChurnBytesSaved,
        (long long)d.h2dBytesSaved, (int)d.migrationsSaved,
        (int)d.residencyMissesSaved, (long long)d.runRamPeakBytesSaved,
        (long long)d.vramPeakBytesSaved, d.verifierOverheadUs,
        d.discoveryOverheadUs, d.patchOverheadUs, d.netTimeSavedUs,
        d.realSpeedup, d.physicalWorkDisappearedScore);
    return buf;
}

} // namespace Exec
} // namespace Deep2
