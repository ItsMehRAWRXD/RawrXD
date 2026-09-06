// ============================================================================
// LiveTimeDisappearance.hpp — TIME is the live resource; speedup is derived
// Updates continuously: mustDisappear → disappeared → remaining → progress
// ============================================================================
#pragma once

#include "LatencyIntent.hpp"
#include "RealtimeKernel.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

namespace Deep2 {
namespace Exec {

enum class WorkClass : uint8_t {
    Ffn = 0,
    Attention,
    Nvme,
    Migration,
    MemStall,
    Verify,
    Patch,
    Sync,
    Other,
    Count
};

inline const char* WorkClassName(WorkClass c) {
    switch (c) {
    case WorkClass::Ffn: return "FFN";
    case WorkClass::Attention: return "Attention";
    case WorkClass::Nvme: return "NVMe";
    case WorkClass::Migration: return "Migration";
    case WorkClass::MemStall: return "MemStall";
    case WorkClass::Verify: return "Verify";
    case WorkClass::Patch: return "Patch";
    case WorkClass::Sync: return "Sync";
    case WorkClass::Other: return "Other";
    default: return "?";
    }
}

struct LiveTimeDisappearance {
    double baselineWallMs = 0.0;
    double targetWallMs = 0.0;

    double mustDisappearMs = 0.0;
    double grossDisappearedMs = 0.0;
    double addedOverheadMs = 0.0;
    double netDisappearedMs = 0.0;
    double remainingMs = 0.0;

    double currentWallMs = 0.0;
    double currentTps = 0.0;
    double currentSpeedup = 1.0;
    double targetTps = 0.0;
    double targetSpeedup = 1.0;
    double progress = 0.0; // 0..1

    double baselineByClass[(size_t)WorkClass::Count]{};
    double currentByClass[(size_t)WorkClass::Count]{};
    double disappearedByClass[(size_t)WorkClass::Count]{};

    uint64_t stateGeneration = 0;
    uint64_t tokenIndex = 0;
};

struct PatchContribution {
    uint64_t patchId = 0;
    double predictedSavingMs = 0.0;
    double observedSavingMs = 0.0;
    double verifierCostMs = 0.0;
    double netDisappearanceMs = 0.0;
    double contributionPct = 0.0; // of mustDisappear
    bool active = false;
    std::string note;
};

inline void SeedLiveBudget(LiveTimeDisappearance& live, double baselineMs,
                           double targetMs) {
    std::memset(live.baselineByClass, 0, sizeof(live.baselineByClass));
    std::memset(live.currentByClass, 0, sizeof(live.currentByClass));
    std::memset(live.disappearedByClass, 0, sizeof(live.disappearedByClass));
    live.baselineWallMs = baselineMs;
    live.targetWallMs = targetMs;
    live.mustDisappearMs = (std::max)(0.0, baselineMs - targetMs);
    live.grossDisappearedMs = 0.0;
    live.addedOverheadMs = 0.0;
    live.netDisappearedMs = 0.0;
    live.remainingMs = live.mustDisappearMs;
    live.currentWallMs = baselineMs;
    live.currentTps = TpsFromMsPerToken(baselineMs);
    live.currentSpeedup = 1.0;
    live.targetTps = TpsFromMsPerToken(targetMs);
    live.targetSpeedup = RequiredSpeedupFromLatency(baselineMs, targetMs);
    live.progress = 0.0;
}

inline void SeedClassBaselines(LiveTimeDisappearance& live,
                               const LatencyBudgetSlice& slice) {
    live.baselineByClass[(size_t)WorkClass::Ffn] = slice.ffnMs;
    live.baselineByClass[(size_t)WorkClass::Attention] = slice.attentionMs;
    live.baselineByClass[(size_t)WorkClass::Nvme] = slice.nvmeMs;
    live.baselineByClass[(size_t)WorkClass::Migration] = slice.migrationMs;
    live.baselineByClass[(size_t)WorkClass::MemStall] = slice.memoryStallMs;
    live.baselineByClass[(size_t)WorkClass::Sync] = slice.syncMs;
    live.baselineByClass[(size_t)WorkClass::Other] = slice.otherMs;
    live.baselineByClass[(size_t)WorkClass::Verify] = 0.0;
    live.baselineByClass[(size_t)WorkClass::Patch] = 0.0;
    for (size_t i = 0; i < (size_t)WorkClass::Count; ++i)
        live.currentByClass[i] = live.baselineByClass[i];
}

// Telemetry tick — TIME debt update (not post-run speedup theater).
inline void UpdateLiveDisappearance(LiveTimeDisappearance& live,
                                    double currentEquivalentMs,
                                    double verifyCostMs, double patchCostMs) {
    const double required = live.mustDisappearMs;
    const double observedGross =
        (std::max)(0.0, live.baselineWallMs - currentEquivalentMs);
    live.grossDisappearedMs = observedGross;
    live.addedOverheadMs = (std::max)(0.0, verifyCostMs + patchCostMs);
    live.netDisappearedMs =
        (std::max)(0.0, live.grossDisappearedMs - live.addedOverheadMs);
    live.remainingMs =
        (std::max)(0.0, required - live.netDisappearedMs);
    live.progress =
        (required > 0.0)
            ? (std::min)(1.0, live.netDisappearedMs / required)
            : 1.0;
    live.currentWallMs = currentEquivalentMs;
    live.currentTps = TpsFromMsPerToken(currentEquivalentMs);
    live.currentSpeedup =
        (currentEquivalentMs > 0.0)
            ? (live.baselineWallMs / currentEquivalentMs)
            : 0.0;
    live.currentByClass[(size_t)WorkClass::Verify] = verifyCostMs;
    live.currentByClass[(size_t)WorkClass::Patch] = patchCostMs;
}

inline void SetCurrentClassMs(LiveTimeDisappearance& live, WorkClass c,
                              double ms) {
    const size_t i = (size_t)c;
    if (i >= (size_t)WorkClass::Count) return;
    live.currentByClass[i] = ms;
    live.disappearedByClass[i] = live.baselineByClass[i] - ms;
}

inline PatchContribution MeasurePatchContribution(
    const LiveTimeDisappearance& live, uint64_t patchId, double predictedMs,
    double observedMs, double verifierMs, const char* note) {
    PatchContribution p;
    p.patchId = patchId;
    p.predictedSavingMs = predictedMs;
    p.observedSavingMs = observedMs;
    p.verifierCostMs = verifierMs;
    p.netDisappearanceMs = observedMs - verifierMs;
    p.contributionPct =
        (live.mustDisappearMs > 0.0)
            ? (100.0 * p.netDisappearanceMs / live.mustDisappearMs)
            : 0.0;
    p.active = true;
    p.note = note ? note : "";
    return p;
}

// Sync live view into replaceable realtime state image (data only).
inline void WriteTelemetryIntoState(RealtimeState& state,
                                    const LiveTimeDisappearance& live) {
    state.telemetry.currentDecodeMs = live.currentWallMs;
    state.telemetry.currentTps = live.currentTps;
    state.telemetry.currentSpeedup = live.currentSpeedup;
    state.telemetry.disappearedMs = live.netDisappearedMs;
    state.telemetry.remainingMs = live.remainingMs;
    state.telemetry.progress = live.progress;
    state.telemetry.tokenIndex = live.tokenIndex;
    state.timing.baselineDecodeMs = live.baselineWallMs;
    state.timing.targetDecodeMs = live.targetWallMs;
    state.timing.mustDisappearMs = live.mustDisappearMs;
    state.timing.targetRealSpeedup = live.targetSpeedup;
}

inline std::string FormatTimeDisappearanceBanner(
    const LiveTimeDisappearance& live) {
    char buf[768];
    std::snprintf(
        buf, sizeof(buf),
        "HEXMAG TIME DISAPPEARANCE  gen=%llu token=%llu\n"
        "Baseline %.1f ms/token | Current %.1f | Target %.1f\n"
        "Disappeared %.1f / %.1f ms (%.1f%%)  remaining %.1f\n"
        "Speedup %.2fx / target %.2fx | TPS %.2f -> %.2f\n",
        (unsigned long long)live.stateGeneration,
        (unsigned long long)live.tokenIndex, live.baselineWallMs,
        live.currentWallMs, live.targetWallMs, live.netDisappearedMs,
        live.mustDisappearMs, live.progress * 100.0, live.remainingMs,
        live.currentSpeedup, live.targetSpeedup, live.currentTps,
        live.targetTps);
    return buf;
}

inline std::string FormatTimeDisappearanceTable(
    const LiveTimeDisappearance& live) {
    std::string out = "             BASE    NOW      D\n";
    char line[128];
    double netBase = 0.0, netNow = 0.0, netD = 0.0;
    for (size_t i = 0; i < (size_t)WorkClass::Count; ++i) {
        const double b = live.baselineByClass[i];
        const double n = live.currentByClass[i];
        double d = live.disappearedByClass[i];
        // Verify/Patch are costs added (positive = time appeared).
        if (i == (size_t)WorkClass::Verify || i == (size_t)WorkClass::Patch)
            d = b - n; // typically negative when overhead grows
        if (b == 0.0 && n == 0.0 && d == 0.0 &&
            i != (size_t)WorkClass::Verify && i != (size_t)WorkClass::Patch)
            continue;
        std::snprintf(line, sizeof(line), "%-12s %6.1f %6.1f %7.1f ms\n",
                      WorkClassName((WorkClass)i), b, n, -d);
        out += line;
        netBase += b;
        netNow += n;
        netD += d;
    }
    std::snprintf(line, sizeof(line),
                  "NET          %6.1f %6.1f %7.1f ms\n", netBase, netNow,
                  -netD);
    out += line;
    return out;
}

// Provenance-aware time map: which generation / ruleset caused the delta.
inline std::string FormatTimeDisappearanceWithProvenance(
    const LiveTimeDisappearance& live, const TokenProvenance& baseline,
    const TokenProvenance& candidate, bool promotionPass) {
    char head[512];
    std::snprintf(
        head, sizeof(head),
        "GENERATION          %llu -> %llu\n"
        "RULESET_SHA         %016llx -> %016llx\n"
        "PROOF_SET_SHA       %016llx -> %016llx\n"
        "IMAGE_SHA           %016llx -> %016llx\n"
        "\n",
        (unsigned long long)baseline.stateGeneration,
        (unsigned long long)candidate.stateGeneration,
        (unsigned long long)baseline.rulesetSha,
        (unsigned long long)candidate.rulesetSha,
        (unsigned long long)baseline.proofSetSha,
        (unsigned long long)candidate.proofSetSha,
        (unsigned long long)baseline.stateImageSha,
        (unsigned long long)candidate.stateImageSha);
    char foot[192];
    std::snprintf(foot, sizeof(foot),
                  "\nREAL_SPEEDUP        %.3fx\nPROMOTION           %s\n",
                  live.currentSpeedup, promotionPass ? "PASS" : "HOLD/FAIL");
    return std::string(head) + FormatTimeDisappearanceBanner(live) +
           FormatTimeDisappearanceTable(live) + foot;
}

} // namespace Exec
} // namespace Deep2
