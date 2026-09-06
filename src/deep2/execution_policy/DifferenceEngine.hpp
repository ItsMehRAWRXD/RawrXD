// ============================================================================
// DifferenceEngine.hpp — ≠ as discoverable optimization space (not boolean fail)
//
//   DESIRED ≠ OBSERVED → Δ → attribute → transform → hotpatch → remeasure
//
// Core Unstatic / Reverse Auto Expert primitive underneath latency, VRAM,
// placement, work, and I/O solvers.
// ============================================================================
#pragma once

#include "HotpatchSynthesizer.hpp"
#include "SpeedupAttribution.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

// Generic measured gap. delta = observed - expected for "surplus" metrics,
// or expected - observed for "deficit vs target" — see GapSense.
template <typename T>
struct Difference {
    T expected{};
    T observed{};
    T delta{};
    bool resolved = false;
};

enum class GapSense : uint8_t {
    // actual > target is the problem (latency, wall, IO churn)
    ExcessActual = 0,
    // actual < target is the problem (speedup, TPS, headroom)
    DeficitActual,
    // |actual - target| either direction (placement mismatch count)
    Absolute
};

enum class GapClass : uint8_t {
    Work = 0,       // MODEL_SIZE ≠ WORK_REQUIRED / presented ≠ required
    Latency,        // BASELINE ≠ TARGET latency
    Speedup,        // CURRENT ≠ TARGET speedup
    Placement,      // PLANNED ≠ OBSERVED
    Vram,           // AVAILABLE ≠ REQUIRED
    Io,             // EXPECTED ≠ PHYSICAL
    Custom
};

enum class GapCauseKind : uint8_t {
    Unknown = 0,
    RedundantCompute,
    MissingReuse,
    UnverifiedSkipCandidate,
    MemoryStall,
    MigrationChurn,
    NvmeChurn,
    QuantTooHeavy,
    PlacementMismatch,
    SyncOverhead,
    VerifierTax,
    UserLocked // never auto-correct
};

struct GapAttribution {
    GapCauseKind kind = GapCauseKind::Unknown;
    double fractionOfDelta = 1.0; // 0..1 share of gap this cause explains
    std::string note;
};

// First-class solver unit: quantify ≠, explain, propose correction.
struct ExecutionGap {
    GapClass type = GapClass::Custom;
    GapSense sense = GapSense::ExcessActual;

    double target = 0.0;
    double actual = 0.0;
    double delta = 0.0; // signed: positive ⇒ still need improvement under sense

    bool stable = false;   // |delta| ≤ epsilon
    bool resolved = false; // correction applied + remeasure closed gap
    bool userLocked = false;

    std::vector<GapAttribution> causes;
    HotpatchPlan correction; // may be empty until SynthesizeFromGap

    std::string detail;
};

struct DifferenceCycleResult {
    ExecutionGap gap;
    bool compared = false;
    bool quantified = false;
    bool explained = false;
    bool synthesized = false;
    bool verified = false;
    bool applied = false;
    bool improved = false;
    std::string firstStop; // where loop halted
};

inline const char* GapClassName(GapClass c) {
    switch (c) {
    case GapClass::Work: return "WORK";
    case GapClass::Latency: return "LATENCY";
    case GapClass::Speedup: return "SPEEDUP";
    case GapClass::Placement: return "PLACEMENT";
    case GapClass::Vram: return "VRAM";
    case GapClass::Io: return "IO";
    default: return "CUSTOM";
    }
}

inline const char* GapCauseName(GapCauseKind k) {
    switch (k) {
    case GapCauseKind::RedundantCompute: return "REDUNDANT_COMPUTE";
    case GapCauseKind::MissingReuse: return "MISSING_REUSE";
    case GapCauseKind::UnverifiedSkipCandidate: return "UNVERIFIED_SKIP";
    case GapCauseKind::MemoryStall: return "MEMORY_STALL";
    case GapCauseKind::MigrationChurn: return "MIGRATION_CHURN";
    case GapCauseKind::NvmeChurn: return "NVME_CHURN";
    case GapCauseKind::QuantTooHeavy: return "QUANT_TOO_HEAVY";
    case GapCauseKind::PlacementMismatch: return "PLACEMENT_MISMATCH";
    case GapCauseKind::SyncOverhead: return "SYNC_OVERHEAD";
    case GapCauseKind::VerifierTax: return "VERIFIER_TAX";
    case GapCauseKind::UserLocked: return "USER_LOCKED";
    default: return "UNKNOWN";
    }
}

// Quantify: turn boolean ≠ into signed improvement remaining.
inline double QuantifyDelta(double target, double actual, GapSense sense) {
    switch (sense) {
    case GapSense::DeficitActual:
        return target - actual; // need actual to rise
    case GapSense::Absolute:
        return std::fabs(actual - target);
    case GapSense::ExcessActual:
    default:
        return actual - target; // need actual to fall
    }
}

inline ExecutionGap MakeGap(GapClass type, double target, double actual,
                            GapSense sense, double epsilon = 1e-9) {
    ExecutionGap g;
    g.type = type;
    g.sense = sense;
    g.target = target;
    g.actual = actual;
    g.delta = QuantifyDelta(target, actual, sense);
    g.stable = (std::fabs(g.delta) <= epsilon) || (g.delta <= 0.0 &&
                sense != GapSense::Absolute);
    if (sense == GapSense::Absolute)
        g.stable = (g.delta <= epsilon);
    // For Excess/Deficit: delta<=0 means target met or exceeded → stable.
    if (sense != GapSense::Absolute && g.delta <= 0.0)
        g.stable = true;
    g.resolved = g.stable;
    g.detail = std::string(GapClassName(type)) + " target=" +
               std::to_string(target) + " actual=" + std::to_string(actual) +
               " delta=" + std::to_string(g.delta);
    return g;
}

// --- Domain constructors (≠ → ExecutionGap) ---------------------------------

// ΔWORK = presented − required  (opportunity = removable regions)
inline ExecutionGap WorkOpportunityGap(uint64_t presented, uint64_t required,
                                       double usPerRegion = 0.0) {
    const double rem = (presented > required)
                           ? static_cast<double>(presented - required)
                           : 0.0;
    // target required, actual presented → excess work is the gap to close
    ExecutionGap g =
        MakeGap(GapClass::Work, static_cast<double>(required),
                static_cast<double>(presented), GapSense::ExcessActual);
    g.delta = rem; // force opportunity units = removable regions
    g.stable = (rem <= 0.0);
    g.resolved = g.stable;
    if (rem > 0.0) {
        GapAttribution a;
        a.kind = GapCauseKind::RedundantCompute;
        a.fractionOfDelta = 1.0;
        a.note = "ΔWORK regions; us≈" +
                 std::to_string(rem * usPerRegion);
        g.causes.push_back(a);
    }
    g.detail = "ΔWORK=" + std::to_string((long long)rem) + " regions";
    return g;
}

inline ExecutionGap LatencyGap(double targetMs, double actualMs) {
    return MakeGap(GapClass::Latency, targetMs, actualMs, GapSense::ExcessActual);
}

inline ExecutionGap SpeedupGap(double targetSpeedup, double actualSpeedup) {
    return MakeGap(GapClass::Speedup, targetSpeedup, actualSpeedup,
                   GapSense::DeficitActual);
}

inline ExecutionGap PlacementGap(size_t plannedMatches, size_t observedMatches,
                                 size_t total) {
    const double target = static_cast<double>(total);
    const double actual = static_cast<double>(observedMatches);
    ExecutionGap g =
        MakeGap(GapClass::Placement, target, actual, GapSense::DeficitActual);
    if (!g.stable) {
        GapAttribution a;
        a.kind = GapCauseKind::PlacementMismatch;
        a.fractionOfDelta = 1.0;
        a.note = "planned_ok=" + std::to_string(plannedMatches);
        g.causes.push_back(a);
    }
    return g;
}

inline ExecutionGap VramGap(uint64_t availableBytes, uint64_t requiredBytes) {
    // Deficit of available vs required → need quant/split/stream
    ExecutionGap g =
        MakeGap(GapClass::Vram, static_cast<double>(requiredBytes),
                static_cast<double>(availableBytes), GapSense::DeficitActual);
    if (!g.stable) {
        GapAttribution a;
        a.kind = GapCauseKind::QuantTooHeavy;
        a.fractionOfDelta = 1.0;
        g.causes.push_back(a);
    }
    return g;
}

inline ExecutionGap IoGap(uint64_t expectedPhysical, uint64_t observedPhysical) {
    return MakeGap(GapClass::Io, static_cast<double>(expectedPhysical),
                   static_cast<double>(observedPhysical),
                   GapSense::ExcessActual);
}

// Attribute a latency-shaped gap from a coarse time slice (ms).
inline void ExplainLatencySlice(ExecutionGap& g, double ffnMs, double attnMs,
                                double memMs, double nvmeMs, double migMs,
                                double otherMs) {
    g.causes.clear();
    const double sum =
        ffnMs + attnMs + memMs + nvmeMs + migMs + otherMs;
    if (sum <= 0.0 || g.delta <= 0.0)
        return;
    auto add = [&](GapCauseKind k, double ms) {
        if (ms <= 0.0)
            return;
        GapAttribution a;
        a.kind = k;
        a.fractionOfDelta = ms / sum;
        a.note = std::to_string(ms) + "ms";
        g.causes.push_back(a);
    };
    add(GapCauseKind::RedundantCompute, ffnMs + attnMs);
    add(GapCauseKind::MemoryStall, memMs);
    add(GapCauseKind::NvmeChurn, nvmeMs);
    add(GapCauseKind::MigrationChurn, migMs);
    add(GapCauseKind::Unknown, otherMs);
}

// Map dominant cause → PatchKind hint (fail-closed on UserLocked / Unknown).
inline PatchKind PatchKindFromCause(GapCauseKind k) {
    switch (k) {
    case GapCauseKind::MissingReuse: return PatchKind::Reuse;
    case GapCauseKind::UnverifiedSkipCandidate: return PatchKind::Skip;
    case GapCauseKind::RedundantCompute: return PatchKind::Skip;
    case GapCauseKind::MemoryStall: return PatchKind::Residency;
    case GapCauseKind::MigrationChurn: return PatchKind::Residency;
    case GapCauseKind::NvmeChurn: return PatchKind::Prefetch;
    case GapCauseKind::QuantTooHeavy: return PatchKind::Quant;
    case GapCauseKind::PlacementMismatch: return PatchKind::Residency;
    case GapCauseKind::SyncOverhead: return PatchKind::Fuse;
    default: return PatchKind::Reuse;
    }
}

inline GapCauseKind DominantCause(const ExecutionGap& g) {
    GapCauseKind best = GapCauseKind::Unknown;
    double bestF = -1.0;
    for (const auto& c : g.causes) {
        if (c.kind == GapCauseKind::UserLocked)
            return GapCauseKind::UserLocked;
        if (c.fractionOfDelta > bestF) {
            bestF = c.fractionOfDelta;
            best = c.kind;
        }
    }
    return best;
}

// Synthesize a minimal HotpatchPlan skeleton from a gap (no install).
inline HotpatchPlan SynthesizeFromGap(const ExecutionGap& g,
                                      double baselineWallUs) {
    HotpatchPlan plan;
    plan.requiredSavingsUs =
        (g.sense == GapSense::ExcessActual && g.delta > 0.0)
            ? g.delta * 1000.0 // if delta was ms
            : (g.sense == GapSense::DeficitActual && g.delta > 0.0 &&
                       g.actual > 0.0
                   ? (baselineWallUs - baselineWallUs / (g.target > 0.0
                                                              ? g.target
                                                              : 1.0))
                   : 0.0);
    if (g.type == GapClass::Latency && g.delta > 0.0)
        plan.requiredSavingsUs = g.delta * 1000.0; // ms → µs

    const GapCauseKind dom = DominantCause(g);
    if (dom == GapCauseKind::UserLocked || g.userLocked) {
        plan.reachable = false;
        plan.report = "USER_LOCKED";
        return plan;
    }
    if (g.stable) {
        plan.reachable = true;
        plan.targetMetByPrediction = true;
        plan.report = "STABLE";
        return plan;
    }
    if (dom == GapCauseKind::Unknown && g.causes.empty()) {
        plan.reachable = false;
        plan.report = "UNKNOWN_CAUSE_FAIL_CLOSED";
        return plan;
    }

    HotpatchCandidate c;
    c.id = 1;
    c.kind = PatchKindFromCause(dom);
    c.predictedSavedUs = plan.requiredSavingsUs * 0.5; // conservative half
    c.predictedSavedMs = c.predictedSavedUs / 1000.0;
    c.predictedSpeedup =
        baselineWallUs > 0.0
            ? baselineWallUs / (baselineWallUs - c.predictedSavedUs)
            : 1.0;
    c.note = GapCauseName(dom);
    plan.selected.push_back(c);
    plan.predictedGrossSavedUs = c.predictedSavedUs;
    plan.predictedVerifierOverheadUs = c.predictedSavedUs * 0.1;
    plan.predictedNetSavedUs =
        plan.predictedGrossSavedUs - plan.predictedVerifierOverheadUs;
    plan.predictedSpeedup =
        baselineWallUs > plan.predictedNetSavedUs && baselineWallUs > 0.0
            ? baselineWallUs / (baselineWallUs - plan.predictedNetSavedUs)
            : 1.0;
    plan.reachable = plan.predictedNetSavedUs > 0.0;
    plan.targetMetByPrediction =
        plan.predictedNetSavedUs >= plan.requiredSavingsUs &&
        plan.requiredSavingsUs > 0.0;
    plan.report = g.detail;
    return plan;
}

// One HexMag difference cycle step (compare → …). Does not apply patches.
inline DifferenceCycleResult DifferenceCycle(ExecutionGap gap,
                                             double baselineWallUs) {
    DifferenceCycleResult r;
    r.gap = gap;
    r.compared = true;
    if (gap.stable) {
        r.quantified = true;
        r.firstStop = "STABLE";
        return r;
    }
    r.quantified = true;
    if (gap.userLocked || DominantCause(gap) == GapCauseKind::UserLocked) {
        r.firstStop = "USER_LOCKED";
        return r;
    }
    r.explained = !gap.causes.empty();
    if (!r.explained) {
        r.firstStop = "NEED_ATTRIBUTION";
        return r;
    }
    r.gap.correction = SynthesizeFromGap(gap, baselineWallUs);
    r.synthesized = !r.gap.correction.selected.empty();
    if (!r.synthesized) {
        r.firstStop = r.gap.correction.report.empty()
                          ? "NO_CANDIDATE"
                          : r.gap.correction.report;
        return r;
    }
    // Verify/apply left to HotpatchSynthesizer + EvolutionState (fail-closed).
    r.firstStop = "AWAIT_VERIFY_APPLY";
    return r;
}

// Remeasure: fold new actual into gap; Δ drives toward 0.
inline ExecutionGap Remeasure(ExecutionGap g, double newActual,
                              double epsilon = 1e-9) {
    g.actual = newActual;
    g.delta = QuantifyDelta(g.target, g.actual, g.sense);
    if (g.sense == GapSense::Absolute)
        g.stable = (g.delta <= epsilon);
    else
        g.stable = (g.delta <= 0.0);
    g.resolved = g.stable;
    g.detail = std::string(GapClassName(g.type)) + " remeasure delta=" +
               std::to_string(g.delta);
    return g;
}

} // namespace Exec
} // namespace Deep2
