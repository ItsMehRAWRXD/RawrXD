// ============================================================================
// ReverseSpeedupSolver.hpp — speedup as policy TARGET, not only measured output
// desiredRealSpeedup → required wall → physical-work reduction budget → search
// ============================================================================
#pragma once

#include "Tunable.hpp"
#include "PhysicalWorkCensus.hpp"
#include "EvolutionState.hpp"
#include <algorithm>
#include <cmath>
#include <string>

namespace Deep2 {
namespace Exec {

struct SpeedupPolicy {
    Tunable<double> targetRealSpeedup;   // e.g. 1.25, 1.50, 2.00
    Tunable<bool> autoTarget;
    Tunable<double> minimumAcceptedGain; // e.g. 1.01 — local promote floor
    Tunable<double> maxRiskBudget;       // 0..1 confidence haircut on removable
    Tunable<double> targetTps;
    Tunable<double> targetTtftMs;
    Tunable<double> targetWallUsPerToken;
};

enum class PerformanceGoalKind : uint8_t {
    Auto = 0,
    SpeedupRatio,
    MaxSafe,
    TargetTps,
    TargetTtft,
    TargetWallPerToken
};

struct PerformanceIntent {
    PerformanceGoalKind kind = PerformanceGoalKind::Auto;
    double desiredRealSpeedup = 1.0; // resolved ratio (≥1)
    double targetWallUs = 0.0;       // absolute candidate wall goal
    double requiredNetRemovalUs = 0.0;
    bool fromUser = false;
    std::string detail;
};

struct RemovableWorkEstimate {
    double computeUs = 0.0;
    double nvmeUs = 0.0;
    double migrationUs = 0.0;
    double memoryStallUs = 0.0;
    double otherUs = 0.0;
    double confidence = 0.7; // 0..1

    double total() const {
        return computeUs + nvmeUs + migrationUs + memoryStallUs + otherUs;
    }
    double conservative(double riskBudget) const {
        const double c = (std::max)(0.0, (std::min)(1.0, confidence));
        const double haircut = (std::max)(0.0, (std::min)(1.0, 1.0 - riskBudget));
        return total() * c * haircut;
    }
};

struct WorkRemovalPlan {
    double predictedReuseUs = 0.0;
    double predictedChurnCutUs = 0.0;
    double predictedResidencyUs = 0.0;
    double predictedMigrationCutUs = 0.0;
    double predictedFuseUs = 0.0;
    double predictedVerifierOverheadUs = 0.0;

    double predictedNetSavedUs() const {
        return predictedReuseUs + predictedChurnCutUs + predictedResidencyUs +
               predictedMigrationCutUs + predictedFuseUs -
               predictedVerifierOverheadUs;
    }
};

struct ReverseSolveResult {
    PerformanceIntent intent;
    double baselineWallUs = 0.0;
    double requiredCandidateWallUs = 0.0;
    double requiredNetRemovalUs = 0.0;
    RemovableWorkEstimate opportunity;
    WorkRemovalPlan plan;
    double predictedNetSavedUs = 0.0;
    double predictedSpeedup = 0.0;
    bool targetMetByPrediction = false;
    bool reachable = false; // opportunity ceiling ≥ required
    std::string report;
};

inline SpeedupPolicy MakeDefaultSpeedupPolicy() {
    SpeedupPolicy s;
    s.targetRealSpeedup.force(1.10, SettingAuthority::AutoDetect,
                              SettingMutability::Immediate);
    s.autoTarget.force(true, SettingAuthority::AutoDetect,
                       SettingMutability::Immediate);
    s.minimumAcceptedGain.force(1.01, SettingAuthority::AutoDetect,
                                SettingMutability::Immediate);
    s.maxRiskBudget.force(0.25, SettingAuthority::AutoDetect,
                          SettingMutability::Immediate);
    return s;
}

// Evidence-derived AUTO target from removable-work ceiling.
inline double DeriveAutoTargetSpeedup(double baselineWallUs,
                                      const RemovableWorkEstimate& rem,
                                      double maxRiskBudget) {
    if (baselineWallUs <= 0.0) return 1.0;
    const double removable = rem.conservative(maxRiskBudget);
    const double candWall =
        (std::max)(baselineWallUs - removable, baselineWallUs * 0.05);
    return baselineWallUs / candWall;
}

inline RemovableWorkEstimate EstimateRemovableFromCensus(
    const PhysicalWorkCensus& b) {
    RemovableWorkEstimate e;
    // Deterministic proxies from physical counters (calibrate later).
    constexpr double kUsPerByte = 1.0e-3;
    constexpr double kUsPerMig = 50.0;
    constexpr double kUsPerMiss = 20.0;
    e.nvmeUs = (double)b.streamChurnBytes * kUsPerByte +
                (double)b.nvmePhysicalReadBytes * kUsPerByte * 0.15;
    e.migrationUs = (double)b.migrations * kUsPerMig;
    e.memoryStallUs = (double)b.bytesHostToGpu * kUsPerByte * 0.5 +
                        (double)b.residencyMisses * kUsPerMiss;
    e.computeUs = b.wallUs * 0.35; // provisional share until compute probes
    e.otherUs = b.wallUs * 0.05;
    e.confidence = 0.65;
    // Cap estimate so removable ≤ 0.85 * wall
    const double cap = b.wallUs * 0.85;
    const double t = e.total();
    if (t > cap && t > 0.0) {
        const double s = cap / t;
        e.computeUs *= s;
        e.nvmeUs *= s;
        e.migrationUs *= s;
        e.memoryStallUs *= s;
        e.otherUs *= s;
    }
    return e;
}

inline PerformanceIntent ResolveIntent(const SpeedupPolicy& pol,
                                       const PhysicalWorkCensus& baseline,
                                       const RemovableWorkEstimate& rem) {
    PerformanceIntent i;
    const double risk = pol.maxRiskBudget.present ? pol.maxRiskBudget.value : 0.25;
    const bool autoT = !pol.autoTarget.present || pol.autoTarget.value;

    if (pol.targetTps.present && pol.targetTps.value > 0.0 &&
        baseline.wallUs > 0.0) {
        // Rough: assume one token ~ wallUs for intent conversion when no TPS live.
        i.kind = PerformanceGoalKind::TargetTps;
        i.desiredRealSpeedup = (std::max)(1.0, pol.targetTps.value / 1.0);
        i.fromUser = (pol.targetTps.authority >= SettingAuthority::UserOverride);
        i.detail = "from targetTps";
    } else if (pol.targetTtftMs.present && pol.targetTtftMs.value > 0.0 &&
               baseline.wallUs > 0.0) {
        i.kind = PerformanceGoalKind::TargetTtft;
        const double targetUs = pol.targetTtftMs.value * 1000.0;
        i.desiredRealSpeedup =
            (std::max)(1.0, baseline.wallUs / (std::max)(targetUs, 1.0));
        i.fromUser = true;
        i.detail = "from targetTtft";
    } else if (pol.targetWallUsPerToken.present &&
               pol.targetWallUsPerToken.value > 0.0) {
        i.kind = PerformanceGoalKind::TargetWallPerToken;
        i.desiredRealSpeedup = (std::max)(
            1.0, baseline.wallUs /
                     (std::max)(pol.targetWallUsPerToken.value, 1.0));
        i.fromUser = true;
        i.detail = "from targetWallUsPerToken";
    } else if (!autoT && pol.targetRealSpeedup.present) {
        i.kind = PerformanceGoalKind::SpeedupRatio;
        i.desiredRealSpeedup = (std::max)(1.0, pol.targetRealSpeedup.value);
        i.fromUser =
            (pol.targetRealSpeedup.authority >= SettingAuthority::UserOverride);
        i.detail = "user/session speedup ratio";
    } else {
        i.kind = PerformanceGoalKind::Auto;
        i.desiredRealSpeedup =
            DeriveAutoTargetSpeedup(baseline.wallUs, rem, risk);
        i.fromUser = false;
        i.detail = "evidence-derived AUTO target";
    }

    if (baseline.wallUs > 0.0 && i.desiredRealSpeedup > 1.0) {
        i.targetWallUs = baseline.wallUs / i.desiredRealSpeedup;
        i.requiredNetRemovalUs = baseline.wallUs - i.targetWallUs;
    } else {
        i.targetWallUs = baseline.wallUs;
        i.requiredNetRemovalUs = 0.0;
        i.desiredRealSpeedup = 1.0;
    }
    return i;
}

inline WorkRemovalPlan DraftPlan(const RemovableWorkEstimate& rem,
                                 double requiredUs) {
    WorkRemovalPlan p;
    // Allocate shares of removable opportunity toward the requirement.
    const double pool = (std::max)(rem.total(), 1.0);
    const double scale = (std::min)(1.0, requiredUs / pool);
    p.predictedReuseUs = rem.computeUs * 0.55 * scale;
    p.predictedChurnCutUs = rem.nvmeUs * 0.70 * scale;
    p.predictedResidencyUs = rem.memoryStallUs * 0.50 * scale;
    p.predictedMigrationCutUs = rem.migrationUs * 0.80 * scale;
    p.predictedFuseUs = rem.otherUs * 0.40 * scale;
    p.predictedVerifierOverheadUs = requiredUs * 0.05 * scale;
    return p;
}

inline ReverseSolveResult ReverseSolve(const SpeedupPolicy& pol,
                                       const PhysicalWorkCensus& baseline) {
    ReverseSolveResult r;
    r.baselineWallUs = baseline.wallUs;
    r.opportunity = EstimateRemovableFromCensus(baseline);
    r.intent = ResolveIntent(pol, baseline, r.opportunity);
    r.requiredCandidateWallUs = r.intent.targetWallUs;
    r.requiredNetRemovalUs = r.intent.requiredNetRemovalUs;

    const double risk =
        pol.maxRiskBudget.present ? pol.maxRiskBudget.value : 0.25;
    const double ceiling = r.opportunity.conservative(risk);
    r.reachable = (ceiling + 1e-9 >= r.requiredNetRemovalUs);

    r.plan = DraftPlan(r.opportunity, r.requiredNetRemovalUs);
    r.predictedNetSavedUs = r.plan.predictedNetSavedUs();
    const double predWall =
        (std::max)(baseline.wallUs - r.predictedNetSavedUs, 1.0);
    r.predictedSpeedup = baseline.wallUs / predWall;
    r.targetMetByPrediction =
        (r.predictedSpeedup + 1e-9 >= r.intent.desiredRealSpeedup);

    char buf[512];
    std::snprintf(
        buf, sizeof(buf),
        "intent=%.3fx  requiredWall=%.1f us  requiredNet=%.1f us\n"
        "removableCeiling=%.1f us  reachable=%s\n"
        "predictedNet=%.1f us  predictedSpeedup=%.3fx  meetsTarget=%s\n"
        "(%s)",
        r.intent.desiredRealSpeedup, r.requiredCandidateWallUs,
        r.requiredNetRemovalUs, ceiling, r.reachable ? "yes" : "no",
        r.predictedNetSavedUs, r.predictedSpeedup,
        r.targetMetByPrediction ? "yes" : "no", r.intent.detail.c_str());
    r.report = buf;
    return r;
}

// Promote only if measured speedup meets policy target (and min gain).
inline bool MeetsSpeedupTarget(const SpeedupPolicy& pol, double measuredSpeedup,
                               double desiredTarget) {
    const double minGain =
        pol.minimumAcceptedGain.present ? pol.minimumAcceptedGain.value : 1.01;
    if (measuredSpeedup + 1e-12 < minGain) return false;
    if (desiredTarget <= 1.0) return measuredSpeedup >= minGain;
    return measuredSpeedup + 1e-12 >= desiredTarget;
}

} // namespace Exec
} // namespace Deep2
