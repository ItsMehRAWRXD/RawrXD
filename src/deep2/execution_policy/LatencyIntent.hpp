// ============================================================================
// LatencyIntent.hpp — latency is the INPUT; speedup is the DERIVED ratio
//
//   target latency → required speed → required speedup → required Δtime
//
// Split: TTFT | DECODE (ms/token) | END-TO-END — never collapse them.
// ============================================================================
#pragma once

#include "Tunable.hpp"
#include "PhysicalWorkCensus.hpp"
#include "ReverseSpeedupSolver.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace Exec {

enum class LatencyKind : uint8_t {
    DecodeMsPerToken = 0, // steady-state generate
    TtftMs,               // prompt → first token
    EndToEndMs            // entire request wall
};

struct LatencyPolicy {
    Tunable<double> targetDecodeMs;
    Tunable<double> targetTtftMs;
    Tunable<double> targetE2eMs;
    Tunable<bool> autoTarget;
    Tunable<double> maxRiskBudget; // haircut on removable estimate
    double maxAcceptedDecodeMs = 0.0;
    double maxAcceptedTtftMs = 0.0;
};

struct LatencyBaseline {
    double decodeMs = 0.0; // ms/token
    double ttftMs = 0.0;
    double e2eMs = 0.0;
    double tps = 0.0; // 1000 / decodeMs when decode known
};

struct LatencyIntent {
    LatencyKind kind = LatencyKind::DecodeMsPerToken;
    bool autoTarget = true;
    bool fromUser = false;

    double baselineMs = 0.0;
    double targetMs = 0.0;
    double requiredSpeedup = 1.0;
    double requiredSavingsMs = 0.0;
    double targetTps = 0.0; // decode only: 1000 / targetMs

    double minAcceptedGain = 1.01;
    double maxRegression = 0.0;
    std::string detail;
};

struct LatencyBudgetSlice {
    double ffnMs = 0.0;
    double attentionMs = 0.0;
    double memoryStallMs = 0.0;
    double nvmeMs = 0.0;
    double migrationMs = 0.0;
    double syncMs = 0.0;
    double otherMs = 0.0;

    double total() const {
        return ffnMs + attentionMs + memoryStallMs + nvmeMs + migrationMs +
               syncMs + otherMs;
    }
};

struct LatencyAttribution {
    LatencyIntent intent;
    LatencyBudgetSlice baselineSlice;
    LatencyBudgetSlice removable; // potentially avoidable
    double conservativeRemovableMs = 0.0;
    bool reachable = false;
    std::string report;
};

inline LatencyPolicy MakeDefaultLatencyPolicy() {
    LatencyPolicy p;
    p.autoTarget.force(true, SettingAuthority::AutoDetect,
                       SettingMutability::Immediate);
    p.maxRiskBudget.force(0.25, SettingAuthority::AutoDetect,
                          SettingMutability::Immediate);
    return p;
}

// TPS ↔ ms/token
inline double MsPerTokenFromTps(double tps) {
    if (tps <= 0.0) return 0.0;
    return 1000.0 / tps;
}
inline double TpsFromMsPerToken(double msPerToken) {
    if (msPerToken <= 0.0) return 0.0;
    return 1000.0 / msPerToken;
}

inline LatencyBaseline BaselineFromObservation(double tokensPerSecond,
                                               double ttftMs,
                                               double e2eWallMs) {
    LatencyBaseline b;
    b.tps = tokensPerSecond;
    b.decodeMs = MsPerTokenFromTps(tokensPerSecond);
    b.ttftMs = ttftMs;
    b.e2eMs = e2eWallMs;
    return b;
}

inline double RequiredSpeedupFromLatency(double baselineMs, double targetMs) {
    if (baselineMs <= 0.0 || targetMs <= 0.0) return 1.0;
    if (targetMs >= baselineMs) return 1.0;
    return baselineMs / targetMs;
}

// Evidence-derived AUTO target latency (not an arbitrary speedup invent).
inline double DeriveAutoTargetLatencyMs(double baselineMs,
                                        double estimatedRemovableMs,
                                        double confidence,
                                        double maxRiskBudget) {
    if (baselineMs <= 0.0) return 0.0;
    const double c = (std::max)(0.0, (std::min)(1.0, confidence));
    const double hair =
        (std::max)(0.0, (std::min)(1.0, 1.0 - maxRiskBudget));
    const double safe =
        (std::max)(0.0, estimatedRemovableMs) * c * hair;
    const double floor = baselineMs * 0.05;
    return (std::max)(baselineMs - safe, floor);
}

inline LatencyBudgetSlice AttributeDecodeSlice(double decodeMs,
                                               const RemovableWorkEstimate& rem,
                                               double wallUsForScale) {
    LatencyBudgetSlice s;
    if (decodeMs <= 0.0) return s;
    // Scale census µs proxies into ms shares of the decode budget.
    const double scale =
        (wallUsForScale > 0.0) ? (decodeMs / (wallUsForScale / 1000.0)) : 1.0;
    const double remTotal = (std::max)(rem.total(), 1.0);
    const double remMs = (rem.total() / 1000.0) * scale;
    auto share = [&](double us) {
        return remMs * (us / remTotal);
    };
    // Fixed structural decode split + removable overlays.
    s.ffnMs = decodeMs * 0.44;
    s.attentionMs = decodeMs * 0.18;
    s.memoryStallMs = decodeMs * 0.14;
    s.nvmeMs = decodeMs * 0.10;
    s.migrationMs = decodeMs * 0.06;
    s.syncMs = decodeMs * 0.04;
    s.otherMs = decodeMs * 0.04;
    // Removable estimate biases which buckets can shrink (cap per bucket).
    s.ffnMs = (std::min)(s.ffnMs, s.ffnMs * 0.5 + share(rem.computeUs));
    s.nvmeMs = (std::min)(s.nvmeMs, share(rem.nvmeUs) + s.nvmeMs * 0.3);
    s.migrationMs =
        (std::min)(s.migrationMs, share(rem.migrationUs) + s.migrationMs * 0.2);
    s.memoryStallMs = (std::min)(s.memoryStallMs,
                                 share(rem.memoryStallUs) + s.memoryStallMs * 0.3);
    return s;
}

inline LatencyBudgetSlice RemovableFromSlice(const LatencyBudgetSlice& base,
                                             LatencyKind kind) {
    LatencyBudgetSlice r;
    // Different latency kinds point at different removable work.
    switch (kind) {
    case LatencyKind::TtftMs:
        r.ffnMs = base.ffnMs * 0.15; // prefill-ish
        r.attentionMs = base.attentionMs * 0.25;
        r.memoryStallMs = base.memoryStallMs * 0.55;
        r.nvmeMs = base.nvmeMs * 0.70;
        r.migrationMs = base.migrationMs * 0.80;
        r.syncMs = base.syncMs * 0.20;
        r.otherMs = base.otherMs * 0.40;
        break;
    case LatencyKind::EndToEndMs:
        r.ffnMs = base.ffnMs * 0.40;
        r.attentionMs = base.attentionMs * 0.35;
        r.memoryStallMs = base.memoryStallMs * 0.50;
        r.nvmeMs = base.nvmeMs * 0.60;
        r.migrationMs = base.migrationMs * 0.70;
        r.syncMs = base.syncMs * 0.35;
        r.otherMs = base.otherMs * 0.40;
        break;
    case LatencyKind::DecodeMsPerToken:
    default:
        r.ffnMs = base.ffnMs * 0.55;
        r.attentionMs = base.attentionMs * 0.30;
        r.memoryStallMs = base.memoryStallMs * 0.50;
        r.nvmeMs = base.nvmeMs * 0.55;
        r.migrationMs = base.migrationMs * 0.75;
        r.syncMs = base.syncMs * 0.25;
        r.otherMs = base.otherMs * 0.35;
        break;
    }
    return r;
}

inline LatencyIntent ResolveLatencyIntent(const LatencyPolicy& pol,
                                          const LatencyBaseline& base,
                                          const RemovableWorkEstimate& rem,
                                          double wallUs) {
    LatencyIntent i;
    const double risk =
        pol.maxRiskBudget.present ? pol.maxRiskBudget.value : 0.25;
    const bool autoT = !pol.autoTarget.present || pol.autoTarget.value;

    // Priority: user decode > user TTFT > user e2e > auto decode.
    if (pol.targetDecodeMs.present && pol.targetDecodeMs.value > 0.0 &&
        base.decodeMs > 0.0) {
        i.kind = LatencyKind::DecodeMsPerToken;
        i.baselineMs = base.decodeMs;
        i.targetMs = pol.targetDecodeMs.value;
        i.fromUser =
            (pol.targetDecodeMs.authority >= SettingAuthority::UserOverride);
        i.autoTarget = false;
        i.detail = "user/session targetDecodeMs";
    } else if (pol.targetTtftMs.present && pol.targetTtftMs.value > 0.0 &&
               base.ttftMs > 0.0) {
        i.kind = LatencyKind::TtftMs;
        i.baselineMs = base.ttftMs;
        i.targetMs = pol.targetTtftMs.value;
        i.fromUser =
            (pol.targetTtftMs.authority >= SettingAuthority::UserOverride);
        i.autoTarget = false;
        i.detail = "user/session targetTtftMs";
    } else if (pol.targetE2eMs.present && pol.targetE2eMs.value > 0.0 &&
               base.e2eMs > 0.0) {
        i.kind = LatencyKind::EndToEndMs;
        i.baselineMs = base.e2eMs;
        i.targetMs = pol.targetE2eMs.value;
        i.fromUser =
            (pol.targetE2eMs.authority >= SettingAuthority::UserOverride);
        i.autoTarget = false;
        i.detail = "user/session targetE2eMs";
    } else if (autoT && base.decodeMs > 0.0) {
        i.kind = LatencyKind::DecodeMsPerToken;
        i.baselineMs = base.decodeMs;
        const LatencyBudgetSlice slice =
            AttributeDecodeSlice(base.decodeMs, rem, wallUs);
        const LatencyBudgetSlice remSlice =
            RemovableFromSlice(slice, LatencyKind::DecodeMsPerToken);
        i.targetMs = DeriveAutoTargetLatencyMs(base.decodeMs, remSlice.total(),
                                               rem.confidence, risk);
        i.autoTarget = true;
        i.fromUser = false;
        i.detail = "evidence-derived AUTO targetDecodeMs";
    } else {
        i.baselineMs = base.decodeMs > 0.0 ? base.decodeMs : base.e2eMs;
        i.targetMs = i.baselineMs;
        i.detail = "no latency baseline — identity intent";
    }

    i.requiredSpeedup =
        RequiredSpeedupFromLatency(i.baselineMs, i.targetMs);
    i.requiredSavingsMs =
        (std::max)(0.0, i.baselineMs - i.targetMs);
    if (i.kind == LatencyKind::DecodeMsPerToken && i.targetMs > 0.0)
        i.targetTps = TpsFromMsPerToken(i.targetMs);
    return i;
}

inline LatencyAttribution AttributeLatency(const LatencyPolicy& pol,
                                           const LatencyBaseline& base,
                                           const PhysicalWorkCensus& census) {
    LatencyAttribution a;
    a.removable = {};
    const RemovableWorkEstimate rem = EstimateRemovableFromCensus(census);
    a.intent = ResolveLatencyIntent(pol, base, rem, census.wallUs);
    a.baselineSlice =
        AttributeDecodeSlice(a.intent.baselineMs, rem, census.wallUs);
    a.removable = RemovableFromSlice(a.baselineSlice, a.intent.kind);

    const double risk =
        pol.maxRiskBudget.present ? pol.maxRiskBudget.value : 0.25;
    const double hair =
        (std::max)(0.0, (std::min)(1.0, 1.0 - risk)) * rem.confidence;
    a.conservativeRemovableMs = a.removable.total() * hair;
    a.reachable =
        (a.conservativeRemovableMs + 1e-9 >= a.intent.requiredSavingsMs);

    char buf[384];
    std::snprintf(
        buf, sizeof(buf),
        "kind=%u baseline=%.2f ms target=%.2f ms requiredSpeedup=%.3fx\n"
        "requiredSavings=%.2f ms ceiling=%.2f ms reachable=%s targetTps=%.2f\n"
        "(%s)",
        (unsigned)a.intent.kind, a.intent.baselineMs, a.intent.targetMs,
        a.intent.requiredSpeedup, a.intent.requiredSavingsMs,
        a.conservativeRemovableMs, a.reachable ? "yes" : "no",
        a.intent.targetTps, a.intent.detail.c_str());
    a.report = buf;
    return a;
}

// Convert latency intent into the existing speedup PerformanceIntent.
inline PerformanceIntent PerformanceIntentFromLatency(const LatencyIntent& L) {
    PerformanceIntent i;
    i.kind = (L.kind == LatencyKind::TtftMs) ? PerformanceGoalKind::TargetTtft
             : (L.kind == LatencyKind::DecodeMsPerToken)
                   ? PerformanceGoalKind::TargetWallPerToken
                   : PerformanceGoalKind::SpeedupRatio;
    i.desiredRealSpeedup = L.requiredSpeedup;
    i.requiredNetRemovalUs = L.requiredSavingsMs * 1000.0;
    i.targetWallUs = L.targetMs * 1000.0;
    i.fromUser = L.fromUser;
    i.detail = "from LatencyIntent: " + L.detail;
    return i;
}

inline bool LatencyTargetReached(const LatencyIntent& intent,
                                 double measuredMs) {
    if (intent.targetMs <= 0.0) return false;
    return measuredMs > 0.0 && measuredMs <= intent.targetMs + 1e-9;
}

} // namespace Exec
} // namespace Deep2
