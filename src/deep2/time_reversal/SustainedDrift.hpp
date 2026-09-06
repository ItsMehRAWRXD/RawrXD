// SustainedDrift.hpp — long-window TPS drift + attribution labels
#pragma once
#include "TimeReversalTypes.hpp"
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

enum class DriftClaimKind : uint8_t { Correlated = 0, Attributed = 1 };

struct DriftFactor {
    const char* name = "";
    double tpsDelta = 0.0; // negative = regression contribution
    DriftClaimKind kind = DriftClaimKind::Correlated;
};

struct SustainedDriftReport {
    double tps1m = 0.0;
    double tps5m = 0.0;
    double tps30m = 0.0;
    double tpsSession = 0.0;
    double drift30mPct = 0.0; // vs 1m
    double sustainedRegressionTps = 0.0;
    DriftFactor factors[8]{};
    int factorCount = 0;
    double unattributedTps = 0.0;
    bool hasAttributedClaims = false;
};

inline SustainedDriftReport AnalyzeSustainedDrift(const PerfWindows& w) {
    SustainedDriftReport r;
    r.tps1m = w.last60s.medianTps;
    r.tps5m = w.last5m.medianTps;
    r.tps30m = w.last30m.medianTps;
    r.tpsSession = w.session.medianTps;
    if (r.tps1m > 0.0)
        r.drift30mPct = 100.0 * (r.tps30m - r.tps1m) / r.tps1m;
    r.sustainedRegressionTps = (std::max)(0.0, r.tps1m - r.tps30m);

    // Default: all factors CORRELATED until causal gates prove ATTRIBUTED
    auto push = [&](const char* n, double d) {
        if (r.factorCount >= 8) return;
        r.factors[r.factorCount++] = {n, d, DriftClaimKind::Correlated};
    };
    // Placeholders filled by caller with measured deltas; zero here
    push("KV expansion", 0.0);
    push("GPU clock reduction", 0.0);
    push("residency churn", 0.0);
    push("NVMe queue contention", 0.0);
    r.unattributedTps = r.sustainedRegressionTps;
    r.hasAttributedClaims = false;
    return r;
}

inline void SetDriftFactor(SustainedDriftReport& r, int idx, double tpsDelta,
                           DriftClaimKind kind) {
    if (idx < 0 || idx >= r.factorCount) return;
    r.factors[idx].tpsDelta = tpsDelta;
    r.factors[idx].kind = kind;
    if (kind == DriftClaimKind::Attributed) r.hasAttributedClaims = true;
    double sumAttr = 0.0;
    for (int i = 0; i < r.factorCount; ++i)
        if (r.factors[i].kind == DriftClaimKind::Attributed)
            sumAttr += -r.factors[i].tpsDelta;
    r.unattributedTps = (std::max)(0.0, r.sustainedRegressionTps - sumAttr);
}

inline std::string FormatDrift(const SustainedDriftReport& r) {
    char buf[1024];
    int n = std::snprintf(buf, sizeof(buf),
        "TPS_1M=%.1f TPS_5M=%.1f TPS_30M=%.1f TPS_SESSION=%.1f\n"
        "DRIFT_30M=%+.1f%%  SUSTAINED_REGRESSION=%.1f TPS\n",
        r.tps1m, r.tps5m, r.tps30m, r.tpsSession, r.drift30mPct,
        r.sustainedRegressionTps);
    for (int i = 0; i < r.factorCount; ++i) {
        n += std::snprintf(buf + n, sizeof(buf) - n, "  %-24s %+5.1f TPS [%s]\n",
            r.factors[i].name, r.factors[i].tpsDelta,
            r.factors[i].kind == DriftClaimKind::Attributed ? "ATTRIBUTED"
                                                            : "CORRELATED");
    }
    n += std::snprintf(buf + n, sizeof(buf) - n,
                       "  unattributed            %+5.1f TPS\n",
                       -r.unattributedTps);
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
