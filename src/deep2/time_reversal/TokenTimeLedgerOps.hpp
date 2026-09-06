// TokenTimeLedgerOps.hpp — reconcile + disappearance (time removed)
#pragma once
#include "TimeReversalTypes.hpp"
#include <cmath>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

inline double LedgerComponentSumUs(const TokenTimeLedger& L) {
    return L.embeddingUs + L.weightAcquireUs + L.nvmeWaitUs + L.ramStageUs +
           L.gpuTransferUs + L.attentionUs + L.ropeUs + L.softmaxUs +
           L.kvReadUs + L.kvWriteUs + L.ffnGateUs + L.ffnUpUs + L.ffnDownUs +
           L.moeRouteUs + L.expertLoadUs + L.expertComputeUs + L.logitsUs +
           L.samplingUs + L.verificationUs + L.schedulerUs + L.synchronizationUs;
}

// Invariant: SUM(components) ≈ totalUs within toleranceUs
inline bool LedgerReconciles(const TokenTimeLedger& L, double tolUs,
                             double* absErrUs = nullptr) {
    const double sum = LedgerComponentSumUs(L);
    const double err = std::fabs(sum - L.totalUs);
    if (absErrUs) *absErrUs = err;
    return err <= tolUs;
}

struct DisappearanceRow {
    const char* name;
    double gUs;
    double g1Us;
    double deltaUs; // negative = time disappeared
};

struct DisappearanceReport {
    DisappearanceRow rows[22]{};
    int rowCount = 0;
    double tokenWallGUs = 0.0;
    double tokenWallG1Us = 0.0;
    double disappearedUs = 0.0;
    double tpsG = 0.0;
    double tpsG1 = 0.0;
    double realSpeedup = 1.0;
};

inline void PushRow(DisappearanceReport& r, const char* n, double a, double b) {
    if (r.rowCount >= 22) return;
    auto& x = r.rows[r.rowCount++];
    x.name = n; x.gUs = a; x.g1Us = b; x.deltaUs = b - a;
}

inline DisappearanceReport CompareLedgers(const TokenTimeLedger& G,
                                          const TokenTimeLedger& G1) {
    DisappearanceReport r;
    PushRow(r, "Weight acquire", G.weightAcquireUs, G1.weightAcquireUs);
    PushRow(r, "NVMe wait", G.nvmeWaitUs, G1.nvmeWaitUs);
    PushRow(r, "Attention", G.attentionUs, G1.attentionUs);
    PushRow(r, "RoPE", G.ropeUs, G1.ropeUs);
    PushRow(r, "Softmax", G.softmaxUs, G1.softmaxUs);
    PushRow(r, "KV", G.kvReadUs + G.kvWriteUs, G1.kvReadUs + G1.kvWriteUs);
    PushRow(r, "FFN", G.ffnGateUs + G.ffnUpUs + G.ffnDownUs,
            G1.ffnGateUs + G1.ffnUpUs + G1.ffnDownUs);
    PushRow(r, "MoE/Expert", G.moeRouteUs + G.expertLoadUs + G.expertComputeUs,
            G1.moeRouteUs + G1.expertLoadUs + G1.expertComputeUs);
    PushRow(r, "Verification", G.verificationUs, G1.verificationUs);
    PushRow(r, "Scheduler", G.schedulerUs, G1.schedulerUs);
    r.tokenWallGUs = G.totalUs;
    r.tokenWallG1Us = G1.totalUs;
    r.disappearedUs = G.totalUs - G1.totalUs;
    r.tpsG = TpsFromMsPerToken(G.totalUs / 1000.0);
    r.tpsG1 = TpsFromMsPerToken(G1.totalUs / 1000.0);
    r.realSpeedup = (G1.totalUs > 0.0) ? (G.totalUs / G1.totalUs) : 1.0;
    return r;
}

inline std::string FormatDisappearance(const DisappearanceReport& r) {
    char buf[2048];
    int n = std::snprintf(buf, sizeof(buf),
        "                 G        G+1      disappeared\n");
    for (int i = 0; i < r.rowCount && n < (int)sizeof(buf) - 80; ++i) {
        n += std::snprintf(buf + n, sizeof(buf) - n,
            "%-14s %7.2f ms %7.2f ms  %+7.2f ms\n",
            r.rows[i].name, r.rows[i].gUs / 1000.0, r.rows[i].g1Us / 1000.0,
            r.rows[i].deltaUs / 1000.0);
    }
    n += std::snprintf(buf + n, sizeof(buf) - n,
        "Token wall    %7.2f ms %7.2f ms  %+7.2f ms\n"
        "TPS           %7.2f     %7.2f\nREAL_SPEEDUP            %.3f×\n",
        r.tokenWallGUs / 1000.0, r.tokenWallG1Us / 1000.0,
        -r.disappearedUs / 1000.0, r.tpsG, r.tpsG1, r.realSpeedup);
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
