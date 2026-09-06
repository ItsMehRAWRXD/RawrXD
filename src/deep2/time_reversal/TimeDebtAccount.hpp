// TimeDebtAccount.hpp — continuous token-time debt ledger
#pragma once
#include "TimeReversalTypes.hpp"
#include <algorithm>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

struct TimeDebtSnapshot {
    double currentMs = 0.0;
    double targetMs = 0.0;
    double debtMs = 0.0;       // max(0, current - target)
    double creditMs = 0.0;     // max(0, target - current)
    double debtRatio = 0.0;    // debt / current
    double throughputRequired = 1.0; // targetTps / currentTps
    double latencyReduction = 0.0;   // debt / current
};

inline TimeDebtSnapshot MakeDebt(double currentMs, double targetMs) {
    TimeDebtSnapshot d;
    d.currentMs = currentMs;
    d.targetMs = targetMs;
    d.debtMs = (std::max)(0.0, currentMs - targetMs);
    d.creditMs = (std::max)(0.0, targetMs - currentMs);
    d.debtRatio = (currentMs > 0.0) ? (d.debtMs / currentMs) : 0.0;
    d.latencyReduction = d.debtRatio;
    const double curTps = TpsFromMsPerToken(currentMs);
    const double tgtTps = TpsFromMsPerToken(targetMs);
    d.throughputRequired = (curTps > 0.0) ? (tgtTps / curTps) : 1.0;
    return d;
}

struct TimeDebtAccount {
    double presentedWallMs = 0.0;
    double targetAllowableMs = 0.0;
    double accumulatedDebtMs = 0.0;
    double timeRemovedMs = 0.0;
    double unpaidDebtMs = 0.0;
    uint64_t tokens = 0;

    void ObserveToken(double measuredMs, double targetMs) {
        tokens++;
        presentedWallMs += measuredMs;
        targetAllowableMs += targetMs;
        const double d = measuredMs - targetMs;
        if (d > 0.0) accumulatedDebtMs += d;
        unpaidDebtMs = (std::max)(0.0, accumulatedDebtMs - timeRemovedMs);
    }

    void CreditRemoval(double removedMs) {
        timeRemovedMs += (std::max)(0.0, removedMs);
        unpaidDebtMs = (std::max)(0.0, accumulatedDebtMs - timeRemovedMs);
    }
};

inline std::string FormatDebt(const TimeDebtSnapshot& d) {
    char buf[384];
    std::snprintf(buf, sizeof(buf),
        "CURRENT=%.2f TARGET=%.2f DEBT=%.2f CREDIT=%.2f\n"
        "DEBT_RATIO=%.2f%% THROUGHPUT_REQ=%.3f× LATENCY_CUT=%.2f%%\n",
        d.currentMs, d.targetMs, d.debtMs, d.creditMs,
        100.0 * d.debtRatio, d.throughputRequired, 100.0 * d.latencyReduction);
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
