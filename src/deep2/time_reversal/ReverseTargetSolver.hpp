// ReverseTargetSolver.hpp — TARGET_TPS → ms/token budget → removal plan
#pragma once
#include "TimeReversalTypes.hpp"
#include <algorithm>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

struct RemovalCandidate {
    const char* name = "";
    double availableSavingMs = 0.0; // theoretical, from measured opportunity
};

struct ReverseTargetPlan {
    double currentTps = 0.0;
    double currentMsToken = 0.0;
    double targetTps = 0.0;
    double targetMsToken = 0.0;
    double timeToRemoveMs = 0.0;
    RemovalCandidate candidates[12]{};
    int candidateCount = 0;
    double plannedSavingMs = 0.0;
    double predictedMsToken = 0.0;
    bool targetSatisfied = false;
    double missingMs = 0.0;
};

inline ReverseTargetPlan SolveReverseTarget(
    double currentMsToken, double targetTps,
    const RemovalCandidate* cands, int nCands) {
    ReverseTargetPlan p;
    p.currentMsToken = currentMsToken;
    p.currentTps = TpsFromMsPerToken(currentMsToken);
    p.targetTps = targetTps;
    p.targetMsToken = MsPerTokenFromTps(targetTps);
    p.timeToRemoveMs = (std::max)(0.0, currentMsToken - p.targetMsToken);

    double sum = 0.0;
    for (int i = 0; i < nCands && p.candidateCount < 12; ++i) {
        if (cands[i].availableSavingMs <= 0.0) continue;
        p.candidates[p.candidateCount++] = cands[i];
        sum += cands[i].availableSavingMs;
    }
    // Greedy take until budget met (preserve order = ranked input)
    double used = 0.0;
    for (int i = 0; i < p.candidateCount; ++i) {
        if (used >= p.timeToRemoveMs) break;
        used += p.candidates[i].availableSavingMs;
    }
    p.plannedSavingMs = (std::min)(used, sum);
    p.predictedMsToken = currentMsToken - p.plannedSavingMs;
    p.targetSatisfied = p.predictedMsToken <= p.targetMsToken + 1e-9;
    p.missingMs = p.targetSatisfied ? 0.0
                                    : (p.predictedMsToken - p.targetMsToken);
    return p;
}

inline std::string FormatReversePlan(const ReverseTargetPlan& p) {
    char buf[1600];
    int n = std::snprintf(buf, sizeof(buf),
        "CURRENT_TPS=%.2f  CURRENT_MS=%.2f\n"
        "TARGET_TPS=%.2f   TARGET_MS=%.2f\n"
        "TIME_TO_REMOVE=%.2f ms/token\n\n",
        p.currentTps, p.currentMsToken, p.targetTps, p.targetMsToken,
        p.timeToRemoveMs);
    for (int i = 0; i < p.candidateCount && n < (int)sizeof(buf) - 64; ++i) {
        n += std::snprintf(buf + n, sizeof(buf) - n, "  %-28s %6.2f ms\n",
                           p.candidates[i].name,
                           p.candidates[i].availableSavingMs);
    }
    n += std::snprintf(buf + n, sizeof(buf) - n,
        "\nplanned=%.2f  predicted_ms=%.2f  %s",
        p.plannedSavingMs, p.predictedMsToken,
        p.targetSatisfied ? "TARGET SATISFIED"
                          : "TARGET NOT YET SATISFIED");
    if (!p.targetSatisfied)
        n += std::snprintf(buf + n, sizeof(buf) - n,
                           "\nmissing %.2f ms/token\n", p.missingMs);
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
