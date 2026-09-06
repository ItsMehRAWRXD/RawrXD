// TpsLossManifest.hpp — measured TPS loss → physical loss graph (no invention)
#pragma once
#include "AsymmetricThrust.hpp"
#include "PhysicalHotpatch.hpp"
#include "TimeDebtAccount.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace Deep2 {
namespace TimeReversal {

struct LossEvidence {
    const char* source = "runtime_counter";
    const char* counter = "";
    uint64_t samples = 0;
    uint64_t generation = 0;
    Hash256 stateImageSha{};
};

struct LossLane {
    const char* id = "";
    double measuredLossMs = 0.0;
    double recoverableMs = 0.0;
    bool physical = true;
    bool criticalPath = true;
    bool recoverable = true;
    LossEvidence evidence{};
};

struct LossHypothesis {
    const char* cause = "";
    double confidence = 0.0; // hypothesis until measured
};

struct HotpatchCandidate {
    const char* type = "";
    ThrustPatchKind kind = ThrustPatchKind::DragRemoval;
    double predictedNetRemovalMs = 0.0;
    LossHypothesis hypothesis{};
};

struct RecoveryRank {
    const char* id = "";
    double recoveryScore = 0.0; // priority only (may include ×11)
    double criticalPathMs = 0.0;
    double recoverability = 0.0;
    double confidence = 0.0;
};

struct TpsLossManifest {
    double targetTps = 0.0;
    double targetMs = 0.0;
    double measuredTps = 0.0;
    double measuredMs = 0.0;
    double tokenTimeDebtMs = 0.0;
    bool powerIncreaseAllowed = false;

    LossLane lanes[16]{};
    int laneCount = 0;
    double unattributedMs = 0.0;
    double criticalPathLossSumMs = 0.0;

    AsymmetryMap asymmetry{};
    ThrustPressure pressure{};

    HotpatchCandidate patches[12]{};
    int patchCount = 0;
    double predictedRemovalMs = 0.0;
    double predictedRemainingDebtMs = 0.0;

    RecoveryRank ranks[16]{};
    int rankCount = 0;
};

inline double RecoveryScore(double criticalPathMs, double recoverability,
                            double confidence, double multiplier = 11.0) {
    return criticalPathMs * recoverability * confidence * multiplier;
}

inline bool CriticalPathLossBound(const TpsLossManifest& m, double tolMs) {
    return std::fabs(m.criticalPathLossSumMs + m.unattributedMs - m.tokenTimeDebtMs) <=
           tolMs;
}

inline TpsLossManifest BuildTpsLossManifest(
    double measuredTps, double targetTps,
    const LossLane* lanes, int nLanes,
    double unattributedMs,
    const AsymmetryMap& asym,
    const HotpatchCandidate* patches, int nPatches) {
    TpsLossManifest m;
    m.measuredTps = measuredTps;
    m.targetTps = targetTps;
    m.measuredMs = MsPerTokenFromTps(measuredTps);
    m.targetMs = MsPerTokenFromTps(targetTps);
    m.tokenTimeDebtMs = MakeDebt(m.measuredMs, m.targetMs).debtMs;
    m.powerIncreaseAllowed = false;
    m.unattributedMs = unattributedMs;
    m.asymmetry = asym;

    double sumCp = 0.0;
    for (int i = 0; i < nLanes && m.laneCount < 16; ++i) {
        m.lanes[m.laneCount++] = lanes[i];
        if (lanes[i].criticalPath) sumCp += lanes[i].measuredLossMs;

        const double recov = (lanes[i].measuredLossMs > 0.0)
            ? (lanes[i].recoverableMs / lanes[i].measuredLossMs) : 0.0;
        const double conf = lanes[i].evidence.samples > 0 ? 0.9 : 0.5;
        m.ranks[m.rankCount++] = {
            lanes[i].id,
            RecoveryScore(lanes[i].measuredLossMs, recov, conf, 11.0),
            lanes[i].measuredLossMs, recov, conf};
    }
    m.criticalPathLossSumMs = sumCp;

    // Sort ranks descending by score (simple insertion)
    for (int i = 1; i < m.rankCount; ++i) {
        RecoveryRank key = m.ranks[i];
        int j = i - 1;
        while (j >= 0 && m.ranks[j].recoveryScore < key.recoveryScore) {
            m.ranks[j + 1] = m.ranks[j];
            --j;
        }
        m.ranks[j + 1] = key;
    }

    double pred = 0.0;
    for (int i = 0; i < nPatches && m.patchCount < 12; ++i) {
        m.patches[m.patchCount++] = patches[i];
        pred += patches[i].predictedNetRemovalMs;
    }
    m.predictedRemovalMs = pred;
    m.predictedRemainingDebtMs = (std::max)(0.0, m.tokenTimeDebtMs - pred);

    const double asymMs = asym.asymmetricRecoveryPotentialUs / 1000.0;
    m.pressure = MakeThrustPressure(m.tokenTimeDebtMs, asymMs, 11.0);
    return m;
}

inline std::string FormatTpsLossManifest(const TpsLossManifest& m) {
    char buf[2048];
    int n = std::snprintf(buf, sizeof(buf),
        "schema=rawrxd.screenpilot.tps-loss.v1\n"
        "measured=%.2f TPS / %.2f ms   target=%.2f / %.2f\n"
        "TOKEN_TIME_DEBT=%.2f  unattributed=%.2f  cp_sum=%.2f  bound=%s\n"
        "power_increase_allowed=%s\n",
        m.measuredTps, m.measuredMs, m.targetTps, m.targetMs,
        m.tokenTimeDebtMs, m.unattributedMs, m.criticalPathLossSumMs,
        CriticalPathLossBound(m, 0.35) ? "PASS" : "FAIL",
        m.powerIncreaseAllowed ? "true" : "false");
    n += std::snprintf(buf + n, sizeof(buf) - n, "ATTACK_ORDER (11x priority):\n");
    for (int i = 0; i < m.rankCount && n < (int)sizeof(buf) - 64; ++i) {
        n += std::snprintf(buf + n, sizeof(buf) - n,
            "  %d. %-16s score=%.2f  cp=%.2f ms\n", i + 1, m.ranks[i].id,
            m.ranks[i].recoveryScore, m.ranks[i].criticalPathMs);
    }
    n += std::snprintf(buf + n, sizeof(buf) - n,
        "predicted_removal=%.2f  remaining_debt=%.2f\n%s",
        m.predictedRemovalMs, m.predictedRemainingDebtMs,
        FormatAsymmetry(m.asymmetry, m.pressure).c_str());
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
