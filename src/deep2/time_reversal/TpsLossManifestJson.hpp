// TpsLossManifestJson.hpp — emit screenpilot-tps-loss manifest text
#pragma once
#include "TpsLossManifest.hpp"
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

inline std::string EmitTpsLossManifestJson(const TpsLossManifest& m) {
    char buf[4096];
    int n = std::snprintf(buf, sizeof(buf),
        "{\n"
        "  \"schema\": \"rawrxd.screenpilot.tps-loss.v1\",\n"
        "  \"mode\": \"reverse_engineering\",\n"
        "  \"target\": {\n"
        "    \"targetTps\": %.4f,\n"
        "    \"targetMsPerToken\": %.4f,\n"
        "    \"powerIncreaseAllowed\": %s\n"
        "  },\n"
        "  \"baseline\": {\n"
        "    \"measuredTps\": %.4f,\n"
        "    \"measuredMsPerToken\": %.4f,\n"
        "    \"tokenTimeDebtMs\": %.4f,\n"
        "    \"throughputDeficitPct\": %.4f\n"
        "  },\n"
        "  \"lossModel\": {\n"
        "    \"equation\": \"max(0, measuredMsPerToken - targetMsPerToken)\",\n"
        "    \"criticalPathOnly\": true,\n"
        "    \"overlapAware\": true,\n"
        "    \"unattributedLossFailsClosed\": true,\n"
        "    \"elevenXIsPriorityOnly\": true\n"
        "  },\n"
        "  \"lanes\": [\n",
        m.targetTps, m.targetMs,
        m.powerIncreaseAllowed ? "true" : "false",
        m.measuredTps, m.measuredMs, m.tokenTimeDebtMs,
        100.0 * MakeDebt(m.measuredMs, m.targetMs).debtRatio);

    for (int i = 0; i < m.laneCount; ++i) {
        n += std::snprintf(buf + n, sizeof(buf) - n,
            "    {\"id\": \"%s\", \"measuredLossMs\": %.4f, \"recoverableMs\": %.4f,"
            " \"criticalPath\": %s}%s\n",
            m.lanes[i].id, m.lanes[i].measuredLossMs, m.lanes[i].recoverableMs,
            m.lanes[i].criticalPath ? "true" : "false",
            (i + 1 < m.laneCount) ? "," : "");
    }
    n += std::snprintf(buf + n, sizeof(buf) - n,
        "  ],\n"
        "  \"unattributedMs\": %.4f,\n"
        "  \"criticalPathLossSumMs\": %.4f,\n"
        "  \"criticalPathLossBound\": %s,\n"
        "  \"asymmetry\": {\n"
        "    \"gpu0BusyPct\": %.2f,\n"
        "    \"gpu1BusyPct\": %.2f,\n"
        "    \"criticalPathOwner\": \"%s\",\n"
        "    \"powerDeficit\": %s,\n"
        "    \"thrustAsymmetry\": %s,\n"
        "    \"asymmetricRecoveryPotentialMs\": %.4f\n"
        "  },\n"
        "  \"reversePressure\": {\n"
        "    \"multiplier\": 11.0,\n"
        "    \"hotpatchPressure\": %.4f,\n"
        "    \"note\": \"priority only; does not scale physical milliseconds\"\n"
        "  },\n"
        "  \"candidateGeneration\": {\n"
        "    \"predictedRemovalMs\": %.4f,\n"
        "    \"predictedRemainingDebtMs\": %.4f\n"
        "  },\n"
        "  \"constraints\": {\n"
        "    \"noAdditionalHardware\": true,\n"
        "    \"noClockIncreaseRequired\": true,\n"
        "    \"authorityMustRemainUnchanged\": true,\n"
        "    \"outputEquivalenceRequired\": true,\n"
        "    \"residencyCapsMustHold\": true\n"
        "  }\n"
        "}\n",
        m.unattributedMs, m.criticalPathLossSumMs,
        CriticalPathLossBound(m, 0.35) ? "true" : "false",
        m.asymmetry.gpu0BusyPct, m.asymmetry.gpu1BusyPct,
        m.asymmetry.criticalPathOwner,
        m.asymmetry.powerDeficit ? "true" : "false",
        m.asymmetry.thrustAsymmetry ? "true" : "false",
        m.asymmetry.asymmetricRecoveryPotentialUs / 1000.0,
        m.pressure.hotpatchPressure,
        m.predictedRemovalMs, m.predictedRemainingDebtMs);
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
