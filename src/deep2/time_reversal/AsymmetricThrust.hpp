// AsymmetricThrust.hpp — recover lost thrust; do not add power
#pragma once
#include "TimeReversalTypes.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

enum class ThrustPatchKind : uint8_t {
    Forward = 0,      // useful execution itself faster
    DragRemoval = 1,  // stalls / redundant work
    Side = 2,         // underused resources
    Anticipatory = 3  // future work before need
};

struct ThrustLane {
    const char* id = "";
    double usefulUs = 0.0;
    double blockedUs = 0.0;
    double idleUs = 0.0;
    double transferableUs = 0.0;
    double avoidableUs = 0.0;

    double netThrustUs() const {
        return usefulUs - blockedUs - avoidableUs;
    }
};

struct AsymmetryMap {
    double gpu0BusyPct = 0.0;
    double gpu1BusyPct = 0.0;
    double thrustAsymmetryPct = 0.0; // max - min load
    double criticalAsymmetryUs = 0.0; // wall caused by wait-while-idle
    double asymmetricRecoveryPotentialUs = 0.0;
    bool powerDeficit = false;
    bool thrustAsymmetry = false;
    const char* criticalPathOwner = "unknown";
};

struct ThrustPressure {
    double thrustDebtMs = 0.0;
    double asymmetryFactor = 0.0; // critical_asymmetric / debt
    double multiplier = 11.0;     // PRIORITY ONLY — never scales physical ms
    double hotpatchPressure = 0.0;
};

inline AsymmetryMap BuildAsymmetryMap(double gpu0Pct, double gpu1Pct,
                                      double criticalPathOwnerBlockedUs,
                                      double otherLaneIdleUs,
                                      double transferableOverlapUs) {
    AsymmetryMap m;
    m.gpu0BusyPct = gpu0Pct;
    m.gpu1BusyPct = gpu1Pct;
    m.thrustAsymmetryPct = std::fabs(gpu0Pct - gpu1Pct);
    m.criticalAsymmetryUs = criticalPathOwnerBlockedUs;
    m.asymmetricRecoveryPotentialUs =
        (std::min)(transferableOverlapUs, (std::min)(criticalPathOwnerBlockedUs, otherLaneIdleUs));
    m.powerDeficit = false; // default: do not assume need more silicon/clocks
    m.thrustAsymmetry = m.thrustAsymmetryPct >= 15.0 || m.asymmetricRecoveryPotentialUs > 0.0;
    m.criticalPathOwner = (gpu0Pct >= gpu1Pct) ? "gpu0" : "gpu1";
    return m;
}

inline ThrustPressure MakeThrustPressure(double thrustDebtMs,
                                         double asymmetricComponentMs,
                                         double multiplier = 11.0) {
    ThrustPressure p;
    p.thrustDebtMs = thrustDebtMs;
    p.multiplier = multiplier;
    p.asymmetryFactor =
        (thrustDebtMs > 0.0) ? (asymmetricComponentMs / thrustDebtMs) : 0.0;
    p.hotpatchPressure = thrustDebtMs * multiplier * p.asymmetryFactor;
    return p;
}

// P_useful = P_available - idle - stall - sync - transfer_waste - recompute
struct PowerSplit {
    double available = 100.0;
    double idle = 0.0;
    double stall = 0.0;
    double sync = 0.0;
    double transferWaste = 0.0;
    double recompute = 0.0;

    double useful() const {
        return available - idle - stall - sync - transferWaste - recompute;
    }
    double counterThrust() const { return available - useful(); }
};

inline std::string FormatAsymmetry(const AsymmetryMap& m, const ThrustPressure& p) {
    char buf[640];
    std::snprintf(buf, sizeof(buf),
        "POWER_DEFICIT=%s  THRUST_ASYMMETRY=%s  owner=%s\n"
        "GPU0=%.0f%% GPU1=%.0f%% ASYMMETRY=%.0f pp\n"
        "CRITICAL_ASYMMETRY=%.2f ms  RECOVERY_POTENTIAL=%.2f ms\n"
        "THRUST_DEBT=%.2f  ASYMM_FACTOR=%.3f  PRESSURE(11x)=%.1f [priority only]\n",
        m.powerDeficit ? "YES" : "NO", m.thrustAsymmetry ? "YES" : "NO",
        m.criticalPathOwner, m.gpu0BusyPct, m.gpu1BusyPct, m.thrustAsymmetryPct,
        m.criticalAsymmetryUs / 1000.0, m.asymmetricRecoveryPotentialUs / 1000.0,
        p.thrustDebtMs, p.asymmetryFactor, p.hotpatchPressure);
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
