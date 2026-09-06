// TimeClassBudget.hpp — critical-path classes + essential floor
#pragma once
#include "TimeReversalTypes.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

enum class TimeClass : uint8_t {
    EssentialCompute = 0,
    AvoidableCompute = 1,
    Movement = 2,
    Stall = 3
};

struct TimeAccounting {
    double accumulatedWorkUs = 0.0; // may overlap; may exceed wall
    double criticalPathUs = 0.0;    // must ≈ token wall
};

struct ClassifiedBudget {
    double essentialMs = 0.0;
    double avoidableMs = 0.0;
    double movementMs = 0.0;
    double stallMs = 0.0;
    double totalMs = 0.0;
    double removableMs = 0.0; // avoidable + movement + stall
    double theoreticalMaxTps = 0.0;
    double targetHeadroomMs = 0.0; // targetMs - essential
    bool targetFeasible = false;
    bool targetPhysicallyUnsupported = false;
};

inline ClassifiedBudget ClassifyBudget(double essentialMs, double avoidableMs,
                                       double movementMs, double stallMs,
                                       double targetMs) {
    ClassifiedBudget b;
    b.essentialMs = essentialMs;
    b.avoidableMs = avoidableMs;
    b.movementMs = movementMs;
    b.stallMs = stallMs;
    b.totalMs = essentialMs + avoidableMs + movementMs + stallMs;
    b.removableMs = avoidableMs + movementMs + stallMs;
    b.theoreticalMaxTps = (essentialMs > 0.0) ? (1000.0 / essentialMs) : 0.0;
    b.targetHeadroomMs = targetMs - essentialMs;
    b.targetFeasible = (targetMs >= essentialMs - 1e-9) && (essentialMs > 0.0);
    b.targetPhysicallyUnsupported = !b.targetFeasible && targetMs > 0.0;
    return b;
}

inline double RecoveryFractionRequired(double timeDebtMs, double removableMs) {
    if (removableMs <= 0.0) return timeDebtMs > 0.0 ? 1.0 : 0.0;
    return timeDebtMs / removableMs;
}

// dTPS/dt = -1000/t² → |value of 1 ms| ≈ 1000/t² TPS per ms
inline double TpsValueOfOneMs(double msPerToken) {
    if (msPerToken <= 0.0) return 0.0;
    return 1000.0 / (msPerToken * msPerToken);
}

inline bool CriticalPathMatchesWall(double criticalPathUs, double tokenWallUs,
                                    double tolUs) {
    return std::fabs(criticalPathUs - tokenWallUs) <= tolUs;
}

// accumulatedWorkUs may exceed wall (overlap); criticalPathUs must match wall
inline bool DualLedgerConsistent(const TimeAccounting& a, double tokenWallUs,
                                 double pathTolUs) {
    return CriticalPathMatchesWall(a.criticalPathUs, tokenWallUs, pathTolUs) &&
           a.accumulatedWorkUs + 1e-9 >= a.criticalPathUs;
}

inline std::string FormatClassifiedBudget(const ClassifiedBudget& b,
                                          double timeDebtMs) {
    char buf[768];
    std::snprintf(buf, sizeof(buf),
        "ESSENTIAL=%.2f AVOIDABLE=%.2f MOVEMENT=%.2f STALL=%.2f TOTAL=%.2f\n"
        "REMOVABLE=%.2f  RECOVERY_NEEDED=%.1f%%\n"
        "FLOOR_MAX_TPS=%.2f  HEADROOM=%.2f  FEASIBLE=%s\n",
        b.essentialMs, b.avoidableMs, b.movementMs, b.stallMs, b.totalMs,
        b.removableMs, 100.0 * RecoveryFractionRequired(timeDebtMs, b.removableMs),
        b.theoreticalMaxTps, b.targetHeadroomMs,
        b.targetPhysicallyUnsupported ? "PHYSICALLY_UNSUPPORTED" :
        (b.targetFeasible ? "YES" : "NO"));
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
