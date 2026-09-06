// ============================================================================
// HostRamTelemetry.hpp — run-local peaks vs process-lifetime OS peaks
// PeakWorkingSetSize is LIFETIME — never use it as per-Generate peak.
// ============================================================================
#pragma once

#include "TelemetrySinks.hpp"
#include <algorithm>
#include <cstdint>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#endif

namespace Deep2 {
namespace Exec {

struct HostRamSnapshot {
    uint64_t processWorkingSetCurrent = 0;
    uint64_t runWorkingSetPeak = 0;              // sampled during run
    uint64_t processLifetimeWorkingSetPeak = 0; // OS PeakWorkingSetSize (info)
    uint64_t privateCommitCurrent = 0;
    uint64_t runPrivateCommitPeak = 0;           // sampled during run
    uint64_t processLifetimePrivateCommitPeak = 0;
    uint64_t modelResidentRam = 0;
    uint64_t marsManagedRam = 0;
    uint64_t streamingWorkingEstimate = 0;
    bool fromOs = false;
};

inline bool SampleCurrentProcessRam(uint64_t& wsOut, uint64_t& commitOut,
                                    uint64_t& lifetimeWsPeak,
                                    uint64_t& lifetimeCommitPeak) {
    wsOut = commitOut = lifetimeWsPeak = lifetimeCommitPeak = 0;
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (!GetProcessMemoryInfo(GetCurrentProcess(),
                              reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                              sizeof(pmc)))
        return false;
    wsOut = pmc.WorkingSetSize;
    commitOut = pmc.PrivateUsage;
    lifetimeWsPeak = pmc.PeakWorkingSetSize; // NOT resettable per run
    lifetimeCommitPeak = pmc.PeakPagefileUsage;
    return true;
#else
    (void)wsOut;
    (void)commitOut;
    (void)lifetimeWsPeak;
    (void)lifetimeCommitPeak;
    return false;
#endif
}

// Call at Generate start AFTER GlobalTelemetry().resetRun().
inline void ResetRunRamPeaks() {
    auto& g = GlobalTelemetry();
    uint64_t ws = 0, commit = 0, lifeWs = 0, lifeCommit = 0;
    const bool ok =
        SampleCurrentProcessRam(ws, commit, lifeWs, lifeCommit);
    g.processWorkingSetCurrent = ws;
    g.privateCommitCurrent = commit;
    g.runWorkingSetPeak = ws;
    g.runPrivateCommitPeak = commit;
    g.processLifetimeWorkingSetPeak = lifeWs;
    if (ok) {
        // lifetime peak is recorded for attribution checks only
    }
}

// Call periodically during Generate and once before observation.
inline void SampleRunRamPeaks() {
    auto& g = GlobalTelemetry();
    uint64_t ws = 0, commit = 0, lifeWs = 0, lifeCommit = 0;
    if (!SampleCurrentProcessRam(ws, commit, lifeWs, lifeCommit))
        return;
    g.processWorkingSetCurrent = ws;
    g.privateCommitCurrent = commit;
    g.runWorkingSetPeak = (std::max)(g.runWorkingSetPeak, ws);
    g.runPrivateCommitPeak = (std::max)(g.runPrivateCommitPeak, commit);
    g.processLifetimeWorkingSetPeak = lifeWs;
}

inline HostRamSnapshot SampleHostRam() {
    SampleRunRamPeaks();
    HostRamSnapshot s;
    auto& g = GlobalTelemetry();
    s.processWorkingSetCurrent = g.processWorkingSetCurrent;
    s.runWorkingSetPeak = g.runWorkingSetPeak;
    s.processLifetimeWorkingSetPeak = g.processLifetimeWorkingSetPeak;
    s.privateCommitCurrent = g.privateCommitCurrent;
    s.runPrivateCommitPeak = g.runPrivateCommitPeak;
    s.processLifetimePrivateCommitPeak = g.processLifetimeWorkingSetPeak; // placeholder
    s.fromOs = (s.processWorkingSetCurrent > 0 || s.runWorkingSetPeak > 0);
    // Re-read lifetime commit peak for observation completeness.
    uint64_t ws = 0, commit = 0, lifeWs = 0, lifeCommit = 0;
    if (SampleCurrentProcessRam(ws, commit, lifeWs, lifeCommit)) {
        s.processLifetimePrivateCommitPeak = lifeCommit;
        s.fromOs = true;
    }
    return s;
}

inline uint64_t PreferPeak(uint64_t a, uint64_t b) {
    return a > b ? a : b;
}

} // namespace Exec
} // namespace Deep2
