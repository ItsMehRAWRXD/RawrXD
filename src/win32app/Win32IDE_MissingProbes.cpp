// Win32IDE_MissingProbes.cpp — No-op implementations for probe gates referenced by main_win32.cpp.
// Full harnesses live in dedicated binaries; Win32IDE links these stubs to satisfy symbols.

#include "Win32IDE_MissingProbes.h"

#include <cstdio>
#include <cstring>
#include <windows.h>

namespace {

bool matchesCmdLine(const char* text, const char* flag)
{
    return text != nullptr && std::strstr(text, flag) != nullptr;
}

bool probeFlagImpl(const char* cmdLine, const char* primary, const char* secondary)
{
    if (cmdLine != nullptr && (matchesCmdLine(cmdLine, primary) || matchesCmdLine(cmdLine, secondary)))
        return true;
    return matchesCmdLine(GetCommandLineA(), primary) || matchesCmdLine(GetCommandLineA(), secondary);
}

} // anonymous namespace

// ------------------------------------------------------------------
// Lane G: Cellular parity engine
// ------------------------------------------------------------------
bool HasParityEngineFlag(const char* cmdLine)
{
    return probeFlagImpl(cmdLine, "--parity-engine-probe", "--parity-telemetry");
}

int RunParityEngineProbe(const char* /*telemetryPath*/, std::uint64_t /*expectedQuietZoneVa*/, int /*cycles*/,
                         std::uint32_t /*laneWidth*/)
{
    fprintf(stderr, "[parity-engine] Parity engine probe is not linked into Win32IDE; "
                  "use a dedicated harness build.\n");
    return 2;
}

// ------------------------------------------------------------------
// Lane F: ExecutionTruth
// ------------------------------------------------------------------
bool HasExecutionTruthFlag(const char* cmdLine)
{
    return probeFlagImpl(cmdLine, "--execution-truth-probe", "--truth-telemetry");
}

int RunExecutionTruth(const char* /*telemetryPath*/, std::uint64_t /*expectedQuietZoneVa*/, int /*cycles*/)
{
    fprintf(stderr, "[execution-truth] ExecutionTruth probe is not linked into Win32IDE; "
                  "use a dedicated harness build.\n");
    return 2;
}

// ------------------------------------------------------------------
// Lane E: SovereignActionGraph
// ------------------------------------------------------------------
bool HasSovereignActionGraphFlag(const char* cmdLine)
{
    return probeFlagImpl(cmdLine, "--action-graph-probe", "--action-graph-telemetry");
}

int RunSovereignActionGraph(const char* /*telemetryPath*/, std::uint64_t /*expectedQuietZoneVa*/, int /*cycles*/)
{
    fprintf(stderr, "[action-graph] SovereignActionGraph probe is not linked into Win32IDE; "
                  "use a dedicated harness build.\n");
    return 2;
}

// ------------------------------------------------------------------
// Lane D: SovereignContextGovernor
// ------------------------------------------------------------------
bool HasSovereignContextGovernorFlag(const char* cmdLine)
{
    return probeFlagImpl(cmdLine, "--context-governor-probe", "--governor-telemetry");
}

int RunSovereignContextGovernor(const char* /*telemetryPath*/, std::uint64_t /*expectedQuietZoneVa*/, int /*cycles*/)
{
    fprintf(stderr, "[context-governor] SovereignContextGovernor probe is not linked into Win32IDE; "
                  "use a dedicated harness build.\n");
    return 2;
}

// ------------------------------------------------------------------
// Lane C: GGUF manifold
// ------------------------------------------------------------------
bool HasGGUFManifoldFlag(const char* cmdLine)
{
    return probeFlagImpl(cmdLine, "--gguf-manifold-probe", "--manifold-telemetry");
}

int RunGGUFManifoldProbe(const char* /*telemetryPath*/, std::uint64_t /*expectedQuietZoneVa*/, int /*cycles*/)
{
    fprintf(stderr, "[gguf-manifold] GGUF manifold probe is not linked into Win32IDE; "
                  "use a dedicated harness build.\n");
    return 2;
}

// ------------------------------------------------------------------
// Lane B: TBA link-graph
// ------------------------------------------------------------------
bool HasTBALinkGraphFlag(const char* cmdLine)
{
    return probeFlagImpl(cmdLine, "--tba-link-graph", "--tba-telemetry");
}

int RunTBALinkGraph(const char* /*telemetryPath*/, std::uint64_t /*expectedQuietZoneVa*/, int /*cycles*/)
{
    fprintf(stderr, "[tba-link-graph] TBA link-graph probe is not linked into Win32IDE; "
                  "use a dedicated harness build.\n");
    return 2;
}

// ------------------------------------------------------------------
// Phase 19.2 soak
// ------------------------------------------------------------------
bool HasPhase19_2SoakFlag(const char* cmdLine)
{
    return probeFlagImpl(cmdLine, "--phase19-2-soak", "--soak-telemetry");
}

int RunPhase19_2Soak(const char* /*telemetryPath*/, std::uint64_t /*expectedQuietZoneVa*/, int /*cycles*/)
{
    fprintf(stderr, "[phase19.2-soak] Phase 19.2 soak probe is not linked into Win32IDE; "
                  "use a dedicated harness build.\n");
    return 2;
}
