// Win32IDE_MissingProbes.h — Declarations for probe gates not covered by existing gate files.
// These are referenced by main_win32.cpp when RAWRXD_ENABLE_IDE_PROBE_GATES is enabled.
#pragma once

#include <cstdint>

// Lane G: Cellular parity engine
bool HasParityEngineFlag(const char* cmdLine);
int  RunParityEngineProbe(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles,
                          std::uint32_t laneWidth);

// Lane F: ExecutionTruth
bool HasExecutionTruthFlag(const char* cmdLine);
int  RunExecutionTruth(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);

// Lane E: SovereignActionGraph
bool HasSovereignActionGraphFlag(const char* cmdLine);
int  RunSovereignActionGraph(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);

// Lane D: SovereignContextGovernor
bool HasSovereignContextGovernorFlag(const char* cmdLine);
int  RunSovereignContextGovernor(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);

// Lane C: GGUF manifold
bool HasGGUFManifoldFlag(const char* cmdLine);
int  RunGGUFManifoldProbe(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);

// Lane B: TBA link-graph
bool HasTBALinkGraphFlag(const char* cmdLine);
int  RunTBALinkGraph(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);

// Phase 19.2 soak
bool HasPhase19_2SoakFlag(const char* cmdLine);
int  RunPhase19_2Soak(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);
