// Win32IDE_TBA_LinkGraph.h — Declarations for TBA link graph probe gate
#pragma once

#include <cstdint>

bool HasTBALinkGraphFlag(const char* cmdLine);
int  RunTBALinkGraph(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);
