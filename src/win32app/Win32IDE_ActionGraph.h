// Win32IDE_ActionGraph.h — Declarations for sovereign action graph probe gate
#pragma once

#include <cstdint>

bool HasSovereignActionGraphFlag(const char* cmdLine);
int  RunSovereignActionGraph(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);
