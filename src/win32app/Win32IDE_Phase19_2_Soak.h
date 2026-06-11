// Win32IDE_Phase19_2_Soak.h — Declarations for phase 19.2 soak probe gate
#pragma once

#include <cstdint>

bool HasPhase19_2SoakFlag(const char* cmdLine);
int  RunPhase19_2Soak(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);
