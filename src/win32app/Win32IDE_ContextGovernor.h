// Win32IDE_ContextGovernor.h — Declarations for sovereign context governor probe gate
#pragma once

#include <cstdint>

bool HasSovereignContextGovernorFlag(const char* cmdLine);
int  RunSovereignContextGovernor(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);
