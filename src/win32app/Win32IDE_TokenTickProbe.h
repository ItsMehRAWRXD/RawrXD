// Win32IDE_TokenTickProbe.h — Declarations for token-tick probe gate
#pragma once

#include <cstdint>

bool HasTokenTickFlag(const char* cmdLine);
int  RunTokenTickProbe(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles,
                       std::uint32_t tickHz, std::uint32_t nominalTps, std::uint32_t draftAcceptRatePermille);
