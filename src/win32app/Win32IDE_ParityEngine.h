// Win32IDE_ParityEngine.h — Declarations for parity engine probe gate
#pragma once

#include <cstdint>

bool HasParityEngineFlag(const char* cmdLine);
int  RunParityEngineProbe(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles,
                          std::uint32_t laneWidth);
