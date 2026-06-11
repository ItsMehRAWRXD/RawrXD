// Win32IDE_KVApertureProbe.h — Declarations for KV aperture probe gate
#pragma once

#include <cstdint>

bool HasKVApertureProbeFlag(const char* cmdLine);
int  RunKVApertureProbe(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles,
                        std::uint64_t bytes);
