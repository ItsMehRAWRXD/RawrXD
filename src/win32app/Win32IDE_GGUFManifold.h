// Win32IDE_GGUFManifold.h — Declarations for GGUF manifold probe gate
#pragma once

#include <cstdint>

bool HasGGUFManifoldFlag(const char* cmdLine);
int  RunGGUFManifoldProbe(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);
