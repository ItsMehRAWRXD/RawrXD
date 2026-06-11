// Win32IDE_ExecutionTruth.h — Declarations for execution truth probe gate
#pragma once

#include <cstdint>

bool HasExecutionTruthFlag(const char* cmdLine);
int  RunExecutionTruth(const char* telemetryPath, std::uint64_t expectedQuietZoneVa, int cycles);
