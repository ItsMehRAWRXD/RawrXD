// Win32IDE_TextEngineProbe.h — Declarations for text-engine probe gate
#pragma once

bool HasTextEngineProbeFlag(const char* cmdLine);
int  RunTextEngineProbe(const char* telemetryPath, int cycles);
int  RunTextEngineInvalidationProbe(const char* telemetryPath, int cycles);
