/*=============================================================================
 * SovereignBridge.h
 * Bridge between RawrXD IDE and Sovereign Runtime validation pipeline
 *
 * Connects IDE → rawrxd.exe → validation/runs/ → certificate.json
 *===========================================================================*/
#pragma once

#ifndef SOVEREIGN_BRIDGE_H
#define SOVEREIGN_BRIDGE_H

#include <windows.h>
#include <strsafe.h>

/* Forward declaration */
typedef struct RawrXD_IDE RawrXD_IDE;

/* Sovereign execution modes */
typedef enum {
    SOV_MODE_VALIDATE,      /* --validate: Run validation suite */
    SOV_MODE_AUTONOMOUS,    /* --autonomous: Self-directed execution */
    SOV_MODE_INFERENCE,     /* --model: Run inference */
    SOV_MODE_CERTIFY        /* Generate certificate.json */
} SovereignMode;

/* Validation result structure */
typedef struct {
    BOOL        success;
    int         gatesPassed;
    int         gatesTotal;
    WCHAR       certificatePath[MAX_PATH];
    WCHAR       evidenceBundle[MAX_PATH];
    DWORD       exitCode;
    WCHAR       summary[512];
} SovereignResult;

/* Bridge functions */
BOOL    SovereignBridge_Init(RawrXD_IDE* ide);
void    SovereignBridge_Cleanup(RawrXD_IDE* ide);

/* Execution entry points */
BOOL    SovereignBridge_RunValidation(RawrXD_IDE* ide, const WCHAR* projectPath);
BOOL    SovereignBridge_RunAutonomous(RawrXD_IDE* ide, const WCHAR* projectPath);
BOOL    SovereignBridge_RunInference(RawrXD_IDE* ide, const WCHAR* modelPath, const WCHAR* prompt);

/* Process management */
HANDLE  SovereignBridge_LaunchProcess(RawrXD_IDE* ide, const WCHAR* cmdLine, const WCHAR* workingDir);
BOOL    SovereignBridge_CaptureOutput(RawrXD_IDE* ide, HANDLE hProcess);
void    SovereignBridge_ParseResult(RawrXD_IDE* ide, const WCHAR* output, SovereignResult* result);

/* Project context */
BOOL    SovereignBridge_ScanProject(RawrXD_IDE* ide, const WCHAR* folder, WCHAR* summaryPath);
BOOL    SovereignBridge_GenerateProjectSummary(const WCHAR* folder, const WCHAR* outputPath);

/* Menu integration */
void    SovereignBridge_OnValidateCommand(RawrXD_IDE* ide);
void    SovereignBridge_OnAutonomousCommand(RawrXD_IDE* ide);

#endif /* SOVEREIGN_BRIDGE_H */
