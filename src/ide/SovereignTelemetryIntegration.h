/*===========================================================================
 * SovereignTelemetryIntegration.h
 * VAL-027: Telemetry Integration Points - Header
 * 
 * Declares integration functions for SovereignInferenceBridge and GhostTextEngine.
 *===========================================================================*/

#pragma once

#include "SovereignTelemetry.h"
#include "SovereignInferenceBridge.h"
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * INFERENCE TELEMETRY INTEGRATION
 *=========================================================================*/

/* Called at start of inference request */
void STEL_BeginInference(const SIB_CompletionRequest* request);

/* Called when first token is generated */
void STEL_OnFirstToken(uint32_t tokenIndex);

/* Called for each token during generation */
void STEL_OnTokenGenerated(uint32_t tokenIndex);

/* Called when inference completes */
void STEL_EndInference(BOOL success, float confidence);

/*===========================================================================
 * GHOSTTEXT TELEMETRY INTEGRATION
 *=========================================================================*/

/* Called when GhostText suggestion is generated */
void STEL_GhostTextGenerated(const std::string& text, const WCHAR* filePath, float confidence);

/* Called when GhostText suggestion is accepted */
void STEL_GhostTextAccepted(uint32_t acceptedLines);

/* Called when GhostText suggestion is rejected */
void STEL_GhostTextRejected(void);

/* Called when GhostText suggestion expires (timeout) */
void STEL_GhostTextExpired(void);

/*===========================================================================
 * MEMORY TELEMETRY INTEGRATION
 *=========================================================================*/

/* Periodic memory snapshot (call from timer) */
void STEL_RecordMemorySnapshot(void);

/*===========================================================================
 * INITIALIZATION
 *=========================================================================*/

/* Initialize telemetry system - call during IDE startup */
BOOL STEL_InitializeForIDE(void);

/* Shutdown telemetry - call during IDE shutdown */
void STEL_ShutdownForIDE(void);

#ifdef __cplusplus
}
#endif
