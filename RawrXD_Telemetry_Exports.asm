; RawrXD_Telemetry_Exports.asm
; Export definitions for telemetry integration
; This file defines all public symbols for linking

; =============================================================================
; RawrXD_Telemetry.asm exports
; =============================================================================
PUBLIC Telemetry_Init
PUBLIC Telemetry_LogEvent
PUBLIC Telemetry_Flush
PUBLIC Telemetry_GetStats
PUBLIC Telemetry_Shutdown

; =============================================================================
; RawrXD_Sovereign_Telemetry_Integration.asm exports
; =============================================================================
PUBLIC Sovereign_Telemetry_Init
PUBLIC Sovereign_Inference_Begin
PUBLIC Sovereign_Inference_End
PUBLIC Sovereign_Token_Generated
PUBLIC Sovereign_Cache_Access
PUBLIC Sovereign_Precision_Switch
PUBLIC Sovereign_GetTelemetryStats

; =============================================================================
; Metric type constants (for C/C++ interop)
; =============================================================================
PUBLIC METRIC_NONE
PUBLIC METRIC_INFERENCE_START
PUBLIC METRIC_INFERENCE_END
PUBLIC METRIC_TOKEN_GENERATED
PUBLIC METRIC_CACHE_HIT
PUBLIC METRIC_CACHE_MISS
PUBLIC METRIC_PRECISION_SWITCH
PUBLIC METRIC_SECURITY_EVENT

; =============================================================================
; Quantization type constants
; =============================================================================
PUBLIC QUANT_INT8
PUBLIC QUANT_BF16
PUBLIC QUANT_FP32

; =============================================================================
; Data exports
; =============================================================================
PUBLIC g_sessionState
PUBLIC g_telemetryReady
PUBLIC g_totalInferences
PUBLIC g_totalTokens
PUBLIC g_totalLatencyUs

; =============================================================================
; C-compatible function names (undecorated)
; =============================================================================
; For C/C++ callers:
; extern "C" {
;     int Telemetry_Init(void);
;     void Telemetry_LogEvent(int type, int session, int count, int latency);
;     void Telemetry_Flush(void);
;     void Sovereign_Inference_Begin(int prompt_length);
;     int Sovereign_Inference_End(void);
;     void Sovereign_Token_Generated(int token_id, int latency_us);
; }

END
