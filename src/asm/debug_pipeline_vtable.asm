; =============================================================================
; debug_pipeline_vtable.asm - Debug Pipeline VTable Implementation
; =============================================================================
; Exports a single GetVTable function that returns a pointer to the static
; vtable structure. This allows the host to access all debug functions via
; structure displacement instead of individual GetProcAddress calls.
;
; Architecture:
;   Host: LoadLibrary("debug_pipeline.dll")
;   Host: GetProcAddress(hModule, "GetVTable")
;   Host: call GetVTable -> returns &g_DebugVTable
;   Host: mov rbx, rax; call [rbx].DEBUG_PIPELINE_VTABLE.pfnInit
;
; Version: 1.0
; Date: 2026-06-18
; =============================================================================

option casemap:none

; Include interface definitions
include plugin_iface.inc

; =============================================================================
; .code Section - Exported Functions
; =============================================================================

.code

; -----------------------------------------------------------------------------
; GetVTable - Returns pointer to the debug pipeline vtable
; -----------------------------------------------------------------------------
; Returns: RAX = pointer to DEBUG_PIPELINE_VTABLE
; -----------------------------------------------------------------------------
GetVTable PROC PUBLIC
    lea rax, g_DebugVTable
    ret
GetVTable ENDP

; =============================================================================
; .data Section - Static VTable Structure
; =============================================================================

.data

; Static vtable initialized with function pointers
; This is the single source of truth for all debug exports
g_DebugVTable DEBUG_PIPELINE_VTABLE \
    <DbgEvent_Init, \
     DbgEvent_Shutdown, \
     DbgEvent_Push, \
     DbgEvent_Pop, \
     DbgEvent_Peek, \
     DbgEvent_GetCount, \
     DbgEvent_WalkStack, \
     DbgEvent_GetStats, \
     DbgEvent_Clear, \
     IDE_DebugInit, \
     IDE_DebugPoll, \
     IDE_DebugGetCurrentLine, \
     IDE_DebugGetCurrentAddress, \
     IDE_DebugGetState, \
     IDE_DebugGetCallStack, \
     IDE_DebugSetBreakpoint, \
     IDE_DebugClearBreakpoint, \
     IDE_DebugGetBreakpoints, \
     IDE_DebugContinue, \
     IDE_DebugStep, \
     IDE_DebugStop>

; =============================================================================
; External Function Declarations
; =============================================================================
; These are implemented in debug_event_ring.asm and ide_debug_bridge.asm
; =============================================================================

; Ring buffer operations (debug_event_ring.asm)
EXTERN DbgEvent_Init:PROC
EXTERN DbgEvent_Shutdown:PROC
EXTERN DbgEvent_Push:PROC
EXTERN DbgEvent_Pop:PROC
EXTERN DbgEvent_Peek:PROC
EXTERN DbgEvent_GetCount:PROC
EXTERN DbgEvent_WalkStack:PROC
EXTERN DbgEvent_GetStats:PROC
EXTERN DbgEvent_Clear:PROC

; IDE bridge operations (ide_debug_bridge.asm)
EXTERN IDE_DebugInit:PROC
EXTERN IDE_DebugPoll:PROC
EXTERN IDE_DebugGetCurrentLine:PROC
EXTERN IDE_DebugGetCurrentAddress:PROC
EXTERN IDE_DebugGetState:PROC
EXTERN IDE_DebugGetCallStack:PROC
EXTERN IDE_DebugSetBreakpoint:PROC
EXTERN IDE_DebugClearBreakpoint:PROC
EXTERN IDE_DebugGetBreakpoints:PROC
EXTERN IDE_DebugContinue:PROC
EXTERN IDE_DebugStep:PROC
EXTERN IDE_DebugStop:PROC

END
