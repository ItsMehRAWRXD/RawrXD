; =============================================================================
; editor_pipeline_vtable.asm - Editor Pipeline VTable Implementation
; =============================================================================
; Exports a single GetVTable function that returns a pointer to the static
; vtable structure. This allows the host to access all editor functions via
; structure displacement instead of individual GetProcAddress calls.
;
; Architecture:
;   Host: LoadLibrary("editor_pipeline.dll")
;   Host: GetProcAddress(hModule, "GetVTable")
;   Host: call GetVTable -> returns &g_EditorVTable
;   Host: mov rbx, rax; call [rbx].EDITOR_PIPELINE_VTABLE.pfnInit
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
; GetVTable - Returns pointer to the editor pipeline vtable
; -----------------------------------------------------------------------------
; Returns: RAX = pointer to EDITOR_PIPELINE_VTABLE
; -----------------------------------------------------------------------------
GetVTable PROC PUBLIC
    lea rax, g_EditorVTable
    ret
GetVTable ENDP

; =============================================================================
; .data Section - Static VTable Structure
; =============================================================================

.data

; Static vtable initialized with function pointers
; This is the single source of truth for all editor exports
g_EditorVTable EDITOR_PIPELINE_VTABLE \
    <Editor_Init, \
     Editor_Shutdown, \
     Editor_PushInput, \
     Editor_PopInput, \
     Editor_PeekInput, \
     Editor_GetInputCount, \
     Editor_InsertChar, \
     Editor_DeleteChar, \
     Editor_InsertLine, \
     Editor_DeleteLine, \
     Editor_GetCursorPos, \
     Editor_SetCursorPos, \
     Editor_GetLineCount, \
     Editor_GetLineLength, \
     Editor_GetLineText, \
     Editor_GetStats>

; =============================================================================
; External Function Declarations
; =============================================================================
; These are implemented in editor.asm, input_handler.asm, wndproc_input_bridge.asm
; =============================================================================

; Initialization
EXTERN Editor_Init:PROC
EXTERN Editor_Shutdown:PROC

; Input queue operations
EXTERN Editor_PushInput:PROC
EXTERN Editor_PopInput:PROC
EXTERN Editor_PeekInput:PROC
EXTERN Editor_GetInputCount:PROC

; Gap buffer operations
EXTERN Editor_InsertChar:PROC
EXTERN Editor_DeleteChar:PROC
EXTERN Editor_InsertLine:PROC
EXTERN Editor_DeleteLine:PROC

; Cursor operations
EXTERN Editor_GetCursorPos:PROC
EXTERN Editor_SetCursorPos:PROC

; Buffer queries
EXTERN Editor_GetLineCount:PROC
EXTERN Editor_GetLineLength:PROC
EXTERN Editor_GetLineText:PROC

; Statistics
EXTERN Editor_GetStats:PROC

END
