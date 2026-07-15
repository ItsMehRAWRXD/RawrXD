; =============================================================================
; editor_stubs.asm - Stub implementations for editor functions
; =============================================================================
; Provides minimal stub implementations for editor functions referenced by
; input_handler.asm and wndproc_input_bridge.asm
; =============================================================================

option casemap:none

; =============================================================================
; .code Section - Function Implementations
; =============================================================================

.code

; ---------------------------------------------------------------------------
; Editor_InsertChar - Stub implementation
; ---------------------------------------------------------------------------
Editor_InsertChar PROC PUBLIC
    xor rax, rax
    ret
Editor_InsertChar ENDP

; ---------------------------------------------------------------------------
; Editor_DeleteChar - Stub implementation
; ---------------------------------------------------------------------------
Editor_DeleteChar PROC PUBLIC
    xor rax, rax
    ret
Editor_DeleteChar ENDP

; ---------------------------------------------------------------------------
; Editor_MoveCursor - Stub implementation
; ---------------------------------------------------------------------------
Editor_MoveCursor PROC PUBLIC
    xor rax, rax
    ret
Editor_MoveCursor ENDP

; ---------------------------------------------------------------------------
; Editor_InsertNewline - Stub implementation
; ---------------------------------------------------------------------------
Editor_InsertNewline PROC PUBLIC
    xor rax, rax
    ret
Editor_InsertNewline ENDP

; ---------------------------------------------------------------------------
; Editor_Backspace - Stub implementation
; ---------------------------------------------------------------------------
Editor_Backspace PROC PUBLIC
    xor rax, rax
    ret
Editor_Backspace ENDP

; ---------------------------------------------------------------------------
; Editor_Render - Stub implementation
; ---------------------------------------------------------------------------
Editor_Render PROC PUBLIC
    xor rax, rax
    ret
Editor_Render ENDP

; ---------------------------------------------------------------------------
; Editor_Initialize - Stub implementation
; ---------------------------------------------------------------------------
Editor_Initialize PROC PUBLIC
    xor rax, rax
    ret
Editor_Initialize ENDP

; ---------------------------------------------------------------------------
; Editor_Init - Stub implementation
; ---------------------------------------------------------------------------
Editor_Init PROC PUBLIC
    xor rax, rax
    ret
Editor_Init ENDP

; ---------------------------------------------------------------------------
; Editor_Shutdown - Stub implementation
; ---------------------------------------------------------------------------
Editor_Shutdown PROC PUBLIC
    xor rax, rax
    ret
Editor_Shutdown ENDP

; ---------------------------------------------------------------------------
; Editor_PushInput - Stub implementation
; ---------------------------------------------------------------------------
Editor_PushInput PROC PUBLIC
    xor rax, rax
    ret
Editor_PushInput ENDP

; ---------------------------------------------------------------------------
; Editor_PopInput - Stub implementation
; ---------------------------------------------------------------------------
Editor_PopInput PROC PUBLIC
    xor rax, rax
    ret
Editor_PopInput ENDP

; ---------------------------------------------------------------------------
; Editor_PeekInput - Stub implementation
; ---------------------------------------------------------------------------
Editor_PeekInput PROC PUBLIC
    xor rax, rax
    ret
Editor_PeekInput ENDP

; ---------------------------------------------------------------------------
; Editor_GetInputCount - Stub implementation
; ---------------------------------------------------------------------------
Editor_GetInputCount PROC PUBLIC
    xor rax, rax
    ret
Editor_GetInputCount ENDP

; ---------------------------------------------------------------------------
; Editor_InsertLine - Stub implementation
; ---------------------------------------------------------------------------
Editor_InsertLine PROC PUBLIC
    xor rax, rax
    ret
Editor_InsertLine ENDP

; ---------------------------------------------------------------------------
; Editor_DeleteLine - Stub implementation
; ---------------------------------------------------------------------------
Editor_DeleteLine PROC PUBLIC
    xor rax, rax
    ret
Editor_DeleteLine ENDP

; ---------------------------------------------------------------------------
; Editor_GetCursorPos - Stub implementation
; ---------------------------------------------------------------------------
Editor_GetCursorPos PROC PUBLIC
    xor rax, rax
    ret
Editor_GetCursorPos ENDP

; ---------------------------------------------------------------------------
; Editor_SetCursorPos - Stub implementation
; ---------------------------------------------------------------------------
Editor_SetCursorPos PROC PUBLIC
    xor rax, rax
    ret
Editor_SetCursorPos ENDP

; ---------------------------------------------------------------------------
; Editor_GetLineCount - Stub implementation
; ---------------------------------------------------------------------------
Editor_GetLineCount PROC PUBLIC
    xor rax, rax
    ret
Editor_GetLineCount ENDP

; ---------------------------------------------------------------------------
; Editor_GetLineLength - Stub implementation
; ---------------------------------------------------------------------------
Editor_GetLineLength PROC PUBLIC
    xor rax, rax
    ret
Editor_GetLineLength ENDP

; ---------------------------------------------------------------------------
; Editor_GetLineText - Stub implementation
; ---------------------------------------------------------------------------
Editor_GetLineText PROC PUBLIC
    xor rax, rax
    ret
Editor_GetLineText ENDP

; ---------------------------------------------------------------------------
; Editor_GetStats - Stub implementation
; ---------------------------------------------------------------------------
Editor_GetStats PROC PUBLIC
    xor rax, rax
    ret
Editor_GetStats ENDP

END

