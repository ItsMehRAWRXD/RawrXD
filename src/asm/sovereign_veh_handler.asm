; ============================================================================
; @file sovereign_veh_handler.asm
; @brief Structured Exception Handler for RawrXD
; @details Provides VEH (Vectored Exception Handler) for Sovereign mode
; ============================================================================

.code

; LONG CALLBACK Sovereign_VEH_Handler(PEXCEPTION_POINTERS ExceptionInfo)
; Vectored Exception Handler for Sovereign mode
Sovereign_VEH_Handler PROC
    ; Check if this is an exception we want to handle
    ; For now, just pass through to next handler (EXCEPTION_CONTINUE_SEARCH = 0)
    xor rax, rax    ; EXCEPTION_CONTINUE_SEARCH = 0
    ret
Sovereign_VEH_Handler ENDP

END
