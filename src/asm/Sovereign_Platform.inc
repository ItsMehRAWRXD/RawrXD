; ==================================================================================
; SOVEREIGN PLATFORM
; File: Sovereign_Platform.inc
; Role: Memory Barriers and Exception Handling Macros
; ==================================================================================

; Memory Barriers (I)
SOV_LFENCE MACRO
    db 0Fh, 0AEh, 0E8h ; lfence
ENDM

SOV_SFENCE MACRO
    db 0Fh, 0AEh, 0F8h ; sfence
ENDM

; Exception Handling (F)
; Minimal SEH frame registration for production stability
SOV_REGISTER_SEH MACRO handler
    sub rsp, 32
    mov rcx, handler
    mov rdx, rsp ; Assuming frame base
    call [g_ApiTable.pRtlAddFunctionTable] 
    add rsp, 32
ENDM
