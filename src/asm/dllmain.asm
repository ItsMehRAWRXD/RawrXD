; ============================================================================
; dllmain.asm - x64 MASM DLL Entry Point
; ============================================================================
; Provides DllMain for editor_pipeline.dll
; ============================================================================

option casemap:none

; Constants
DLL_PROCESS_ATTACH   EQU 1
DLL_PROCESS_DETACH   EQU 0
DLL_THREAD_ATTACH    EQU 2
DLL_THREAD_DETACH    EQU 3

.data

.code

; ============================================================================
; DllMain
; ============================================================================
; DLL entry point
;
; Parameters:
;   RCX = hinstDLL (module handle)
;   RDX = fdwReason (reason for calling)
;   R8  = lpvReserved (reserved)
; Returns:
;   RAX = TRUE (1) for success
; ============================================================================

ALIGN 16
DllMain PROC
    
    ; Check reason
    cmp     edx, DLL_PROCESS_ATTACH
    je      L_attach
    cmp     edx, DLL_PROCESS_DETACH
    je      L_detach
    cmp     edx, DLL_THREAD_ATTACH
    je      L_thread_attach
    cmp     edx, DLL_THREAD_DETACH
    je      L_thread_detach
    
    ; Unknown reason, return success
    mov     rax, 1
    ret
    
L_attach:
    ; Initialize on process attach
    ; Call Input_Init and Editor_Initialize here if needed
    mov     rax, 1
    ret
    
L_detach:
    ; Cleanup on process detach
    mov     rax, 1
    ret
    
L_thread_attach:
    ; Thread attach (no action needed)
    mov     rax, 1
    ret
    
L_thread_detach:
    ; Thread detach (no action needed)
    mov     rax, 1
    ret

DllMain ENDP

; ============================================================================
; Exported symbols
; ============================================================================

PUBLIC DllMain

END
