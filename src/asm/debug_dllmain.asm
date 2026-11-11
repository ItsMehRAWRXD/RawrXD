; ============================================================================
; debug_dllmain.asm - x64 MASM DLL Entry Point for Debug Pipeline
; ============================================================================

option casemap:none

.data

.code

; ============================================================================
; DllMain
; ============================================================================
ALIGN 16
DllMain PROC
    
    ; RCX = hinstDLL
    ; RDX = fdwReason
    ; R8  = lpvReserved
    
    cmp     edx, 1          ; DLL_PROCESS_ATTACH
    je      L_attach
    cmp     edx, 0          ; DLL_PROCESS_DETACH
    je      L_detach
    cmp     edx, 2          ; DLL_THREAD_ATTACH
    je      L_thread
    cmp     edx, 3          ; DLL_THREAD_DETACH
    je      L_thread
    
    mov     rax, 1
    ret
    
L_attach:
    ; Initialize debug event ring buffer
    ; Call DbgEvent_Init here if needed
    mov     rax, 1
    ret
    
L_detach:
    mov     rax, 1
    ret
    
L_thread:
    mov     rax, 1
    ret

DllMain ENDP

PUBLIC DllMain

END
