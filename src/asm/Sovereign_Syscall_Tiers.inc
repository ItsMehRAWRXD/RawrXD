; ==============================================================================
; Sovereign_Syscall_Tiers.inc - Syscall / WinAPI Boundary Classification
; ==============================================================================
; TIER 0 = Pure MASM Internal Logic
; TIER 1 = Resolved WinAPI Interface Logic
; TIER 2 = Direct Ring-0 Boundary Syscalls

; Defines explicit segmentation bridging to intercept execution flow

; Fast Tier 1 Syscall Wrapper (e.g. g_ApiTable calls)
API_CALL_T1 MACRO func_ptr
    CALL_FRAME_ALIGNED
    call [func_ptr]
    CALL_EXIT_ALIGNED
ENDM

; Dynamic Register Call (e.g. RAX points to API function)
API_CALL_T1_REG MACRO reg
    CALL_FRAME_ALIGNED
    call reg
    CALL_EXIT_ALIGNED
ENDM

; Tier 2 Direct Syscall (If transitioning to raw NT calls)
API_CALL_T2 MACRO syscall_idx
    ; Prepare registers
    mov r10, rcx
    mov eax, syscall_idx
    syscall
ENDM
