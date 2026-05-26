; ==============================================================================
; Sovereign_Stealth.asm - Direct PEB/TEB Anti-Debug Hardening
; ==============================================================================

include Sovereign_Common.inc

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Check_Stealth_State
; Direct Segment-based Probe (Bypasses IAT Hooks)
; Returns RAX = 1 if detected, 0 if clean.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Check_Stealth_State
Sovereign_Check_Stealth_State PROC
    ; GS:[60h] is the PEB pointer on x64
    mov rax, qword ptr gs:[60h]
    
    ; 1. BeingDebugged flag (Offset 0x02)
    movzx ecx, byte ptr [rax + 2]
    test ecx, ecx
    jnz @@Detected
    
    ; 2. NtGlobalFlag (Offset 0xBC)
    ; Common debugger flags: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    mov ecx, [rax + 0BCh]
    and ecx, 70h
    jnz @@Detected

    xor rax, rax
    ret

@@Detected:
    mov rax, 1
    ret
Sovereign_Check_Stealth_State ENDP

END
