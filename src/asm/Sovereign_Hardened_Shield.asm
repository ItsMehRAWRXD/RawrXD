; ==============================================================================
; Sovereign_Hardened_Shield.asm - Direct PEB/TEB/TSC Integrity Shield
; ==============================================================================

include Sovereign_Common.inc

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Verify_Integrity
; Performs direct PEB probe and TSC jitter analysis.
; Returns: RAX=0 if clean, 1 if tampered.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Verify_Integrity
Sovereign_Verify_Integrity PROC
    push rbx
    push rsi
    push rdi

    ; 1. Direct TEB/PEB Probe (Bypass IsDebuggerPresent)
    mov rax, gs:[60h]              ; RAX = PEB
    movzx ecx, byte ptr [rax + 2]  ; Current BeingDebugged flag
    test ecx, ecx
    jnz @@Tampered

    ; 2. Timing Jitter Analysis (Detect Single-Stepping)
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rsi, rax                   ; RSI = Start TSC

    ; Inline dummy workload to establish a baseline jitter signature
    mov rcx, 1000
@@Baseline:
    pause
    loop @@Baseline

    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rsi                   ; RAX = Delta Cycles

    ; Threshold for 1000 pause instructions; if > 0x100000, 
    ; it implies a context switch or debugger interrupt.
    cmp rax, 100000h
    ja @@Tampered

    xor rax, rax                   ; Clean
    jmp @@Exit

@@Tampered:
    mov rax, 1                     ; Tampered status

@@Exit:
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Verify_Integrity ENDP

END
