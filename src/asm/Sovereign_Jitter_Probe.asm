; ==============================================================================
; Sovereign_Jitter_Probe.asm
; Logic: Baseline RDTSC Jitter Calculation
; Purpose: Satisfies Smoke Test Protocol Requirement 2 (Jitter Baseline)
; ==============================================================================

include Sovereign_Common.inc

.DATA
szJitterMsg DB "[DIAG] Baseline Jitter Check: Cycles=", 0
szUnitsMsg  DB " | Determinism Status: ", 0
szGreenMsg  DB "STABLE", 10, 0
szAmberMsg  DB "VARIANCE DETECTED", 10, 0

.CODE

; ------------------------------------------------------------------------------
; Sovereign_Calculate_Jitter
; Logic: Measures delta between consecutive RDTSC calls.
; Returns: RAX = Peak Jitter (Cycles)
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Calculate_Jitter
Sovereign_Calculate_Jitter PROC
    push rbx
    push rsi
    
    xor rsi, rsi ; Peak jitter
    mov rcx, 100 ; Sample count

@@SampleLoop:
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax ; Start

    ; Small constant work to ignore pipeline noise
    mov r8, 10
@@work:
    pause
    dec r8
    jnz @@work

    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rbx ; Delta (Cycles)

    cmp rax, rsi
    jbe @@Next
    mov rsi, rax ; New peak
@@Next:
    loop @@SampleLoop

    mov rax, rsi
    pop rsi
    pop rbx
    ret
Sovereign_Calculate_Jitter ENDP

END
