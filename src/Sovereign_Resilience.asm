; Sovereign_Resilience.asm ? Production
SOVEREIGN_RESILIENCE_MODULE equ 1
; Sovereign_Resilience.asm ? Production
; Exponential Backoff with RDTSC Jitter
; x64 MASM | Hardened for 7800X3D
SOVEREIGN_RESILIENCE_MODULE equ 1
include Sovereign_Common.inc

.code

; -----------------------------------------------------------------------------
; Sovereign_CalcBackoff
; RCX = Retry Attempt (0-based)
; Returns: RAX = Backoff duration in iterations/ms (RDTSC-based)
; -----------------------------------------------------------------------------
PUBLIC Sovereign_CalcBackoff
Sovereign_CalcBackoff PROC
    mov rax, 100            ; Base units
    test rcx, rcx
    jz @no_attempt
    
    cmp rcx, 6              ; Cap at 2^6 (64x base)
    jbe @do_shift
    mov rcx, 6
@do_shift:
    shl rax, cl
    
@no_attempt:
    ; Add RDTSC Jitter (Non-reproducible jitter)
    push rax
    rdtsc                   ; EDX:EAX = TSC
    and rax, 0FFFFh         ; 64k mask for noise
    mov r8, rax
    pop rax
    add rax, r8             ; total = base_backoff + jitter
    
    ret
Sovereign_CalcBackoff ENDP

; -----------------------------------------------------------------------------
; Sovereign_Wait
; RCX = Iteration Count (Roughly ms if pause is used)
; -----------------------------------------------------------------------------
PUBLIC Sovereign_Wait
Sovereign_Wait PROC
    test rcx, rcx
    jz @done
@loop:
    pause
    dec rcx
    jnz @loop
@done:
    ret
Sovereign_Wait ENDP
end
