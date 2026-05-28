; ==================================================================================
; SOVEREIGN TELEMETRY
; File: Sovereign_Telemetry.asm
; Role: Instrumentation and Work Stealing
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc
include Sovereign_Telemetry.inc

.CODE

; Component E: Instrumentation
PUBLIC Sovereign_Timestamp
Sovereign_Timestamp PROC
    rdtscp
    shl rdx, 32
    or rax, rdx
    ret
Sovereign_Timestamp ENDP

; Component D: Atomic Work-Stealing Primitive
; RCX = Ptr to Counter
PUBLIC Sovereign_Atomic_FetchAndAdd
Sovereign_Atomic_FetchAndAdd PROC
    mov rax, 1
    lock xadd [rcx], rax
    ret
Sovereign_Atomic_FetchAndAdd ENDP

END
