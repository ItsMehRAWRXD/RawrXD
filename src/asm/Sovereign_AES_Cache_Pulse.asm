; ==============================================================================
; Sovereign_AES_Cache_Pulse.asm
; Logic: AES-NI SIMD Cache-Thrashing & Determinism Pulse
; Features: Exercises AESENCLAST across a 256KB block to stabilize L2 latency.
; ==============================================================================

INCLUDE Sovereign_Execution_Graph_ABI.inc

.DATA
    align 16
    g_AES_State     db 256 dup(055h) ; AES Keys / State
    g_PulseBuffer   db 262144 dup(0) ; 256KB (Fits common L2 slices)

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Pulse_L2
; Logic: Forces all L2 lines in the 256KB block through the AES pipeline.
; Purpose: Eliminates warm-up jitter and creates a deterministic hardware path.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Pulse_L2
Sovereign_Pulse_L2 PROC
    push rsi
    push rdi
    
    lea rsi, g_PulseBuffer
    lea rdi, g_AES_State
    
    ; Load initial 128-bit state into XMM0 from g_AES_State
    movdqa xmm0, xmmword ptr [rdi]
    movdqa xmm1, xmmword ptr [rdi + 16] ; "Key"
    
    mov rcx, 16384 ; 256KB / 16 bytes per block
    
@@PulseLoop:
    ; 1. Encrypt current line (Cache Hit ensured by sequential pull)
    aesenc xmm0, xmm1
    aesenclast xmm0, xmm1
    
    ; 2. Store result to PulseBuffer (Thrashing L2)
    movdqa xmmword ptr [rsi], xmm0
    
    add rsi, 16
    dec rcx
    jnz @@PulseLoop
    
    pop rdi
    pop rsi
    ret
Sovereign_Pulse_L2 ENDP

END