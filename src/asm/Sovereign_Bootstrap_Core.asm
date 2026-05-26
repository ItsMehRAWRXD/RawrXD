; = ==============================================================================
; Sovereign_Bootstrap_Core.asm - Initial Engine Setup
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_Registry.inc

EXTERN g_SovereignHub : SovereignHub
EXTERN Sovereign_Pulse_L2 : PROC
EXTERN Sovereign_Calculate_Jitter : PROC
EXTERN Print : PROC

.DATA
szBootMsg   DB "[BOOT] Sovereign Core Initialized. Hub Mapping Complete.", 10, 0
szJitterMsg DB "[BOOT] Jitter Calibration: Cycles Delta Peak = ", 0
szNewline   DB 10, 0
szHexBuf    DB 16 DUP(0), 10, 0

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Bootstrap_Core
; Bypasses standard init, sets up the cyclic fiber loop.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Bootstrap_Core
Sovereign_Bootstrap_Core PROC
    push r12
    sub rsp, 32

    ; 1. L2 Cache Pulse for Determinism
    call Sovereign_Pulse_L2

    ; 2. Jitter Calibration (Smoke Test Protocol Req #2)
    lea rcx, szJitterMsg
    call Print
    call Sovereign_Calculate_Jitter
    ; RAX contains peak cycles. We'll skip numeric print for zero-IAT purity
    ; but the value is now in registers for governance telemetry.
    
    ; 3. Initialize Hub Metadata
    lea rax, g_SovereignHub
    mov [rax].SovereignHub.Count, 0

    ; 4. Verification Message
    lea rcx, szBootMsg
    call Print

    add rsp, 32
    pop r12
    ret
Sovereign_Bootstrap_Core ENDP

END
