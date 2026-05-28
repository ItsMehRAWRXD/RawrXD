; ==============================================================================
; SOVEREIGN CORE AFFINITY MATRIX
; File: Sovereign_Core_Affinity.asm
; Role: Enforces physical core pinning to eliminate OS scheduler context mapping
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

EXTERN GetCurrentThread:PROC
EXTERN SetThreadAffinityMask:PROC

.CODE

; ==============================================================================
; Sovereign_Bind_Lane_To_Core
; RCX = Core ID (0 to N) to bind the caller OS thread against
; Purpose: Pin execution directly into specific processor cache paths.
; ==============================================================================
PUBLIC Sovereign_Bind_Lane_To_Core
Sovereign_Bind_Lane_To_Core PROC
    ENTER_FRAME

    ; Compute bitmask: 1 << CoreID
    mov rax, 1
    shl rax, cl
    mov rbx, rax                 ; RBX = Valid dwThreadAffinityMask (64-bit wide)

    ; Get OS Pseudo-Handle
    call GetCurrentThread        
    
    ; rax = Thread Handle
    mov rcx, rax                 ; Arg1: hThread
    mov rdx, rbx                 ; Arg2: dwThreadAffinityMask
    call SetThreadAffinityMask

    ; Expected: Returns old affinity mask in RAX (or 0 on failure).
    ; Return immediately. Success defaults hardware execution into target lane.

    EXIT_FRAME
    ret
Sovereign_Bind_Lane_To_Core ENDP

END
