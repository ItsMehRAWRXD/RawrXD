; ==============================================================================
; SOVEREIGN GHOST TRACE
; File: Sovereign_Ghost_Trace.asm
; Role: Deterministic, Non-Blocking Telemetry (Component E)
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

GHOST_ENTRY STRUCT
    Timestamp   QWORD ?
    NodeID      QWORD ?
    Status      QWORD ?
    Reserved    QWORD ?
GHOST_ENTRY ENDS

.DATA
    GHOST_BUFFER_SIZE EQU 4096
    g_GhostBuffer     GHOST_ENTRY GHOST_BUFFER_SIZE DUP(<0>)
    g_GhostCursor     QWORD 0

.CODE

; RCX = NodeID, RDX = Status/Return Code
PUBLIC Sovereign_Ghost_Log
Sovereign_Ghost_Log PROC
    ; 1. Atomic Cursor Advance
    mov rax, 1
    lock xadd [g_GhostCursor], rax
    and rax, GHOST_BUFFER_SIZE - 1 ; Wrap to buffer size
    
    ; 2. Calculate Pointer
    shl rax, 5 ; sizeof(GHOST_ENTRY) is 32 (4 QWORDs). shl rax, 5 is exactly * 32.
    lea r8, [g_GhostBuffer + rax]
    
    ; 3. Stamp Data (preserving caller RDX into non-volatile or temp)
    mov r9, rdx
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [r8 + GHOST_ENTRY.Timestamp], rax
    mov [r8 + GHOST_ENTRY.NodeID], rcx
    mov [r8 + GHOST_ENTRY.Status], r9
    
    ret
Sovereign_Ghost_Log ENDP
END