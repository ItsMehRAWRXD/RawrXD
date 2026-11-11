; ==============================================================================
; GhostBuffer_MASM.asm — MASM-side telemetry producer
; ==============================================================================
; Calls GhostBuffer_WriteEvent (C wrapper) to push telemetry into the
; lock-free ring buffer. Zero CRT. Pure x64 ABI.
; ==============================================================================

option casemap:none
option prologue:none
option epilogue:none

; ==============================================================================
; External C wrappers (from GhostBuffer_Wrappers.cpp)
; ==============================================================================
EXTERN GhostBuffer_WriteEvent : PROC

; ==============================================================================
; Event type constants (must match GhostEvent enum in GhostBuffer.hpp)
; ==============================================================================
GHOST_LOAD_START      EQU 01h
GHOST_LOAD_PROGRESS   EQU 02h
GHOST_LOAD_COMPLETE   EQU 03h
GHOST_LOAD_FAILED     EQU 04h
GHOST_INFER_START     EQU 10h
GHOST_INFER_TOKEN     EQU 11h
GHOST_INFER_COMPLETE  EQU 12h
GHOST_VRAM_ALLOC      EQU 20h
GHOST_VRAM_FREE       EQU 21h
GHOST_SYS_ALLOC       EQU 22h
GHOST_TENSOR_MAP      EQU 30h
GHOST_TENSOR_UNMAP    EQU 31h
GHOST_SCHEDULER_TICK  EQU 40h
GHOST_AGENT_DISPATCH  EQU 50h

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; Ghost_Log_Event — Write telemetry record from MASM
; Input:  CL = GhostEvent type, RDX = payload
; Clobbers: RAX, RCX, RDX, R8-R11 (per x64 ABI)
; ==============================================================================
PUBLIC Ghost_Log_Event
Ghost_Log_Event PROC
    push rbx
    sub rsp, 28h                    ; Shadow space (32) + align to 16

    ; C wrapper: GhostBuffer_WriteEvent(uint8_t type, uint64_t payload)
    ; RCX = type (zero-extended), RDX = payload
    movzx ecx, cl
    ; RDX already = payload
    call GhostBuffer_WriteEvent

    add rsp, 28h
    pop rbx
    ret
Ghost_Log_Event ENDP

; ==============================================================================
; Ghost_Log_Progress — Specialized: percent in high 32, bytes in low 32
; Input:  ECX = percent (0-100), EDX = bytes loaded
; ==============================================================================
PUBLIC Ghost_Log_Progress
Ghost_Log_Progress PROC
    push rbx
    sub rsp, 28h

    ; Pack percent (high 32) + bytes (low 32) into RDX payload
    movzx rax, cl                   ; percent
    shl rax, 32
    ; EDX already contains bytes; writing to EDX zero-extends to RDX
    or rdx, rax                     ; RDX = payload

    mov cl, GHOST_LOAD_PROGRESS
    call Ghost_Log_Event

    add rsp, 28h
    pop rbx
    ret
Ghost_Log_Progress ENDP

; ==============================================================================
; Ghost_Log_TensorMap — Specialized: tensor hash in payload
; Input:  RDX = tensor name hash
; ==============================================================================
PUBLIC Ghost_Log_TensorMap
Ghost_Log_TensorMap PROC
    push rbx
    sub rsp, 28h

    ; RDX already = hash (payload)
    mov cl, GHOST_TENSOR_MAP
    call Ghost_Log_Event

    add rsp, 28h
    pop rbx
    ret
Ghost_Log_TensorMap ENDP

; ==============================================================================
; Ghost_Log_Scheduler — Specialized: pack 4x uint16 into uint64 payload
; Input:  CX = pending, DX = running, R8w = done, R9w = failed
; ==============================================================================
PUBLIC Ghost_Log_Scheduler
Ghost_Log_Scheduler PROC
    push rbx
    sub rsp, 28h

    ; Pack: [pending:16][running:16][done:16][failed:16]
    movzx rax, r9w                  ; failed (low 16)
    movzx rbx, r8w
    shl rbx, 16
    or rax, rbx                     ; [done:16][failed:16]
    movzx rbx, dx
    shl rbx, 32
    or rax, rbx                     ; [running:16][done:16][failed:16]
    movzx rbx, cx
    shl rbx, 48
    or rax, rbx                     ; [pending:16][running:16][done:16][failed:16]
    mov rdx, rax

    mov cl, GHOST_SCHEDULER_TICK
    call Ghost_Log_Event

    add rsp, 28h
    pop rbx
    ret
Ghost_Log_Scheduler ENDP

end
