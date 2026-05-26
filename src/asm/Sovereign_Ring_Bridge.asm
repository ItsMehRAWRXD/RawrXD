; ==============================================================================
; Sovereign_Ring_Bridge.asm
; Logic: Lock-Free Inter-Thread Communication Ring Buffer
; Purpose: High-throughput telemetry and instruction bus for the Sovereign Engine.
; ABI: Standard x64 MASM (Volatile: RCX, RDX, R8, R9)
; ==============================================================================

INCLUDE Sovereign_Execution_Graph_ABI.inc

; ------------------------------------------------------------------------------
; RING BUFFER STRUCTURE
; ------------------------------------------------------------------------------
; Layout (64-byte aligned):
; 00h: Head (Producer Index)
; 08h: Tail (Consumer Index)
; 10h: Capacity (Mask)
; 18h: Buffer Pointer
; ------------------------------------------------------------------------------
RING_HEADER STRUCT
    Head        dq ?    ; Producer
    Tail        dq ?    ; Consumer
    Capacity    dq ?    ; Power-of-2 Mask
    BufferPtr   dq ?
RING_HEADER ENDS

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: RawrXD_Ring_Init
; Input: RCX = BufferPointer, RDX = Capacity (Must be power of 2)
; Output: RAX = Success
; ------------------------------------------------------------------------------
PUBLIC RawrXD_Ring_Init
RawrXD_Ring_Init PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Initialize Header
    mov qword ptr [rcx + RING_HEADER.Head], 0
    mov qword ptr [rcx + RING_HEADER.Tail], 0
    mov [rcx + RING_HEADER.Capacity], rdx
    
    ; Store raw buffer address at end of header (64-byte aligned offset)
    lea rax, [rcx + 64]
    mov [rcx + RING_HEADER.BufferPtr], rax
    
    mov rax, 1 ; Success
    add rsp, 32
    pop rbp
    ret
RawrXD_Ring_Init ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Ring_Push_Atomic
; Input: RCX = RingHeaderPtr, RDX = Data (8 bytes)
; Logic: Lock-free producer slot reservation.
; ------------------------------------------------------------------------------
PUBLIC Ring_Push_Atomic
Ring_Push_Atomic PROC
    mov r8, [rcx + RING_HEADER.Head]
    mov r9, [rcx + RING_HEADER.Tail]
    
    ; Check if Full (Head + 1 == Tail, masked)
    mov rax, r8
    inc rax
    and rax, [rcx + RING_HEADER.Capacity]
    cmp rax, r9
    je @@Full ; Ring is full

    ; Reserved Head index in R8
    mov r10, [rcx + RING_HEADER.BufferPtr]
    mov [r10 + r8*8], rdx ; Write data
    
    ; Increment Head (Store)
    inc r8
    and r8, [rcx + RING_HEADER.Capacity]
    mov [rcx + RING_HEADER.Head], r8
    
    mov rax, 1 ; Success
    ret

@@Full:
    xor rax, rax ; Failure (Queue Full)
    ret
Ring_Push_Atomic ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Ring_Pop_Atomic
; Input: RCX = RingHeaderPtr
; Output: RAX = Data, RDX = Success (1) / Failure (0)
; ------------------------------------------------------------------------------
PUBLIC Ring_Pop_Atomic
Ring_Pop_Atomic PROC
    mov r8, [rcx + RING_HEADER.Head]
    mov r9, [rcx + RING_HEADER.Tail]
    
    ; Check if Empty
    cmp r8, r9
    je @@Empty

    ; Read Data
    mov r10, [rcx + RING_HEADER.BufferPtr]
    mov rax, [r10 + r9*8]
    
    ; Increment Tail (Store)
    inc r9
    and r9, [rcx + RING_HEADER.Capacity]
    mov rdx, 1 ; Success
    ret

@@Empty:
    xor rax, rax
    xor rdx, rdx ; Failure
    ret
Ring_Pop_Atomic ENDP

END

    
    mov rdx, 1 ; Success
    ret

@@Empty:
    xor rax, rax
    xor rdx, rdx ; Failure
    ret
Ring_Pop_Atomic ENDP

END
