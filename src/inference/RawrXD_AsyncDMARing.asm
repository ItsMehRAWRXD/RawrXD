; ============================================================================
; RawrXD_AsyncDMARing.asm — SPSC ring control for async DMA staging lanes
; ============================================================================
; Minimal lockless ring manager for single-producer/single-consumer flow.
; Capacity must be a power of two.
;
; Exports:
;   RawrXD_DMA_Init_Asm(capacity)
;   RawrXD_DMA_AcquireFill_Asm() -> slot index or -1 if full
;   RawrXD_DMA_Commit_Asm()
;   RawrXD_DMA_Release_Asm()
;   RawrXD_DMA_Head_Asm() -> current head
;   RawrXD_DMA_Tail_Asm() -> current tail
;   RawrXD_DMA_Depth_Asm() -> current depth in slots
;   RawrXD_DMA_IsNearlyFull_Asm(margin) -> 1 if depth >= capacity - margin
;   RawrXD_DMA_GetFullCount_Asm() -> atomic count of ring-full events
; ============================================================================

OPTION CASEMAP:NONE

.data
ALIGN 16
g_dma_head       QWORD 0
                QWORD 7 DUP(0)

ALIGN 16
g_dma_tail       QWORD 0
                QWORD 7 DUP(0)

ALIGN 16
g_dma_full_cnt   QWORD 0
                QWORD 7 DUP(0)

g_dma_capacity   QWORD 0
g_dma_mask       QWORD 0

.code

RawrXD_DMA_Init_Asm PROC PUBLIC
    ; RCX = capacity (power of two, >= 2)
    mov rax, rcx
    cmp rax, 2
    jae init_ok
    mov rax, 2
init_ok:
    mov g_dma_capacity, rax
    dec rax
    mov g_dma_mask, rax
    xor rax, rax
    mov g_dma_head, rax
    mov g_dma_tail, rax
    mov g_dma_full_cnt, rax
    ret
RawrXD_DMA_Init_Asm ENDP

RawrXD_DMA_AcquireFill_Asm PROC PUBLIC
    ; Returns RAX = current head slot if ring has space, else -1.
    mov r8, g_dma_head
    mov r9, g_dma_tail

    mov rax, r8
    inc rax
    and rax, g_dma_mask
    cmp rax, r9
    je ring_full

    mov rax, r8
    ret

ring_full:
    lock inc qword ptr [g_dma_full_cnt]
    mov rax, -1
    ret
RawrXD_DMA_AcquireFill_Asm ENDP

RawrXD_DMA_Commit_Asm PROC PUBLIC
    mov rax, g_dma_head
    inc rax
    and rax, g_dma_mask
    mov g_dma_head, rax
    ret
RawrXD_DMA_Commit_Asm ENDP

RawrXD_DMA_Release_Asm PROC PUBLIC
    mov rax, g_dma_tail
    inc rax
    and rax, g_dma_mask
    mov g_dma_tail, rax
    ret
RawrXD_DMA_Release_Asm ENDP

RawrXD_DMA_Head_Asm PROC PUBLIC
    mov rax, g_dma_head
    ret
RawrXD_DMA_Head_Asm ENDP

RawrXD_DMA_Tail_Asm PROC PUBLIC
    mov rax, g_dma_tail
    ret
RawrXD_DMA_Tail_Asm ENDP

RawrXD_DMA_Depth_Asm PROC PUBLIC
    ; Returns depth = (head - tail) mod capacity
    mov r8, g_dma_head
    mov r9, g_dma_tail
    mov rax, r8
    sub rax, r9
    jns depth_done
    add rax, g_dma_capacity
depth_done:
    ret
RawrXD_DMA_Depth_Asm ENDP

RawrXD_DMA_IsNearlyFull_Asm PROC PUBLIC
    ; RCX = margin
    ; Returns 1 if depth >= (capacity - margin), else 0.
    ; margin must be >= 1 and < capacity (caller enforces).
    mov r10, rcx
    call RawrXD_DMA_Depth_Asm
    mov r11, g_dma_capacity
    sub r11, r10
    cmp rax, r11
    setae al
    movzx rax, al
    ret
RawrXD_DMA_IsNearlyFull_Asm ENDP

RawrXD_DMA_GetFullCount_Asm PROC PUBLIC
    mov rax, g_dma_full_cnt
    ret
RawrXD_DMA_GetFullCount_Asm ENDP

END
