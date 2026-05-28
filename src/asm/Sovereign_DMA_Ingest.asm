; ==============================================================================
; SOVEREIGN DMA INGEST
; File: Sovereign_DMA_Ingest.asm
; Role: Zero-Copy Hardware Tensor Ingestion via PRPs and Doorbell
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

; ==============================================================================
; NVME COMMAND ENTRY (64 bytes)
; ==============================================================================

NVME_CMD STRUCT
    OPCODE      BYTE ?
    FLAGS       BYTE ?
    CMDID       WORD ?
    NSID        DWORD ?
    RESERVED0   QWORD ?
    PRP1        QWORD ?   ; Physical pointer 1
    PRP2        QWORD ?   ; Physical pointer 2 / SGL
    CDW10       DWORD ?   ; LBA start
    CDW11       DWORD ?
    CDW12       DWORD ?
    CDW13       DWORD ?
    CDW14       DWORD ?
    CDW15       DWORD ?
NVME_CMD ENDS

NVME_SQ0TDBL EQU 1000h

.CODE

; RCX = NVMe BAR0 base
; RDX = Physical destination (Arena base)
; R8  = PRP list pointer
; R9  = LBA start
PUBLIC Sovereign_Direct_DMA_Ingest
Sovereign_Direct_DMA_Ingest PROC
    ENTER_FRAME

    ; Build NVMe command in-place (stack or arena scratch)
    sub rsp, 64
    mov r10, rsp

    ; OPCODE = READ (0x02)
    mov byte ptr [r10 + NVME_CMD.OPCODE], 02h
    mov byte ptr [r10 + NVME_CMD.FLAGS], 0

    ; PRP1 = destination physical address
    mov [r10 + NVME_CMD.PRP1], rdx

    ; PRP2 = optional scatter list
    mov [r10 + NVME_CMD.PRP2], r8

    ; LBA
    mov [r10 + NVME_CMD.CDW10], r9d

    ; Submit to SQ0 (MMIO write)
    mov rax, [rcx + NVME_SQ0TDBL]
    inc rax
    mov [rcx + NVME_SQ0TDBL], rax

    add rsp, 64
    EXIT_FRAME
    ret

Sovereign_Direct_DMA_Ingest ENDP

END
