; =====================================================================================
; ENGINE CORE: Low-Level Memory Allocator
; Target: Windows x64 (AMD64)
; Compiler: MASM (ml64.exe)
; =====================================================================================

; Win32 constants
MEM_COMMIT      EQU     00001000h
MEM_RESERVE     EQU     00002000h
PAGE_READWRITE  EQU     00000004h

.DATA

; --- Heap descriptor table ---
; Supports 10 fixed-size pools (16B, 32B, 64B, 128B, 256B, 512B, 1KB, 4KB, 16KB, 64KB)
ALIGN 8
PoolDescriptors  DWORD 10 DUP(0)       ; Base address of each pool
PoolBlockSizes   DWORD 16, 32, 64, 128, 256, 512, 1024, 4096, 16384, 65536
PoolBlockCounts  DWORD 4096, 2048, 1024, 512, 256, 128, 64, 16, 8, 4
PoolTotalSize    QWORD 0               ; Total committed bytes

; --- Global allocation tracking ---
TotalAllocated   QWORD 0
TotalFreed       QWORD 0
PeakAllocated    QWORD 0
AllocationCount  QWORD 0

.CODE

; ---------------------------------------------------------------------------
; External Win32 API
; ---------------------------------------------------------------------------
EXTERN VirtualAlloc : PROC

; ---------------------------------------------------------------------------
; EngineMem_Init - Initialize all memory pools
; Returns: RAX = 1 on success, 0 on failure
; ---------------------------------------------------------------------------
EngineMem_Init PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12

    xor     rsi, rsi                    ; pool index
    lea     rdi, PoolDescriptors
    lea     rbx, PoolBlockSizes
    lea     rcx, PoolBlockCounts

InitLoop:
    cmp     rsi, 10
    jae     InitDone

    mov     eax, [rbx + rsi*4]          ; block size
    mov     r12d, [rcx + rsi*4]         ; block count
    mul     r12d                        ; total bytes for this pool
    mov     r12, rax                    ; save size
    add     [PoolTotalSize], rax

    ; VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    xor     ecx, ecx                    ; lpAddress = NULL
    mov     rdx, r12                    ; dwSize
    mov     r8d, MEM_COMMIT OR MEM_RESERVE ; flAllocationType
    mov     r9d, PAGE_READWRITE         ; flProtect
    sub     rsp, 32                     ; shadow space
    call    VirtualAlloc
    add     rsp, 32
    test    rax, rax
    jz      InitFail

    mov     [rdi + rsi*4], eax          ; store pool base (low 32 bits)
    inc     rsi
    jmp     InitLoop

InitFail:
    xor     eax, eax
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

InitDone:
    mov     eax, 1
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
EngineMem_Init ENDP

; ---------------------------------------------------------------------------
; EngineMem_Alloc - Allocate from best-fit pool
; Input:  ECX = requested bytes
; Output: RAX = pointer, 0 if out of memory
; ---------------------------------------------------------------------------
EngineMem_Alloc PROC
    push    rbx
    push    rsi

    ; Find best-fit pool
    xor     rsi, rsi
    lea     rbx, PoolBlockSizes

FindPool:
    cmp     rsi, 10
    jae     AllocFail
    cmp     ecx, [rbx + rsi*4]
    jbe     PoolFound
    inc     rsi
    jmp     FindPool

PoolFound:
    ; Pop from free list
    lea     rbx, PoolDescriptors
    mov     rax, [rbx + rsi*8]          ; current free pointer
    test    rax, rax
    jz      AllocFail

    ; Update free list to next block
    mov     rcx, [rax]                  ; next free block pointer
    mov     [rbx + rsi*8], rcx

    ; Update tracking
    add     qword ptr [TotalAllocated], rsi
    inc     qword ptr [AllocationCount]

    pop     rsi
    pop     rbx
    ret

AllocFail:
    xor     eax, eax
    pop     rsi
    pop     rbx
    ret
EngineMem_Alloc ENDP

; ---------------------------------------------------------------------------
; EngineMem_Free - Return block to pool
; Input:  RCX = pointer to free
; ---------------------------------------------------------------------------
EngineMem_Free PROC
    push    rbx
    push    rsi

    ; Push to pool 0 free list
    lea     rbx, PoolDescriptors
    mov     rax, [rbx]                  ; current head of pool 0
    mov     [rcx], rax                  ; point freed block to current head
    mov     [rbx], rcx                  ; new head = freed block

    inc     qword ptr [TotalFreed]

    pop     rsi
    pop     rbx
    ret
EngineMem_Free ENDP

; ---------------------------------------------------------------------------
; EngineMem_GetStats - Return allocation statistics
; Output: RAX = total allocated, RDX = total freed, R8 = peak
; ---------------------------------------------------------------------------
EngineMem_GetStats PROC
    mov     rax, [TotalAllocated]
    mov     rdx, [TotalFreed]
    mov     r8,  [PeakAllocated]
    ret
EngineMem_GetStats ENDP

END
