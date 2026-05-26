; ============================================================================
; Sovereign_Heap.asm - Non-Kernel User-Mode Memory Manager
; x64 MASM / Zero Dependencies
; Implementation: High-Performance Bump Allocator with SIMD No-Mans-Land
; ============================================================================

include Sovereign_Common.inc

EXTERN g_ApiTable : SOVEREIGN_API_TABLE
EXTERN g_HeapBase : QWORD
EXTERN g_HeapPtr : QWORD
EXTERN g_HeapLimit : QWORD

.CODE

; ----------------------------------------------------------------------------
; PROCEDURE: Sovereign_Heap_Init
; Logic: Reserves a large contiguous block of memory. 
; Added 64-byte safety margin at the absolute peak of the reserve.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Heap_Init
Sovereign_Heap_Init PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32

    ; VirtualAlloc(NULL, 256MB + 64, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    xor     rcx, rcx
    mov     rdx, 10000040h          ; 256MB + 64 bytes safety
    mov     r8d, 3000h              ; MEM_COMMIT | MEM_RESERVE
    mov     r9d, 04h                ; PAGE_READWRITE
    call    qword ptr [g_ApiTable.pVirtualAlloc]
    
    test    rax, rax
    jz      @@Error

    mov     [g_HeapBase], rax
    mov     [g_HeapPtr], rax
    add     rax, 10000000h          ; Limit is the 256MB mark
    mov     [g_HeapLimit], rax

    mov     rax, 1
    jmp     @@Done

@@Error:
    xor     rax, rax

@@Done:
    add     rsp, 32
    pop     rbp
    ret
Sovereign_Heap_Init ENDP

; ----------------------------------------------------------------------------
; PROCEDURE: Sovereign_Malloc
; Input:  RCX = Size in bytes
; Output: RAX = Pointer to allocated memory
; Logic: Force 64-byte alignment and append 64-byte "No-Mans-Land" padding
; to prevent AVX-512 Page Faults on buffer tails.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Malloc
Sovereign_Malloc PROC
    ; 1. Alignment (force 64-byte boundary for SIMD efficiency)
    add     rcx, 63
    and     rcx, -64

    ; 2. Current Pointer
    mov     rax, [g_HeapPtr]
    mov     rdx, rax
    
    ; 3. Calculate advance (Requested + 64 bytes padding)
    mov     r8, rcx
    add     r8, 64
    add     rdx, r8
    
    ; 4. Bounds Check
    cmp     rdx, [g_HeapLimit]
    ja      @@OutOfMemory

    ; 5. Commit
    mov     [g_HeapPtr], rdx
    ; RAX still contains the original start of the block
    ret

@@OutOfMemory:
    xor     rax, rax
    ret
Sovereign_Malloc ENDP

PUBLIC Sovereign_Heap_Reset
Sovereign_Heap_Reset PROC
    mov     rax, [g_HeapBase]
    mov     [g_HeapPtr], rax
    ret
Sovereign_Heap_Reset ENDP

END
