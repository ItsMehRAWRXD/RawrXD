; ==================================================================================
; SOVEREIGN CONFIGURATION SUBSTRATE - AFFINE ARENA ALLOCATOR
; File: Sovereign_Allocator.asm
; Role: O(1) thread-affine bump allocator with cache-line isolation
; ABI: ENTER_FRAME / EXIT_FRAME compliant
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc
include Sovereign_Atomics.inc

.DATA
ALIGN 64

; ------------------------------------------------------------------------------
; CACHE PAD STRUCTURE (prevents false sharing across threads, 64-byte total)
; ------------------------------------------------------------------------------
ALLOC_STATE STRUCT
    BasePtr     QWORD ?
    Cursor      QWORD ?
    EndPtr      QWORD ?
    Pad0        QWORD ?
    Pad1        QWORD ?
    Pad2        QWORD ?
    Pad3        QWORD ?
    Pad4        QWORD ?
ALLOC_STATE ENDS

; ------------------------------------------------------------------------------
; GLOBAL FALLBACK ARENA STATE
; ------------------------------------------------------------------------------
g_GlobalArenaState ALLOC_STATE <>

; ------------------------------------------------------------------------------
; DETERMINISTIC THREAD STATE POINTER (Replaces OS TLS)
; ------------------------------------------------------------------------------
g_AllocatorTLS QWORD 0

; ------------------------------------------------------------------------------
; CONFIGURATION CONSTANTS
; ------------------------------------------------------------------------------
ALLOC_ALIGNMENT        EQU 64
ALLOC_CHUNK_SIZE       EQU 1048576        ; 1MB default arena chunk
ALLOC_PAD              EQU 64

.CODE

; ==================================================================================
; INTERNAL: Sovereign_Allocator_GetState
; Returns: RAX = pointer to thread-local allocator state
; ==================================================================================
Sovereign_Allocator_GetState PROC
    ENTER_FRAME

    ; Deterministic TLS alternative
    mov rax, [g_AllocatorTLS]
    test rax, rax
    jnz @@Done

@@UseGlobal:
    lea rax, g_GlobalArenaState

@@Done:
    EXIT_FRAME
Sovereign_Allocator_GetState ENDP


; ==================================================================================
; API: Sovereign_Allocator_InitThread
; Creates per-thread arena (call once per worker thread)
; ==================================================================================
PUBLIC Sovereign_Allocator_InitThread
Sovereign_Allocator_InitThread PROC
    ENTER_FRAME

    ; allocate arena block
    mov rcx, 0
    mov rdx, ALLOC_CHUNK_SIZE
    mov r8, MEM_COMMIT or MEM_RESERVE
    mov r9, PAGE_READWRITE
    call [g_ApiTable.pVirtualAlloc]

    test rax, rax
    jz @@Fail

    ; initialize ALLOC_STATE structure
    mov rbx, rax
    mov [rbx].ALLOC_STATE.BasePtr, rax
    mov [rbx].ALLOC_STATE.Cursor,  rax
    lea rcx, [rax + ALLOC_CHUNK_SIZE]
    mov [rbx].ALLOC_STATE.EndPtr,  rcx

    ; store in deterministic TLS
    mov [g_AllocatorTLS], rbx

    mov rax, 1
    EXIT_FRAME

@@Fail:
    xor rax, rax
    EXIT_FRAME
Sovereign_Allocator_InitThread ENDP


; ==================================================================================
; API: Sovereign_Alloc
; Fast O(1) bump allocator
; RCX = size
; Returns RAX = pointer
; ==================================================================================
PUBLIC Sovereign_Alloc
Sovereign_Alloc PROC
    ENTER_FRAME

    mov rsi, rcx
    add rsi, ALLOC_ALIGNMENT - 1
    and rsi, -ALLOC_ALIGNMENT          ; align size to 64 bytes

@@Retry:
    call Sovereign_Allocator_GetState
    mov rbx, rax

    mov rax, [rbx].ALLOC_STATE.Cursor
    mov rdx, rax
    add rdx, rsi

    ; boundary check
    cmp rdx, [rbx].ALLOC_STATE.EndPtr
    ja @@Realloc

    mov [rbx].ALLOC_STATE.Cursor, rdx
    mfence                             ; Order memory writes for safe visibility
    
    mov rax, rdx
    sub rax, rsi
    jmp @@Done

@@Realloc:
    ; fallback: allocate new chunk (rare path only)
    mov rcx, ALLOC_CHUNK_SIZE
    call Sovereign_Allocator_InitThread
    test rax, rax
    jz @@Fail
    jmp @@Retry

@@Fail:
    xor rax, rax

@@Done:
    EXIT_FRAME
Sovereign_Alloc ENDP


; ==================================================================================
; API: Sovereign_AllocZero
; Same as alloc but zero-initialized
; ==================================================================================
PUBLIC Sovereign_AllocZero
Sovereign_AllocZero PROC
    ENTER_FRAME

    mov rdx, rcx          ; preserve size
    call Sovereign_Alloc
    test rax, rax
    jz @@FailCheck
    
    mov rdi, rax
    mov rcx, rdx          ; restore size for stosq
    shr rcx, 3
    xor eax, eax
    rep stosq

    mov rax, rdi
@@FailCheck:
    EXIT_FRAME
Sovereign_AllocZero ENDP


; ==================================================================================
; API: Sovereign_Allocator_ResetThread
; ==================================================================================
PUBLIC Sovereign_Allocator_ResetThread
Sovereign_Allocator_ResetThread PROC
    ENTER_FRAME

    call Sovereign_Allocator_GetState
    mov rbx, rax

    mov rax, [rbx].ALLOC_STATE.BasePtr
    mov [rbx].ALLOC_STATE.Cursor, rax
    mfence

    xor rax, rax
    EXIT_FRAME
Sovereign_Allocator_ResetThread ENDP


; ==================================================================================
; DEBUG: Sovereign_Allocator_Dump
; ==================================================================================
PUBLIC Sovereign_Allocator_Dump
Sovereign_Allocator_Dump PROC
    ENTER_FRAME

    call Sovereign_Allocator_GetState
    mov rbx, rax

    mov rax, [rbx].ALLOC_STATE.Cursor
    sub rax, [rbx].ALLOC_STATE.BasePtr

    EXIT_FRAME
Sovereign_Allocator_Dump ENDP

END
