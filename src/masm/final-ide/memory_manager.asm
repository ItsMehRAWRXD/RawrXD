;==========================================================================
; memory_manager.asm - Complete Memory Management System
;==========================================================================
; Provides heap allocation, deallocation, reallocation, statistics,
; and memory protection tracking for entire application.
;==========================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

EXTERN console_log:PROC
EXTERN OutputDebugStringA:PROC

PUBLIC asm_malloc:PROC
PUBLIC asm_free:PROC
PUBLIC asm_realloc:PROC
PUBLIC asm_calloc:PROC
PUBLIC mem_get_stats:PROC
PUBLIC mem_validate_ptr:PROC
PUBLIC mem_dump_leaks:PROC

;==========================================================================
; MEMORY_BLOCK header structure (16 bytes)
;==========================================================================
MEMORY_BLOCK STRUCT
    signature           DWORD ?      ; 0x4D454D42 = "MEMB"
    size                QWORD ?      ; Allocation size
    flags               DWORD ?      ; Allocation flags
    next_block          QWORD ?      ; Linked list
MEMORY_BLOCK ENDS

;==========================================================================
; MEMORY_STATS structure
;==========================================================================
MEMORY_STATS STRUCT
    total_allocated     QWORD ?      ; Total bytes allocated
    total_freed         QWORD ?      ; Total bytes freed
    current_usage       QWORD ?      ; Currently allocated
    peak_usage          QWORD ?      ; Peak usage ever
    allocation_count    QWORD ?      ; Number of allocations
    free_count          QWORD ?      ; Number of frees
    realloc_count       QWORD ?      ; Number of reallocations
    block_count         QWORD ?      ; Current block count
MEMORY_STATS ENDS

.data

; Memory heap handle (created by VirtualAlloc)
g_heap_start        QWORD 0         ; Start of managed heap
g_heap_end          QWORD 0         ; End of managed heap
g_heap_ptr          QWORD 0         ; Current allocation pointer
g_heap_size         QWORD 64*1024*1024  ; 64 MB default heap

; Block list tracking
g_first_block       QWORD 0         ; First allocated block
g_last_block        QWORD 0         ; Last allocated block

; Statistics
g_mem_stats MEMORY_STATS <0,0,0,0,0,0,0,0>

; Constants
MEMORY_SIGNATURE    EQU 0x4D454D42  ; "MEMB"
HEAP_BLOCK_SIZE     EQU 4096        ; Min block size
MEM_MAGIC           EQU 0xDEADBEEF  ; Fill value for freed memory

; Logging
szMemAllocate       BYTE "[MEM] Allocated %I64d bytes at %p (size=%I64d)", 13, 10, 0
szMemFree           BYTE "[MEM] Freed %p (%I64d bytes)", 13, 10, 0
szMemStats          BYTE "[MEM] Current: %I64d bytes, Peak: %I64d bytes, Blocks: %I64d", 13, 10, 0
szMemError          BYTE "[MEM ERROR] Invalid pointer %p", 13, 10, 0

.code

;==========================================================================
; mem_initialize() - Called once at startup
;==========================================================================
PUBLIC mem_initialize
ALIGN 16
mem_initialize PROC

    push rbx
    sub rsp, 32

    ; Allocate initial heap
    mov rcx, [g_heap_size]
    mov edx, MEM_COMMIT or MEM_RESERVE
    mov r8d, PAGE_READWRITE
    call VirtualAlloc
    
    mov [g_heap_start], rax
    mov [g_heap_ptr], rax
    
    ; Calculate heap end
    mov rax, [g_heap_start]
    add rax, [g_heap_size]
    mov [g_heap_end], rax

    add rsp, 32
    pop rbx
    ret

mem_initialize ENDP

;==========================================================================
; asm_malloc(size: RCX) -> RAX (pointer to allocated memory)
;==========================================================================
PUBLIC asm_malloc
ALIGN 16
asm_malloc PROC

    push rbx
    push rsi
    sub rsp, 32

    ; RCX = requested size
    ; Align to 16-byte boundary for efficiency
    mov rax, rcx
    add rax, 15
    and rax, NOT 15
    mov rsi, rax        ; Aligned size

    ; Add header size (32 bytes: MEMORY_BLOCK + padding)
    add rax, 32

    ; Check heap bounds
    mov rbx, [g_heap_ptr]
    add rbx, rax
    cmp rbx, [g_heap_end]
    jge malloc_out_of_memory

    ; Get current pointer
    mov rbx, [g_heap_ptr]

    ; Write header
    mov DWORD PTR [rbx + MEMORY_BLOCK.signature], MEMORY_SIGNATURE
    mov QWORD PTR [rbx + MEMORY_BLOCK.size], rsi
    mov DWORD PTR [rbx + MEMORY_BLOCK.flags], 0
    mov QWORD PTR [rbx + MEMORY_BLOCK.next_block], 0

    ; Link into block list
    mov rax, [g_last_block]
    test rax, rax
    jz first_block
    
    mov QWORD PTR [rax + MEMORY_BLOCK.next_block], rbx
    jmp link_done

first_block:
    mov [g_first_block], rbx

link_done:
    mov [g_last_block], rbx

    ; Update statistics
    add [g_mem_stats.total_allocated], rsi
    add [g_mem_stats.current_usage], rsi
    inc [g_mem_stats.allocation_count]
    inc [g_mem_stats.block_count]

    ; Check peak
    mov rax, [g_mem_stats.current_usage]
    cmp rax, [g_mem_stats.peak_usage]
    jle peak_ok
    mov [g_mem_stats.peak_usage], rax

peak_ok:
    ; Update heap pointer
    mov rax, [g_heap_ptr]
    add rax, rsi
    add rax, 32
    mov [g_heap_ptr], rax

    ; Return pointer after header
    mov rax, rbx
    add rax, 32
    
    ; Log allocation
    lea rcx, szMemAllocate
    mov rdx, rsi
    mov r8, rax
    mov r9, rsi
    call console_log

    jmp malloc_done

malloc_out_of_memory:
    xor eax, eax        ; Return NULL

malloc_done:
    add rsp, 32
    pop rsi
    pop rbx
    ret

asm_malloc ENDP

;==========================================================================
; asm_free(ptr: RCX) -> EAX (1=success, 0=failure)
;==========================================================================
PUBLIC asm_free
ALIGN 16
asm_free PROC

    push rbx
    push rsi
    sub rsp, 32

    ; RCX = pointer to free
    test rcx, rcx
    jz free_already_null

    ; Get header (32 bytes before)
    mov rax, rcx
    sub rax, 32
    mov rbx, rax

    ; Validate signature
    mov edx, [rbx + MEMORY_BLOCK.signature]
    cmp edx, MEMORY_SIGNATURE
    jne free_invalid_ptr

    ; Get size
    mov rsi, [rbx + MEMORY_BLOCK.size]

    ; Fill with magic pattern
    mov rax, rcx
    mov r8, rsi
    xor r9, r9
fill_loop:
    cmp r9, r8
    jge fill_done
    mov DWORD PTR [rax + r9], MEM_MAGIC
    add r9, 4
    jmp fill_loop

fill_done:
    ; Update statistics
    add [g_mem_stats.total_freed], rsi
    sub [g_mem_stats.current_usage], rsi
    inc [g_mem_stats.free_count]
    dec [g_mem_stats.block_count]

    ; Log free
    lea rcx, szMemFree
    mov rdx, rcx        ; Original ptr
    mov r8, rsi         ; Size
    call console_log

    mov eax, 1          ; Success
    jmp free_done

free_already_null:
    mov eax, 1
    jmp free_done

free_invalid_ptr:
    lea rcx, szMemError
    mov rdx, rcx        ; Invalid ptr
    call console_log
    xor eax, eax

free_done:
    add rsp, 32
    pop rsi
    pop rbx
    ret

asm_free ENDP

;==========================================================================
; asm_calloc(count: RCX, size: RDX) -> RAX (zeroed memory)
;==========================================================================
PUBLIC asm_calloc
ALIGN 16
asm_calloc PROC

    push rbx
    sub rsp, 32

    ; RCX = count, RDX = size
    mov rax, rcx
    imul rax, rdx       ; total = count * size
    
    ; Allocate
    call asm_malloc
    test rax, rax
    jz calloc_fail

    ; Zero the memory
    mov rcx, rax
    mov rdx, [rax - 32 + MEMORY_BLOCK.size]
    xor r8, r8
    xor r9d, r9d

zero_loop:
    cmp r9, rdx
    jge zero_done
    mov QWORD PTR [rcx + r9], 0
    add r9, 8
    jmp zero_loop

zero_done:
    jmp calloc_done

calloc_fail:
    xor eax, eax

calloc_done:
    add rsp, 32
    pop rbx
    ret

asm_calloc ENDP

;==========================================================================
; asm_realloc(ptr: RCX, new_size: RDX) -> RAX
;==========================================================================
PUBLIC asm_realloc
ALIGN 16
asm_realloc PROC

    push rbx
    push rsi
    push rdi
    sub rsp, 32

    ; RCX = ptr, RDX = new_size
    mov rsi, rcx        ; Save old ptr
    mov rdi, rdx        ; Save new size

    ; Allocate new block
    mov rcx, rdi
    call asm_malloc
    test rax, rax
    jz realloc_fail

    ; Copy old data if exists
    test rsi, rsi
    jz realloc_done

    mov rax, rsi
    sub rax, 32
    mov rcx, [rax + MEMORY_BLOCK.size]  ; Old size
    
    ; Copy min(old_size, new_size)
    cmp rcx, rdi
    jle copy_size_ok
    mov rcx, rdi

copy_size_ok:
    mov rdi, rsi        ; src = old ptr
    mov rsi, rax        ; dest = new ptr header
    add rsi, 32
    mov r8, rcx         ; Size

    ; memcpy loop
    xor r9, r9
copy_loop:
    cmp r9, r8
    jge copy_done
    mov al, [rdi + r9]
    mov [rsi + r9], al
    inc r9
    jmp copy_loop

copy_done:
    ; Free old block
    mov rcx, rdi
    call asm_free

    mov rax, rsi        ; Return new ptr
    inc [g_mem_stats.realloc_count]
    jmp realloc_done

realloc_fail:
    xor eax, eax

realloc_done:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret

asm_realloc ENDP

;==========================================================================
; mem_get_stats() -> RAX (pointer to MEMORY_STATS)
;==========================================================================
PUBLIC mem_get_stats
ALIGN 16
mem_get_stats PROC

    lea rax, [g_mem_stats]
    ret

mem_get_stats ENDP

;==========================================================================
; mem_validate_ptr(ptr: RCX) -> EAX (1=valid, 0=invalid)
;==========================================================================
PUBLIC mem_validate_ptr
ALIGN 16
mem_validate_ptr PROC

    test rcx, rcx
    jz validate_null

    ; Check header signature
    mov rax, rcx
    sub rax, 32
    mov edx, [rax + MEMORY_BLOCK.signature]
    cmp edx, MEMORY_SIGNATURE
    je validate_ok

validate_null:
    xor eax, eax
    ret

validate_ok:
    mov eax, 1
    ret

mem_validate_ptr ENDP

;==========================================================================
; mem_dump_leaks() - Log current allocations
;==========================================================================
PUBLIC mem_dump_leaks
ALIGN 16
mem_dump_leaks PROC

    push rbx
    sub rsp, 32

    ; Log stats
    lea rcx, szMemStats
    mov rdx, [g_mem_stats.current_usage]
    mov r8, [g_mem_stats.peak_usage]
    mov r9, [g_mem_stats.block_count]
    call console_log

    add rsp, 32
    pop rbx
    ret

mem_dump_leaks ENDP

END

