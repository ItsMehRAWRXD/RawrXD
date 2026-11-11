; ============================================================================
; memory.asm - x64 MASM Memory Allocator Stub
; ============================================================================
; Minimal implementation for editor pipeline integration.
; Provides heap allocation with metadata tracking.
; ============================================================================

option casemap:none

.data

; Global statistics
g_total_allocations QWORD 0
g_total_bytes       QWORD 0
g_alloc_count       QWORD 0
g_magic_failed      QWORD 0
g_process_heap_handle QWORD 0

; Logging strings
szMallocStart       BYTE "Memory allocation starting.", 0
szMallocSuccess     BYTE "Memory allocation successful.", 0
szMallocFailed      BYTE "Memory allocation failed.", 0

.code

; External Win32 APIs
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN HeapReAlloc:PROC

; ============================================================================
; asm_malloc
; ============================================================================
; Allocates memory with specified alignment.
;
; Parameters:
;   RCX = size (bytes)
;   RDX = alignment (bytes, must be power of 2)
; Returns:
;   RAX = pointer to allocated memory (NULL on failure)
; ============================================================================

ALIGN 16
asm_malloc PROC
    
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 40
    
    mov     rbx, rcx            ; Save size
    mov     rsi, rdx            ; Save alignment
    
    ; Validate parameters
    test    rbx, rbx
    jz      L_fail              ; size == 0 -> fail
    
    ; Default alignment to 16 if < 16
    cmp     rsi, 16
    jae     L_align_ok
    mov     rsi, 16
    
L_align_ok:
    ; Get process heap
    call    GetProcessHeap
    mov     rdi, rax            ; Save heap handle
    mov     [g_process_heap_handle], rax
    
    ; Calculate total size (size + alignment padding + metadata)
    mov     rcx, rbx            ; size
    add     rcx, rsi            ; + alignment
    add     rcx, 64             ; + metadata (64 bytes)
    
    ; Allocate from heap
    xor     rdx, rdx            ; Flags = 0
    call    HeapAlloc
    
    test    rax, rax
    jz      L_fail
    
    ; Align pointer (skip metadata space)
    mov     rcx, rax
    add     rcx, 64             ; Skip metadata
    add     rcx, rsi
    dec     rcx                 ; rcx = ptr + 64 + align - 1
    and     rcx, -16            ; Align to 16 bytes minimum
    
    ; Store metadata (at ptr - 64)
    mov     rdx, rcx
    sub     rdx, 64             ; Metadata location
    
    ; Magic marker (split into two 32-bit values for MASM compatibility)
    mov     dword ptr [rdx + 0], 0CAFEBABEh     ; Low 32 bits
    mov     dword ptr [rdx + 4], 0DEADBEEFh     ; High 32 bits
    mov     qword ptr [rdx + 8], rsi              ; Alignment
    mov     qword ptr [rdx + 16], rbx            ; Requested size
    mov     qword ptr [rdx + 24], rcx            ; Total allocated
    
    ; Update statistics
    lock inc qword ptr [g_total_allocations]
    lock add qword ptr [g_total_bytes], rbx
    lock inc qword ptr [g_alloc_count]
    
    ; Return aligned pointer
    mov     rax, rcx
    jmp     L_done
    
L_fail:
    xor     rax, rax
    
L_done:
    add     rsp, 40
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

asm_malloc ENDP

; ============================================================================
; asm_free
; ============================================================================
; Frees memory allocated by asm_malloc.
;
; Parameters:
;   RCX = pointer to free
; Returns: None
; ============================================================================

ALIGN 16
asm_free PROC
    
    push    rbx
    sub     rsp, 32
    
    mov     rbx, rcx            ; Save pointer
    
    ; Validate pointer
    test    rbx, rbx
    jz      L_done
    
    ; Get metadata location
    sub     rbx, 64
    
    ; Validate magic marker
    mov     eax, dword ptr [rbx + 0]
    cmp     eax, 0CAFEBABEh
    jne     L_invalid
    mov     eax, dword ptr [rbx + 4]
    cmp     eax, 0DEADBEEFh
    jne     L_invalid
    
    ; Get heap handle
    mov     rcx, [g_process_heap_handle]
    test    rcx, rcx
    jz      L_done
    
    ; Free memory
    xor     rdx, rdx            ; Flags = 0
    mov     r8, rbx             ; Pointer
    call    HeapFree
    
    ; Update statistics
    lock dec qword ptr [g_alloc_count]
    
    jmp     L_done
    
L_invalid:
    lock inc qword ptr [g_magic_failed]
    
L_done:
    add     rsp, 32
    pop     rbx
    ret

asm_free ENDP

; ============================================================================
; asm_realloc
; ============================================================================
; Reallocates memory.
;
; Parameters:
;   RCX = pointer to reallocate
;   RDX = new size
; Returns:
;   RAX = new pointer (NULL on failure)
; ============================================================================

ALIGN 16
asm_realloc PROC
    
    push    rbx
    push    rsi
    sub     rsp, 32
    
    mov     rbx, rcx            ; Save old pointer
    mov     rsi, rdx            ; Save new size
    
    ; Validate
    test    rsi, rsi
    jz      L_fail
    
    ; Allocate new block
    mov     rcx, rsi
    mov     rdx, 16             ; Default alignment
    call    asm_malloc
    
    test    rax, rax
    jz      L_fail
    
    ; If old pointer exists, copy data
    test    rbx, rbx
    jz      L_done
    
    ; Get old size from metadata
    mov     r8, rbx
    sub     r8, 64
    mov     r9, [r8 + 16]       ; Old size
    
    ; Copy min(old_size, new_size)
    cmp     r9, rsi
    jbe     L_copy_old
    mov     r9, rsi             ; Use new size if smaller
    
L_copy_old:
    ; Copy memory
    mov     rdi, rax            ; Destination
    mov     rsi, rbx             ; Source
    mov     rcx, r9              ; Count
    rep     movsb
    
    ; Free old block
    mov     rcx, rbx
    call    asm_free
    
    jmp     L_done
    
L_fail:
    xor     rax, rax
    
L_done:
    add     rsp, 32
    pop     rsi
    pop     rbx
    ret

asm_realloc ENDP

; ============================================================================
; asm_memcpy
; ============================================================================
; Fast memory copy.
;
; Parameters:
;   RCX = destination
;   RDX = source
;   R8  = count
; Returns:
;   RAX = destination
; ============================================================================

ALIGN 16
asm_memcpy PROC
    
    mov     rax, rcx            ; Save destination
    mov     r9, rcx             ; Destination
    mov     r10, rdx            ; Source
    mov     r11, r8             ; Count
    
    ; Copy in 8-byte chunks
    shr     r11, 3              ; Count / 8
    jz      L_copy_bytes
    
L_copy_qwords:
    mov     rax, [r10]
    mov     [r9], rax
    add     r9, 8
    add     r10, 8
    dec     r11
    jnz     L_copy_qwords
    
L_copy_bytes:
    ; Copy remaining bytes
    and     r8, 7               ; Count % 8
    jz      L_done
    
    mov     rcx, r8
    rep     movsb
    
L_done:
    mov     rax, rcx
    ret

asm_memcpy ENDP

; ============================================================================
; asm_get_process_heap
; ============================================================================
; Returns the process heap handle.
;
; Parameters: None
; Returns: RAX = heap handle
; ============================================================================

ALIGN 16
asm_get_process_heap PROC
    
    call    GetProcessHeap
    mov     [g_process_heap_handle], rax
    ret

asm_get_process_heap ENDP

; ============================================================================
; asm_heap_alloc
; ============================================================================
; Direct heap allocation (no metadata).
;
; Parameters:
;   RCX = heap handle
;   RDX = flags
;   R8  = size
; Returns:
;   RAX = pointer
; ============================================================================

ALIGN 16
asm_heap_alloc PROC
    
    ; RCX = heap, RDX = flags, R8 = size
    ; HeapAlloc signature: HeapAlloc(heap, flags, size)
    call    HeapAlloc
    ret

asm_heap_alloc ENDP

; ============================================================================
; asm_heap_free
; ============================================================================
; Direct heap free.
;
; Parameters:
;   RCX = heap handle
;   RDX = flags
;   R8  = pointer
; Returns:
;   RAX = 1 on success, 0 on failure
; ============================================================================

ALIGN 16
asm_heap_free PROC
    
    ; RCX = heap, RDX = flags, R8 = pointer
    ; HeapFree signature: HeapFree(heap, flags, pointer)
    call    HeapFree
    ret

asm_heap_free ENDP

; ============================================================================
; asm_memory_stats
; ============================================================================
; Returns memory statistics.
;
; Parameters: None
; Returns:
;   RAX = total allocations
;   RCX = total bytes
;   RDX = current count
;   R8  = magic failures
; ============================================================================

ALIGN 16
asm_memory_stats PROC
    
    mov     rax, [g_total_allocations]
    mov     rcx, [g_total_bytes]
    mov     rdx, [g_alloc_count]
    mov     r8, [g_magic_failed]
    ret

asm_memory_stats ENDP

; ============================================================================
; Exported symbols
; ============================================================================

PUBLIC asm_malloc
PUBLIC asm_free
PUBLIC asm_realloc
PUBLIC asm_memcpy
PUBLIC asm_get_process_heap
PUBLIC asm_heap_alloc
PUBLIC asm_heap_free
PUBLIC asm_memory_stats

END
