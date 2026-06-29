; ============================================================================
; KV-Cache Arena Implementation - RawrXD Inference Engine
; ============================================================================
; Fixed-buffer arena for zero-allocation KV-cache operations
; Optimized for latency: pre-allocated, page-locked, cache-aligned
;
; Architecture: x86-64 (AMD64)
; Calling Convention: Windows x64 (RCX, RDX, R8, R9)
; SIMD: AVX-512 for cache line operations
; ============================================================================

; ----------------------------------------------------------------------------
; STRUCTURE DEFINITIONS
; ----------------------------------------------------------------------------

; KV_Cache_Arena - Fixed buffer descriptor
KV_Cache_Arena STRUCT
    buffer_ptr      QWORD   ?       ; Pointer to pre-allocated memory
    current_size    DWORD   ?       ; Current token count
    max_tokens      DWORD   ?       ; Maximum capacity
    head_dim        DWORD   ?       ; Dimension per head
    num_heads       DWORD   ?       ; Number of attention heads
    stride          DWORD   ?       ; Bytes per token (K + V)
    flags           DWORD   ?       ; Status flags
    reserved        DWORD   ?       ; Padding to 64-byte alignment
KV_Cache_Arena ENDS

; KV_Cache_Slot - Individual token storage
KV_Cache_Slot STRUCT
    key_data        BYTE    0 DUP (?)   ; Key tensor data (head_dim * num_heads)
    value_data      BYTE    0 DUP (?)   ; Value tensor data (head_dim * num_heads)
KV_Cache_Slot ENDS

; ----------------------------------------------------------------------------
; CONSTANTS
; ----------------------------------------------------------------------------

CACHE_LINE_SIZE     EQU     64
PAGE_SIZE           EQU     4096
AVX512_REG_BYTES    EQU     64

; Flags
KV_FLAG_PINNED        EQU     1       ; Memory is VirtualLock'd
KV_FLAG_GPU_MAPPED    EQU     2       ; Memory mapped to GPU
KV_FLAG_DIRTY        EQU     4       ; Cache needs flush

; ----------------------------------------------------------------------------
; DATA SECTION
; ----------------------------------------------------------------------------

.data
    ; Global arena registry (supports up to 8 concurrent contexts)
    KV_Arena_Registry   QWORD   8 DUP (0)
    KV_Arena_Count      DWORD   0
    
    ; Alignment padding for cache line separation
    ALIGN CACHE_LINE_SIZE

; ----------------------------------------------------------------------------
; CODE SECTION
; ----------------------------------------------------------------------------

.code

; ============================================================================
; PUBLIC INTERFACE
; ============================================================================

; ----------------------------------------------------------------------------
; KVCache_Arena_Create
; 
; Description:
;   Creates a fixed-size KV-cache arena with pre-allocated memory
;
; Parameters (Windows x64):
;   RCX = max_tokens (DWORD)
;   RDX = head_dim (DWORD)  
;   R8  = num_heads (DWORD)
;
; Returns:
;   RAX = Pointer to KV_Cache_Arena (NULL on failure)
;
; C++ Equivalent:
;   KV_Cache_Arena* KVCache_Arena_Create(uint32_t max_tokens, 
;                                      uint32_t head_dim, 
;                                      uint32_t num_heads);
; ----------------------------------------------------------------------------
KVCache_Arena_Create PROC FRAME
    ; Save non-volatile registers
    push    rbx
    push    rdi
    push    rsi
    .pushreg rbx
    .pushreg rdi
    .pushreg rsi
    
    ; Allocate stack space for local variables
    sub     rsp, 64
    .allocstack 64
    
    .endprolog
    
    ; Store parameters
    mov     ebx, ecx            ; max_tokens
    mov     esi, edx            ; head_dim
    mov     edi, r8d            ; num_heads
    
    ; Calculate stride: (head_dim * num_heads * 2) * sizeof(float)
    ; Key + Value = 2x, float = 4 bytes
    mov     eax, esi            ; head_dim
    imul    eax, edi            ; * num_heads
    shl     eax, 1              ; * 2 (K + V)
    shl     eax, 2              ; * 4 (sizeof(float))
    mov     r12d, eax           ; Save stride
    
    ; Calculate total size: max_tokens * stride
    ; Align to page boundary for VirtualLock
    mov     eax, ebx            ; max_tokens
    imul    rax, r12            ; * stride
    add     rax, PAGE_SIZE - 1  ; Round up
    and     rax, NOT (PAGE_SIZE - 1)  ; Align to page
    mov     r13, rax            ; Save total size
    
    ; Allocate arena descriptor
    mov     ecx, SIZEOF KV_Cache_Arena
    call    malloc              ; C runtime malloc
    test    rax, rax
    jz      .create_failed
    mov     r14, rax            ; Save arena pointer
    
    ; Allocate fixed buffer with page alignment
    mov     rcx, r13            ; Size
    mov     edx, PAGE_SIZE      ; Alignment
    call    aligned_malloc      ; Custom aligned allocator
    test    rax, rax
    jz      .alloc_failed
    mov     r15, rax            ; Save buffer pointer
    
    ; Initialize arena structure
    mov     [r14].KV_Cache_Arena.buffer_ptr, r15
    mov     [r14].KV_Cache_Arena.current_size, 0
    mov     [r14].KV_Cache_Arena.max_tokens, ebx
    mov     [r14].KV_Cache_Arena.head_dim, esi
    mov     [r14].KV_Cache_Arena.num_heads, edi
    mov     [r14].KV_Cache_Arena.stride, r12d
    mov     [r14].KV_Cache_Arena.flags, 0
    
    ; Zero-initialize the buffer (prevents page faults during first access)
    mov     rdi, r15            ; Destination
    mov     rcx, r13            ; Size
    shr     rcx, 3            ; Convert to QWORDs
    xor     eax, eax
    rep     stosq
    
    ; Return arena pointer
    mov     rax, r14
    jmp     .create_done
    
.alloc_failed:
    ; Free arena descriptor
    mov     rcx, r14
    call    free
    
.create_failed:
    xor     rax, rax            ; Return NULL
    
.create_done:
    ; Restore stack and registers
    add     rsp, 64
    pop     rsi
    pop     rdi
    pop     rbx
    ret

KVCache_Arena_Create ENDP

; ----------------------------------------------------------------------------
; KVCache_Arena_Pin
;
; Description:
;   Locks the KV-cache pages in physical memory using VirtualLock
;   Prevents OS from swapping during critical inference loops
;
; Parameters:
;   RCX = Arena pointer
;
; Returns:
;   RAX = 1 on success, 0 on failure
; ----------------------------------------------------------------------------
KVCache_Arena_Pin PROC FRAME
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    mov     rbx, rcx            ; Save arena pointer
    
    ; Get buffer pointer and size
    mov     rcx, [rbx].KV_Cache_Arena.buffer_ptr
    mov     edx, [rbx].KV_Cache_Arena.max_tokens
    imul    edx, [rbx].KV_Cache_Arena.stride
    
    ; Align size to page boundary
    add     rdx, PAGE_SIZE - 1
    and     rdx, NOT (PAGE_SIZE - 1)
    
    ; Call VirtualLock
    ; BOOL VirtualLock(LPVOID lpAddress, SIZE_T dwSize);
    sub     rsp, 32             ; Shadow space
    call    VirtualLock
    add     rsp, 32
    
    test    rax, rax
    jz      .pin_failed
    
    ; Set pinned flag
    or      [rbx].KV_Cache_Arena.flags, KV_FLAG_PINNED
    mov     rax, 1              ; Success
    jmp     .pin_done
    
. pin_failed:
    xor     rax, rax            ; Failure
    
.pin_done:
    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    ret

KVCache_Arena_Pin ENDP

; ----------------------------------------------------------------------------
; KVCache_Arena_Write
;
; Description:
;   Writes a token's K/V data to the cache (zero-allocation)
;
; Parameters:
;   RCX = Arena pointer
;   RDX = Token index
;   R8  = Key data pointer (head_dim * num_heads floats)
;   R9  = Value data pointer (head_dim * num_heads floats)
;
; Returns:
;   RAX = 1 on success, 0 on failure
; ----------------------------------------------------------------------------
KVCache_Arena_Write PROC FRAME
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    mov     rbx, rcx            ; Arena
    mov     r12, rdx            ; Token index
    mov     r13, r8             ; Key data
    mov     rsi, r9             ; Value data
    
    ; Bounds check
    cmp     r12d, [rbx].KV_Cache_Arena.max_tokens
    jae     .write_failed
    
    ; Calculate slot offset: token_index * stride
    mov     eax, r12d
    imul    rax, [rbx].KV_Cache_Arena.stride
    
    ; Get buffer base
    mov     rdi, [rbx].KV_Cache_Arena.buffer_ptr
    add     rdi, rax            ; Destination = base + offset
    
    ; Calculate copy size: head_dim * num_heads * sizeof(float)
    mov     eax, [rbx].KV_Cache_Arena.head_dim
    imul    eax, [rbx].KV_Cache_Arena.num_heads
    shl     eax, 2              ; * 4 bytes
    mov     r8d, eax            ; Save size
    
    ; Copy Key data using AVX-512
    mov     rcx, r8             ; Size
    shr     rcx, 6              ; / 64 (AVX-512 registers)
    jz      .key_copy_remainder
    
.key_copy_loop:
    vmovdqu64 zmm0, [r13]       ; Load from source
    vmovdqu64 [rdi], zmm0       ; Store to destination
    add     r13, 64
    add     rdi, 64
    dec     rcx
    jnz     .key_copy_loop
    
.key_copy_remainder:
    ; Handle remaining bytes (< 64)
    mov     rcx, r8
    and     rcx, 63             ; Remainder
    jz      .key_done
    rep     movsb
    
.key_done:
    ; Copy Value data (same pattern)
    mov     rdi, [rbx].KV_Cache_Arena.buffer_ptr
    mov     eax, r12d
    imul    rax, [rbx].KV_Cache_Arena.stride
    add     rdi, rax
    add     rdi, r8             ; Offset to value section
    
    ; Copy Value using AVX-512
    mov     rcx, r8
    shr     rcx, 6
    jz      .value_copy_remainder
    
.value_copy_loop:
    vmovdqu64 zmm0, [rsi]
    vmovdqu64 [rdi], zmm0
    add     rsi, 64
    add     rdi, 64
    dec     rcx
    jnz     .value_copy_loop
    
.value_copy_remainder:
    mov     rcx, r8
    and     rcx, 63
    jz      .value_done
    rep     movsb
    
.value_done:
    ; Update current size if this is a new token
    mov     eax, [rbx].KV_Cache_Arena.current_size
    cmp     r12d, eax
    jbe     .write_success
    mov     [rbx].KV_Cache_Arena.current_size, r12d
    inc     [rbx].KV_Cache_Arena.current_size
    
.write_success:
    mov     rax, 1
    jmp     .write_done
    
.write_failed:
    xor     rax, rax
    
.write_done:
    vzeroupper                  ; Required after AVX-512
    add     rsp, 40
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

KVCache_Arena_Write ENDP

; ----------------------------------------------------------------------------
; KVCache_Arena_Read
;
; Description:
;   Reads K/V data for a specific token (zero-allocation)
;
; Parameters:
;   RCX = Arena pointer
;   RDX = Token index
;   R8  = Output key buffer
;   R9  = Output value buffer
;
; Returns:
;   RAX = 1 on success, 0 on failure
; ----------------------------------------------------------------------------
KVCache_Arena_Read PROC FRAME
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    mov     rbx, rcx            ; Arena
    mov     r12, rdx            ; Token index
    mov     rdi, r8             ; Output key
    mov     rsi, r9             ; Output value
    
    ; Bounds check
    cmp     r12d, [rbx].KV_Cache_Arena.current_size
    jae     .read_failed
    
    ; Calculate slot offset
    mov     eax, r12d
    imul    rax, [rbx].KV_Cache_Arena.stride
    
    ; Get source pointer
    mov     r13, [rbx].KV_Cache_Arena.buffer_ptr
    add     r13, rax
    
    ; Calculate copy size
    mov     eax, [rbx].KV_Cache_Arena.head_dim
    imul    eax, [rbx].KV_Cache_Arena.num_heads
    shl     eax, 2
    mov     r8d, eax
    
    ; Prefetch next slot (latency optimization)
    prefetcht0 [r13 + 512]
    
    ; Copy Key data using AVX-512
    mov     rcx, r8
    shr     rcx, 6
    jz      .key_read_remainder
    
.key_read_loop:
    vmovdqu64 zmm0, [r13]
    vmovdqu64 [rdi], zmm0
    add     r13, 64
    add     rdi, 64
    dec     rcx
    jnz     .key_read_loop
    
.key_read_remainder:
    mov     rcx, r8
    and     rcx, 63
    jz      .key_read_done
    rep     movsb
    
.key_read_done:
    ; Copy Value data
    mov     r13, [rbx].KV_Cache_Arena.buffer_ptr
    mov     eax, r12d
    imul    rax, [rbx].KV_Cache_Arena.stride
    add     r13, rax
    add     r13, r8             ; Offset to value
    
    mov     rcx, r8
    shr     rcx, 6
    jz      .value_read_remainder
    
.value_read_loop:
    vmovdqu64 zmm0, [r13]
    vmovdqu64 [rsi], zmm0
    add     r13, 64
    add     rsi, 64
    dec     rcx
    jnz     .value_read_loop
    
.value_read_remainder:
    mov     rcx, r8
    and     rcx, 63
    jz      .value_read_done
    rep     movsb
    
.value_read_done:
    mov     rax, 1
    jmp     .read_done
    
.read_failed:
    xor     rax, rax
    
.read_done:
    vzeroupper
    add     rsp, 40
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

KVCache_Arena_Read ENDP

; ----------------------------------------------------------------------------
; KVCache_Arena_Clear
;
; Description:
;   Resets the cache without deallocating (fast reset for new context)
;
; Parameters:
;   RCX = Arena pointer
; ----------------------------------------------------------------------------
KVCache_Arena_Clear PROC FRAME
    .pushreg rbx
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    mov     rbx, rcx
    mov     [rbx].KV_Cache_Arena.current_size, 0
    
    ; Optionally zero the buffer (commented for speed)
    ; mov     rdi, [rbx].KV_Cache_Arena.buffer_ptr
    ; mov     rcx, [rbx].KV_Cache_Arena.max_tokens
    ; imul    rcx, [rbx].KV_Cache_Arena.stride
    ; shr     rcx, 3
    ; xor     eax, eax
    ; rep     stosq
    
    add     rsp, 40
    pop     rbx
    ret

KVCache_Arena_Clear ENDP

; ----------------------------------------------------------------------------
; KVCache_Arena_Destroy
;
; Description:
;   Frees the arena and its buffer
;
; Parameters:
;   RCX = Arena pointer
; ----------------------------------------------------------------------------
KVCache_Arena_Destroy PROC FRAME
    .pushreg rbx
    .pushreg rsi
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    mov     rbx, rcx
    
    ; Check if pinned
    test    [rbx].KV_Cache_Arena.flags, KV_FLAG_PINNED
    jz      .not_pinned
    
    ; Unlock pages
    mov     rcx, [rbx].KV_Cache_Arena.buffer_ptr
    mov     edx, [rbx].KV_Cache_Arena.max_tokens
    imul    edx, [rbx].KV_Cache_Arena.stride
    add     rdx, PAGE_SIZE - 1
    and     rdx, NOT (PAGE_SIZE - 1)
    sub     rsp, 32
    call    VirtualUnlock
    add     rsp, 32
    
.not_pinned:
    ; Free buffer
    mov     rcx, [rbx].KV_Cache_Arena.buffer_ptr
    call    aligned_free
    
    ; Free arena
    mov     rcx, rbx
    call    free
    
    add     rsp, 40
    pop     rsi
    pop     rbx
    ret

KVCache_Arena_Destroy ENDP

; ============================================================================
; C BRIDGE FUNCTIONS (extern "C")
; ============================================================================

; Export symbols for C++ linkage
PUBLIC KVCache_Arena_Create
PUBLIC KVCache_Arena_Pin
PUBLIC KVCache_Arena_Write
PUBLIC KVCache_Arena_Read
PUBLIC KVCache_Arena_Clear
PUBLIC KVCache_Arena_Destroy

; External imports
EXTRN malloc:PROC
EXTRN free:PROC
EXTRN VirtualLock:PROC
EXTRN VirtualUnlock:PROC
EXTRN aligned_malloc:PROC
EXTRN aligned_free:PROC

END
