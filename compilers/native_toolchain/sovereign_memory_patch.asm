; sovereign_memory_patch.asm - Fixed heap implementation for Sovereign Engine
; This patch replaces the problematic custom heap with Windows process heap
; Build: ml64 /c sovereign_memory_patch.asm

include \masm64\macros\macros.asm

option casemap:none
option win64:3

; =============================================================================
; CONSTANTS
; =============================================================================

HEAP_ZERO_MEMORY    EQU     000000008h

; =============================================================================
; DATA SECTION
; =============================================================================

.data
    ; Global heap handle
    ; NULL = not initialized
    ; Non-NULL = process heap or custom heap
    g_heap              QWORD   0
    
    ; Flag to track if we own the heap (need to destroy)
    g_heap_owned        BYTE    0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; Heap_Init - Initialize heap subsystem
; Uses process heap by default (most reliable)
; Falls back to custom heap only if process heap unavailable
; Returns: RAX = 0 on success, non-zero on failure
; =============================================================================
Heap_Init PROC FRAME
    push rbx
    push rsi
    push rdi
    .allocstack 24
    .endprolog
    
    ; Check if already initialized
    mov rax, g_heap
    test rax, rax
    jnz already_initialized
    
    ; Try process heap first (always available, already initialized)
    call GetProcessHeap
    mov g_heap, rax
    test rax, rax
    jz try_custom_heap
    
    ; Using process heap - we don't own it
    mov g_heap_owned, 0
    jmp success
    
try_custom_heap:
    ; Process heap failed, try creating custom heap
    xor ecx, ecx                ; flOptions = 0
    mov edx, 1024 * 1024       ; dwInitialSize = 1MB
    xor r8d, r8d               ; dwMaximumSize = 0 (growable)
    call HeapCreate
    mov g_heap, rax
    test rax, rax
    jz failure
    
    ; Using custom heap - we own it
    mov g_heap_owned, 1
    
success:
    xor eax, eax                ; Return 0 (success)
    jmp done
    
already_initialized:
    xor eax, eax                ; Already initialized = success
    jmp done
    
failure:
    mov eax, 1                  ; Return 1 (failure)
    
done:
    pop rdi
    pop rsi
    pop rbx
    ret
Heap_Init ENDP

; =============================================================================
; Heap_Alloc - Allocate memory from heap
; RCX = size in bytes
; Returns: RAX = pointer to allocated memory, or NULL on failure
; =============================================================================
Heap_Alloc PROC FRAME
    push rbx
    push rsi
    push rdi
    mov rbx, rcx                ; Save size
    .allocstack 24
    .endprolog
    
    ; Ensure heap is initialized
    mov rax, g_heap
    test rax, rax
    jnz do_alloc
    
    ; Initialize heap
    call Heap_Init
    test eax, eax
    jnz alloc_failed
    
    ; Re-check heap
    mov rax, g_heap
    test rax, rax
    jz alloc_failed
    
do_alloc:
    ; Allocate with zero initialization
    mov rcx, g_heap             ; hHeap
    mov edx, HEAP_ZERO_MEMORY   ; dwFlags
    mov r8, rbx                 ; dwBytes
    call HeapAlloc
    
    ; RAX now contains pointer or NULL
    jmp done
    
alloc_failed:
    xor eax, eax                ; Return NULL
    
done:
    pop rdi
    pop rsi
    pop rbx
    ret
Heap_Alloc ENDP

; =============================================================================
; Heap_Realloc - Reallocate memory
; RCX = original pointer (can be NULL)
; RDX = new size
; Returns: RAX = new pointer, or NULL on failure
; =============================================================================
Heap_Realloc PROC FRAME
    push rbx
    push rsi
    push rdi
    mov rbx, rcx                ; Save original pointer
    mov rsi, rdx                ; Save new size
    .allocstack 24
    .endprolog
    
    ; Ensure heap is initialized
    mov rax, g_heap
    test rax, rax
    jnz do_realloc
    
    ; Initialize heap
    call Heap_Init
    test eax, eax
    jnz realloc_failed
    
do_realloc:
    ; Reallocate
    mov rcx, g_heap             ; hHeap
    xor edx, edx                ; dwFlags = 0
    mov r8, rbx                 ; lpMem (original pointer)
    mov r9, rsi                 ; dwBytes (new size)
    call HeapReAlloc
    
    ; RAX now contains new pointer or NULL
    jmp done
    
realloc_failed:
    xor eax, eax                ; Return NULL
    
done:
    pop rdi
    pop rsi
    pop rbx
    ret
Heap_Realloc ENDP

; =============================================================================
; Heap_Free - Free allocated memory
; RCX = pointer to free (can be NULL)
; Returns: RAX = 1 on success, 0 on failure
; =============================================================================
Heap_Free PROC FRAME
    push rbx
    mov rbx, rcx                ; Save pointer
    .allocstack 8
    .endprolog
    
    ; Check for NULL pointer
    test rbx, rbx
    jz success                  ; Freeing NULL is success
    
    ; Check if heap is initialized
    mov rax, g_heap
    test rax, rax
    jz failure
    
    ; Free the memory
    mov rcx, g_heap             ; hHeap
    xor edx, edx                ; dwFlags = 0
    mov r8, rbx                 ; lpMem
    call HeapFree
    
    ; RAX contains result (non-zero = success)
    test rax, rax
    jz failure
    
success:
    mov eax, 1                  ; Return 1 (success)
    jmp done
    
failure:
    xor eax, eax                ; Return 0 (failure)
    
done:
    pop rbx
    ret
Heap_Free ENDP

; =============================================================================
; Heap_Size - Get size of allocated block
; RCX = pointer
; Returns: RAX = size in bytes, or 0 on failure
; =============================================================================
Heap_Size PROC FRAME
    push rbx
    mov rbx, rcx                ; Save pointer
    .allocstack 8
    .endprolog
    
    ; Check for NULL
    test rbx, rbx
    jz failure
    
    ; Check if heap is initialized
    mov rax, g_heap
    test rax, rax
    jz failure
    
    ; Get size
    mov rcx, g_heap             ; hHeap
    xor edx, edx                ; dwFlags = 0
    mov r8, rbx                 ; lpMem
    call HeapSize
    
    ; RAX contains size or -1 on failure
    cmp rax, -1
    je failure
    jmp done
    
failure:
    xor eax, eax                ; Return 0
    
done:
    pop rbx
    ret
Heap_Size ENDP

; =============================================================================
; Heap_Shutdown - Cleanup heap subsystem
; Only destroys heap if we created it (not process heap)
; =============================================================================
Heap_Shutdown PROC FRAME
    push rbx
    .allocstack 8
    .endprolog
    
    ; Check if we own the heap
    cmp g_heap_owned, 0
    je clear_only
    
    ; We own it - destroy it
    mov rcx, g_heap
    call HeapDestroy
    
clear_only:
    ; Clear globals regardless
    mov g_heap, 0
    mov g_heap_owned, 0
    
    pop rbx
    ret
Heap_Shutdown ENDP

; =============================================================================
; Heap_Validate - Validate heap integrity
; Returns: RAX = 1 if valid, 0 if corrupted
; =============================================================================
Heap_Validate PROC FRAME
    push rbx
    .allocstack 8
    .endprolog
    
    ; Check if initialized
    mov rax, g_heap
    test rax, rax
    jz invalid
    
    ; Validate heap
    mov rcx, g_heap
    xor edx, edx                ; dwFlags = 0
    xor r8d, r8d                ; lpMem = NULL (validate entire heap)
    call HeapValidate
    
    ; RAX = 0 if invalid, non-zero if valid
    test rax, rax
    jz invalid
    
    mov eax, 1                  ; Valid
    jmp done
    
invalid:
    xor eax, eax                ; Invalid
    
done:
    pop rbx
    ret
Heap_Validate ENDP

; =============================================================================
; EXPORTS
; =============================================================================

PUBLIC Heap_Init
PUBLIC Heap_Alloc
PUBLIC Heap_Realloc
PUBLIC Heap_Free
PUBLIC Heap_Size
PUBLIC Heap_Shutdown
PUBLIC Heap_Validate
PUBLIC g_heap

END
