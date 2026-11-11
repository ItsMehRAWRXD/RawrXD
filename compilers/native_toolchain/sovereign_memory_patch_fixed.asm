; sovereign_memory_patch_fixed.asm - Fixed heap implementation for Sovereign Engine
; This patch replaces the problematic custom heap with Windows process heap
; Build: ml64 /c /nologo /Zi /Fo:sovereign_memory_patch.obj sovereign_memory_patch_fixed.asm

; =============================================================================
; External Windows API functions
; =============================================================================
EXTRN GetProcessHeap:PROC
EXTRN HeapAlloc:PROC
EXTRN HeapFree:PROC
EXTRN HeapReAlloc:PROC
EXTRN HeapSize:PROC
EXTRN HeapCreate:PROC
EXTRN HeapDestroy:PROC

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
    mov edx, 1048576            ; dwInitialSize = 1MB
    xor r8d, r8d                ; dwMaximumSize = 0 (growable)
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
    .allocstack 8
    .endprolog
    
    ; Ensure heap is initialized
    mov rax, g_heap
    test rax, rax
    jnz heap_ready
    
    ; Initialize heap
    call Heap_Init
    test eax, eax
    jnz failure
    
heap_ready:
    ; Allocate from heap
    ; Windows x64 calling convention:
    ; RCX = hHeap, RDX = dwFlags, R8 = dwBytes
    mov r9, rcx                 ; Save size to R9 (non-volatile)
    xor edx, edx                ; dwFlags = 0
    mov rcx, g_heap             ; hHeap
    mov r8, r9                  ; dwBytes = size
    call HeapAlloc
    jmp done
    
failure:
    xor eax, eax                ; Return NULL
    
done:
    pop rbx
    ret
Heap_Alloc ENDP

; =============================================================================
; Heap_Free - Free memory back to heap
; RCX = pointer to memory
; Returns: RAX = 1 on success, 0 on failure
; =============================================================================
Sovereign_Heap_Free PROC
    ; Free memory
    ; RCX = ptr
    ; Windows x64 calling convention:
    ; RCX = hHeap, RDX = dwFlags, R8 = lpMem
    ; Match the working test_heapfree_import.asm exactly
    sub rsp, 40                    ; Shadow space + alignment
    mov r8, rcx                    ; lpMem = ptr
    xor rdx, rdx                   ; dwFlags = 0
    mov rcx, g_heap                ; hHeap
    call HeapFree
    add rsp, 40                    ; Restore stack
    ret
Sovereign_Heap_Free ENDP

; =============================================================================
; Heap_Realloc - Reallocate memory block
; RCX = old pointer (can be NULL)
; RDX = new size
; Returns: RAX = new pointer, or NULL on failure
; =============================================================================
Sovereign_Heap_Realloc PROC FRAME
    push rbx
    push rsi
    .allocstack 16
    .endprolog
    
    mov rbx, rcx                ; Save old pointer
    mov rsi, rdx                ; Save new size
    
    ; Ensure heap is initialized
    mov rax, g_heap
    test rax, rax
    jnz heap_ready
    
    call Heap_Init
    test eax, eax
    jnz failure
    
heap_ready:
    ; Reallocate
    ; Windows x64 calling convention:
    ; RCX = hHeap, RDX = dwFlags, R8 = lpMem, R9 = dwBytes
    sub rsp, 40                ; Shadow space + alignment
    mov r9, rsi                ; dwBytes = new size
    mov r8, rbx                ; lpMem = old pointer
    xor rdx, rdx               ; dwFlags = 0
    mov rcx, g_heap            ; hHeap
    call HeapReAlloc
    add rsp, 40                ; Restore stack
    jmp done
    
failure:
    xor eax, eax                ; Return NULL
    
done:
    pop rsi
    pop rbx
    ret
Sovereign_Heap_Realloc ENDP

; =============================================================================
; Heap_GetSize - Get size of allocated block
; RCX = pointer to memory
; Returns: RAX = size in bytes, or 0 on failure
; =============================================================================
Heap_GetSize PROC FRAME
    push rbx
    .allocstack 8
    .endprolog
    
    ; Check for NULL
    test rcx, rcx
    jz failure
    
    ; Get heap handle
    mov rax, g_heap
    test rax, rax
    jz failure
    
    ; Get size
    mov rdx, rcx                ; lpMem = pointer
    mov rcx, g_heap             ; hHeap
    call HeapSize
    cmp rax, -1                 ; Check for error (returns -1)
    je failure
    jmp done
    
failure:
    xor eax, eax                ; Return 0
    
done:
    pop rbx
    ret
Heap_GetSize ENDP

; =============================================================================
; Heap_Cleanup - Clean up heap resources
; Should be called before program exit if using custom heap
; =============================================================================
Heap_Cleanup PROC FRAME
    push rbx
    .allocstack 8
    .endprolog
    
    ; Check if we own the heap (custom heap)
    mov al, g_heap_owned
    test al, al
    jz just_clear               ; Process heap - just clear handle
    
    ; Destroy custom heap
    mov rcx, g_heap
    call HeapDestroy
    
just_clear:
    ; Clear global state
    mov g_heap, 0
    mov g_heap_owned, 0
    
    pop rbx
    ret
Heap_Cleanup ENDP

; =============================================================================
; Export symbols for linking
; =============================================================================
PUBLIC Heap_Init
PUBLIC Heap_Alloc
PUBLIC Sovereign_Heap_Free
PUBLIC Sovereign_Heap_Realloc
PUBLIC Heap_GetSize
PUBLIC Heap_Cleanup
PUBLIC g_heap

END
