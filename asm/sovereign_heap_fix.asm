; sovereign_heap_fix.asm - Standalone Heap Fix for Sovereign Engine
; No external dependencies - uses only Windows API
; Build: ml64 /c /W3 /nologo /Zi sovereign_heap_fix.asm

option casemap:none

; =============================================================================
; EXTERNAL FUNCTIONS (kernel32)
; =============================================================================

extern GetProcessHeap:proc
extern HeapAlloc:proc
extern HeapFree:proc
extern HeapReAlloc:proc
extern HeapCreate:proc
extern HeapDestroy:proc

; =============================================================================
; CONSTANTS
; =============================================================================

HEAP_ZERO_MEMORY    EQU     000000008h

; =============================================================================
; DATA SECTION
; =============================================================================

.data
    ; Global heap handle
    g_heap              QWORD   0
    
    ; Flag to track if we own the heap
    g_heap_owned        BYTE    0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; Heap_Init_Fixed - Initialize heap using Windows process heap
; Returns: RAX = 0 on success, non-zero on failure
; =============================================================================
Heap_Init_Fixed PROC
    push rbx
    
    ; Check if already initialized
    mov rax, g_heap
    test rax, rax
    jnz already_initialized
    
    ; Get process heap (always available)
    call GetProcessHeap
    mov g_heap, rax
    test rax, rax
    jz failure
    
    ; Using process heap - we don't own it
    mov g_heap_owned, 0
    
success:
    xor eax, eax
    pop rbx
    ret
    
already_initialized:
    xor eax, eax
    pop rbx
    ret
    
failure:
    mov eax, 1
    pop rbx
    ret
Heap_Init_Fixed ENDP

; =============================================================================
; Heap_Alloc_Fixed - Allocate memory from heap
; RCX = size in bytes
; Returns: RAX = pointer to allocated memory, or NULL on failure
; =============================================================================
Heap_Alloc_Fixed PROC
    push rbx
    mov rbx, rcx                ; Save size
    
    ; Ensure heap is initialized
    mov rax, g_heap
    test rax, rax
    jnz do_alloc
    
    ; Initialize heap
    call Heap_Init_Fixed
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
    pop rbx
    ret
    
alloc_failed:
    xor eax, eax
    pop rbx
    ret
Heap_Alloc_Fixed ENDP

; =============================================================================
; Heap_Free_Fixed - Free allocated memory
; RCX = pointer to free (can be NULL)
; Returns: RAX = 1 on success, 0 on failure
; =============================================================================
Heap_Free_Fixed PROC
    push rbx
    mov rbx, rcx                ; Save pointer
    
    ; Check for NULL pointer
    test rbx, rbx
    jz free_done
    
    ; Ensure heap is initialized
    mov rax, g_heap
    test rax, rax
    jz free_failed
    
    ; Free the memory
    mov rcx, g_heap             ; hHeap
    xor edx, edx                ; dwFlags
    mov r8, rbx                 ; lpMem
    call HeapFree
    
    ; Return success (non-zero)
    mov eax, 1
    pop rbx
    ret
    
free_done:
    ; NULL pointer - return success
    mov eax, 1
    pop rbx
    ret
    
free_failed:
    xor eax, eax
    pop rbx
    ret
Heap_Free_Fixed ENDP

; =============================================================================
; Test entry point
; =============================================================================
main PROC
    sub rsp, 40
    
    ; Test heap initialization
    call Heap_Init_Fixed
    test eax, eax
    jnz init_failed
    
    ; Test allocation
    mov ecx, 1024               ; Allocate 1KB
    call Heap_Alloc_Fixed
    test rax, rax
    jz alloc_failed
    mov rbx, rax                ; Save pointer
    
    ; Test free
    mov rcx, rbx
    call Heap_Free_Fixed
    
    ; Success
    xor ecx, ecx
    call ExitProcess
    
init_failed:
    mov ecx, 1
    call ExitProcess
    
alloc_failed:
    mov ecx, 2
    call ExitProcess
    
main ENDP

extern ExitProcess:proc

END
