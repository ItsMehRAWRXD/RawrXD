; sovereign_memory_patch_debug.asm - Debug heap implementation
; Build: ml64 /c /nologo /Zi /Fo:sovereign_memory_patch.obj sovereign_memory_patch_debug.asm

EXTRN GetProcessHeap:PROC
EXTRN HeapAlloc:PROC
EXTRN HeapFree:PROC
EXTRN HeapReAlloc:PROC
EXTRN HeapSize:PROC
EXTRN HeapCreate:PROC
EXTRN HeapDestroy:PROC
EXTRN printf:PROC

HEAP_ZERO_MEMORY    EQU     000000008h

.data
    g_heap              QWORD   0
    g_heap_owned        BYTE    0
    
    msg_init db 'Heap_Init: calling GetProcessHeap', 10, 0
    msg_init_result db 'Heap_Init: result=%d, g_heap=%p', 10, 0
    msg_alloc db 'Heap_Alloc: size=%llu, g_heap=%p', 10, 0
    msg_alloc_result db 'Heap_Alloc: result=%p', 10, 0
    msg_free_enter db 'Heap_Free: entering, ptr=%p', 10, 0
    msg_free_heap db 'Heap_Free: g_heap=%p', 10, 0
    msg_free_call db 'Heap_Free: calling HeapFree', 10, 0
    msg_free_result db 'Heap_Free: result=%d', 10, 0

.code

Heap_Init PROC
    sub rsp, 40
    
    lea rcx, msg_init
    call printf
    
    call GetProcessHeap
    mov g_heap, rax
    
    lea rcx, msg_init_result
    xor rdx, rdx
    mov r8, rax
    call printf
    
    add rsp, 40
    xor eax, eax
    ret
Heap_Init ENDP

Heap_Alloc PROC
    ; RCX = size
    sub rsp, 40
    
    lea rcx, msg_alloc
    mov rdx, rcx
    mov r8, g_heap
    call printf
    
    mov r9, rcx
    xor rdx, rdx
    mov rcx, g_heap
    mov r8, r9
    call HeapAlloc
    
    lea rcx, msg_alloc_result
    mov rdx, rax
    call printf
    
    add rsp, 40
    ret
Heap_Alloc ENDP

Heap_Free PROC
    ; RCX = ptr
    sub rsp, 56
    
    ; Save ptr to stack
    mov [rsp+48], rcx
    
    lea rcx, msg_free_enter
    mov rdx, [rsp+48]
    call printf
    
    lea rcx, msg_free_heap
    mov rdx, g_heap
    call printf
    
    lea rcx, msg_free_call
    call printf
    
    ; Call HeapFree
    mov rcx, g_heap
    xor rdx, rdx
    mov r8, [rsp+48]
    call HeapFree
    
    lea rcx, msg_free_result
    mov rdx, rax
    call printf
    
    add rsp, 56
    ret
Heap_Free ENDP

PUBLIC Heap_Init
PUBLIC Heap_Alloc
PUBLIC Heap_Free
PUBLIC g_heap

END