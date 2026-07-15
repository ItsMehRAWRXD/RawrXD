; test_heapfree_debug.asm - Debug Heap_Free wrapper
; Build: ml64 /c /nologo test_heapfree_debug.asm
; Link: gcc test_heapfree_debug.obj -o test_heapfree_debug.exe

EXTRN GetProcessHeap:PROC
EXTRN HeapAlloc:PROC
EXTRN HeapFree:PROC
EXTRN printf:PROC

.data
    g_heap QWORD 0
    
    msg1 db 'Heap_Init: calling GetProcessHeap', 10, 0
    msg2 db 'Heap_Init: handle=%p', 10, 0
    msg3 db 'Heap_Alloc: calling HeapAlloc', 10, 0
    msg4 db 'Heap_Alloc: ptr=%p', 10, 0
    msg5 db 'Heap_Free: entering', 10, 0
    msg6 db 'Heap_Free: lpMem=%p', 10, 0
    msg7 db 'Heap_Free: g_heap=%p', 10, 0
    msg8 db 'Heap_Free: calling HeapFree', 10, 0
    msg9 db 'Heap_Free: result=%d', 10, 0

.code

Heap_Init PROC
    sub rsp, 40
    
    lea rcx, msg1
    call printf
    
    call GetProcessHeap
    mov g_heap, rax
    
    lea rcx, msg2
    mov rdx, rax
    call printf
    
    xor eax, eax
    add rsp, 40
    ret
Heap_Init ENDP

Heap_Alloc PROC
    ; RCX = size
    sub rsp, 40
    
    lea rcx, msg3
    call printf
    
    mov r9, rcx        ; Save size
    mov rcx, g_heap
    xor rdx, rdx
    mov r8, r9
    call HeapAlloc
    
    lea rcx, msg4
    mov rdx, rax
    call printf
    
    add rsp, 40
    ret
Heap_Alloc ENDP

Heap_Free PROC
    ; RCX = lpMem
    sub rsp, 56        ; Shadow space + alignment
    
    lea rcx, msg5
    call printf
    
    lea rcx, msg6
    mov rdx, rcx       ; This is wrong - RCX is lpMem, not the format
    ; Actually, we need to save RCX first
    mov rax, rcx       ; Save lpMem to RAX (volatile)
    
    lea rcx, msg6
    mov rdx, rax       ; lpMem
    call printf
    
    lea rcx, msg7
    mov rdx, g_heap
    call printf
    
    ; Check for NULL
    test rax, rax
    jz return_success
    
    ; Check g_heap
    mov rdx, g_heap
    test rdx, rdx
    jz return_failure
    
    lea rcx, msg8
    call printf
    
    ; Call HeapFree
    mov rcx, g_heap
    xor rdx, rdx
    mov r8, rax        ; lpMem
    call HeapFree
    
    lea rcx, msg9
    mov rdx, rax
    call printf
    
    test eax, eax
    jz return_failure
    
return_success:
    mov eax, 1
    add rsp, 56
    ret
    
return_failure:
    xor eax, eax
    add rsp, 56
    ret
Heap_Free ENDP

END