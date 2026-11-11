; test_heapfree_wrapper.asm - Test Heap_Free wrapper
; Build: ml64 /c /nologo test_heapfree_wrapper.asm
; Link: gcc test_heapfree_wrapper.obj -o test_heapfree_wrapper.exe

EXTRN Heap_Init:PROC
EXTRN Heap_Alloc:PROC
EXTRN Heap_Free:PROC
EXTRN printf:PROC

.data
    msg1 db '1. Heap_Init', 10, 0
    msg2 db '2. Heap_Alloc(1024)', 10, 0
    msg3 db '3. Heap_Free', 10, 0
    msg4 db '   ptr=%p', 10, 0
    msg5 db '   result=%d', 10, 0
    msg6 db 'All tests passed!', 10, 0

.code

main PROC
    sub rsp, 40
    
    ; Test 1: Init
    lea rcx, msg1
    call printf
    
    call Heap_Init
    
    lea rcx, msg5
    mov rdx, rax
    call printf
    
    ; Test 2: Alloc
    lea rcx, msg2
    call printf
    
    mov rcx, 1024
    call Heap_Alloc
    mov rbx, rax                ; Save ptr
    
    lea rcx, msg4
    mov rdx, rax
    call printf
    
    ; Test 3: Free
    lea rcx, msg3
    call printf
    
    mov rcx, rbx                ; ptr
    call Heap_Free
    
    lea rcx, msg5
    mov rdx, rax
    call printf
    
    ; Done
    lea rcx, msg6
    call printf
    
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 40
    ret
main ENDP

EXTRN ExitProcess:PROC

END