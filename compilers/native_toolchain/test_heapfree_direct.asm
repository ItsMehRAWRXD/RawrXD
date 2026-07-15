; test_heapfree_direct.asm - Test HeapFree import directly
; Build: ml64 /c /nologo test_heapfree_direct.asm
; Link: link /SUBSYSTEM:CONSOLE /ENTRY:main test_heapfree_direct.obj

EXTRN GetProcessHeap:PROC
EXTRN HeapAlloc:PROC
EXTRN HeapFree:PROC
EXTRN printf:PROC
EXTRN ExitProcess:PROC

.data
    msg1 db 'Step 1: GetProcessHeap', 10, 0
    msg2 db 'Step 2: HeapAlloc', 10, 0
    msg3 db 'Step 3: HeapFree', 10, 0
    msg4 db 'PASS', 10, 0
    msg5 db 'FAIL', 10, 0
    fmt1 db '  Handle: %p', 10, 0
    fmt2 db '  Pointer: %p', 10, 0
    fmt3 db '  Result: %d', 10, 0

.code

main PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    
    ; Step 1: GetProcessHeap
    lea rcx, msg1
    call printf
    
    call GetProcessHeap
    mov rbx, rax                ; Save heap handle
    
    lea rcx, fmt1
    mov rdx, rax
    call printf
    
    lea rcx, msg4
    call printf
    
    ; Step 2: HeapAlloc
    lea rcx, msg2
    call printf
    
    mov rcx, rbx                ; hHeap
    xor rdx, rdx                ; dwFlags = 0
    mov r8, 1024                ; dwBytes = 1024
    call HeapAlloc
    mov rsi, rax                ; Save pointer
    
    lea rcx, fmt2
    mov rdx, rax
    call printf
    
    lea rcx, msg4
    call printf
    
    ; Step 3: HeapFree
    lea rcx, msg3
    call printf
    
    mov rcx, rbx                ; hHeap
    xor rdx, rdx                ; dwFlags = 0
    mov r8, rsi                ; lpMem
    call HeapFree
    
    lea rcx, fmt3
    mov rdx, rax
    call printf
    
    lea rcx, msg4
    call printf
    
    ; Exit
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret
main ENDP

END