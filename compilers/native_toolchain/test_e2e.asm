; test_e2e.asm - End-to-end test of native toolchain
; Tests: external symbols, import table, and execution

PUBLIC _start
EXTERN ExitProcess : PROC
EXTERN GetStdHandle : PROC
EXTERN WriteFile : PROC
EXTERN HeapAlloc : PROC
EXTERN HeapFree : PROC
EXTERN GetProcessHeap : PROC

.data
    message DB "Hello from RawrXD Native Toolchain!", 13, 10
    msg_len EQU $ - message
    written DQ 0
    heap_ptr DQ 0

.code
_start PROC FRAME
    push rbp
    .PUSHREG rbp
    mov rbp, rsp
    .SETFRAME rbp, 0
    sub rsp, 48
    .ALLOCSTACK 48
    .ENDPROLOG

    ; Test 1: Get stdout handle
    mov rcx, -11                    ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov r12, rax                    ; Save handle

    ; Test 2: Write to stdout
    mov rcx, r12                    ; hConsoleOutput
    lea rdx, message                ; lpBuffer
    mov r8d, msg_len                ; nNumberOfBytesToWrite
    lea r9, written                 ; lpNumberOfBytesWritten
    mov QWORD PTR [rsp+32], 0       ; lpReserved
    call WriteFile

    ; Test 3: Get process heap
    call GetProcessHeap
    mov r13, rax                    ; Save heap handle

    ; Test 4: Allocate memory from heap
    mov rcx, r13                    ; hHeap
    xor rdx, rdx                    ; dwFlags = 0
    mov r8, 256                     ; dwBytes = 256
    call HeapAlloc
    mov r14, rax                    ; Save allocated pointer

    ; Test 5: Free the memory
    mov rcx, r13                    ; hHeap
    xor rdx, rdx                    ; dwFlags = 0
    mov r8, r14                     ; lpMem
    call HeapFree

    ; Exit with code 42
    mov rcx, 42
    call ExitProcess

_start ENDP

END
