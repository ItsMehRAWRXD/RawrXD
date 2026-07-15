; test_import.asm - Test import table functionality
; Simple program that calls Windows APIs

PUBLIC _start
EXTERN ExitProcess : PROC
EXTERN GetStdHandle : PROC
EXTERN WriteFile : PROC

.data
    message DB "Hello from RawrXD Native Toolchain!", 13, 10
    msg_len EQU $ - message
    written DQ 0

.code
_start PROC FRAME
    push rbp
    .PUSHREG rbp
    push rbx
    .PUSHREG rbx
    sub rsp, 40
    .ALLOCSTACK 40
    .ENDPROLOG

    ; Get stdout handle (-11 = STD_OUTPUT_HANDLE)
    mov rcx, -11
    call GetStdHandle
    mov rbx, rax        ; Save handle

    ; Write to stdout
    mov rcx, rbx                    ; hConsoleOutput
    lea rdx, message                ; lpBuffer
    mov r8d, msg_len                ; nNumberOfBytesToWrite
    lea r9, written                 ; lpNumberOfBytesWritten
    mov QWORD PTR [rsp+32], 0       ; lpReserved
    call WriteFile

    ; Exit with code 42
    mov rcx, 42
    call ExitProcess

_start ENDP

END
