; Test Assembly program for RAWRXD Compiler Driver
; Expected: Assembles successfully and exits with code 42
; x64 Windows assembly using Win32 API

extrn ExitProcess: proc
extrn GetStdHandle: proc
extrn WriteConsoleA: proc

.data
    message db "Hello from Assembly!", 0dh, 0ah
    message_len equ $ - message
    written dq ?

.code
main PROC
    ; Get stdout handle
    mov rcx, -11              ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov r12, rax              ; Save handle
    
    ; Write message
    mov rcx, r12              ; hConsoleOutput
    lea rdx, message          ; lpBuffer
    mov r8, message_len       ; nNumberOfCharsToWrite
    lea r9, written           ; lpNumberOfCharsWritten
    mov qword ptr [rsp+28h], 0 ; lpReserved
    call WriteConsoleA
    
    ; Exit with code 42
    xor ecx, ecx              ; Exit code 0 for success
    call ExitProcess
    
main ENDP

END
