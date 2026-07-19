; Hello World in x64 Assembly for RAWRXD Compiler Driver
; Compile with: rawrxd-compiler compile hello.asm
; This uses Windows x64 calling convention

extrn ExitProcess: proc
extrn GetStdHandle: proc
extrn WriteConsoleA: proc

.data
    message db "Hello, World from RAWRXD Assembly!", 13, 10, 0
    message_len equ $ - message
    bytes_written dq ?

.code
main proc
    sub rsp, 40                 ; Shadow space + alignment
    
    ; Get stdout handle (-11 = STD_OUTPUT_HANDLE)
    mov rcx, -11
    call GetStdHandle
    mov rbx, rax                ; Save handle
    
    ; Write to console
    mov rcx, rbx                ; Handle
    lea rdx, message            ; Buffer
    mov r8, message_len         ; Length
    lea r9, bytes_written       ; Bytes written
    mov qword ptr [rsp+32], 0   ; Reserved (must be NULL)
    call WriteConsoleA
    
    ; Exit process
    xor ecx, ecx                ; Exit code 0
    call ExitProcess
    
    add rsp, 40
    ret
main endp

end
