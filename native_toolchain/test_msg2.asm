; Simple message test
.DATA
msg DB 'Test message', 13, 10, 0

.CODE
EXTERN ExitProcess:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC

Start PROC
    lea rcx, msg
    call PrintString
    xor rcx, rcx
    call ExitProcess
Start ENDP

PrintString PROC
    mov rsi, rcx
    mov rdi, rsi
    xor rcx, rcx
    dec rcx
    xor al, al
    repne scasb
    not rcx
    dec rcx
    mov r8, rcx
    mov rcx, 0FFFFFFF5h
    call GetStdHandle
    mov rcx, rax
    mov rdx, rsi
    sub rsp, 40
    lea r9, [rsp+32]
    mov QWORD PTR [rsp+32], 0
    call WriteFile
    add rsp, 40
    ret
PrintString ENDP

END