; SimpleTest.asm - Minimal diagnostic test
option casemap:none

EXTERNDEF PrintString:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteConsoleA:PROC

.data
    msg_start   db "=== SIMPLE TEST ===", 13, 10, 0
    msg_ok      db "OK: Reached end", 13, 10, 0
    newline     db 13, 10, 0

.code
mainCRTStartup PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    
    lea     rcx, msg_start
    call    PrintString
    
    lea     rcx, msg_ok
    call    PrintString
    
    xor     ecx, ecx
    call    ExitProcess
    
    add     rsp, 32
    pop     rbp
    ret
mainCRTStartup ENDP
END
