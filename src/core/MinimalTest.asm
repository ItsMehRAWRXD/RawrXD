; MinimalTest.asm - Absolute minimal test
option casemap:none

EXTERNDEF PrintString:PROC
EXTERNDEF ExitProcess:PROC

.data
    msg1    db "Step 1: Entry", 13, 10, 0
    msg2    db "Step 2: Before PrintString", 13, 10, 0
    msg3    db "Step 3: After PrintString", 13, 10, 0
    msg4    db "Step 4: Success!", 13, 10, 0

.code
mainCRTStartup PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    
    ; Step 1
    lea     rcx, msg1
    call    PrintString
    
    ; Step 2
    lea     rcx, msg2
    call    PrintString
    
    ; Step 3
    lea     rcx, msg3
    call    PrintString
    
    ; Step 4
    lea     rcx, msg4
    call    PrintString
    
    ; Exit
    xor     ecx, ecx
    call    ExitProcess
    
    add     rsp, 32
    pop     rbp
    ret
mainCRTStartup ENDP
END
