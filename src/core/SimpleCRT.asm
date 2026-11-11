; SimpleCRT.asm - Test with CRT
option casemap:none

 includelib msvcrt.lib

EXTERN printf:PROC
EXTERN exit:PROC

.data
    fmt db "Hello from CRT!", 10, 0

.code
main PROC
    sub rsp, 40
    
    lea rcx, fmt
    call printf
    
    xor ecx, ecx
    call exit
    
    add rsp, 40
    ret
main ENDP
END
