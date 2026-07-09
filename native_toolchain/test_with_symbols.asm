global main
extern ExitProcess

main:
    mov rax, 42
    mov rcx, rax
    call ExitProcess
    ret
