; Test assembly file for native toolchain integration
; Simple x64 program that returns 42

bits 64
default rel

section .text
    global main
    extern ExitProcess

main:
    push rbp
    mov rbp, rsp
    sub rsp, 32

    mov rax, 42
    mov rcx, rax
    call ExitProcess

    xor rax, rax
    leave
    ret