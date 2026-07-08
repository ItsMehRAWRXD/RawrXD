section .text
global _start

_start:
    mov rax, 0x12345678
    mov rcx, rax
    add rax, rcx
    sub rax, 0x10
    xor rax, rax
    ret
