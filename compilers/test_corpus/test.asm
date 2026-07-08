; Test Assembly Source File
; For testing assembly compilers

section .data
    msg db "Hello from Assembly", 0
    len equ $ - msg

section .text
global _start

_start:
    ; Write to stdout
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    mov rsi, msg
    mov rdx, len
    syscall
    
    ; Exit
    mov rax, 60         ; sys_exit
    xor rdi, rdi
    syscall
