; Simple test - just exit with code 42
bits 64
default rel

section .text
global main
extern ExitProcess

main:
    mov ecx, 42
    call ExitProcess
