; Simple test - just return 42 (no imports needed)
bits 64
default rel

section .text
global main

main:
    mov eax, 42
    ret
