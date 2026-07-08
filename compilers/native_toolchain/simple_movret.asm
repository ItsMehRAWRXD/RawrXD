; Simple test - return 42 using mov eax, 42 then ret
bits 64
default rel

section .text
global main

main:
    mov eax, 42
    ret
