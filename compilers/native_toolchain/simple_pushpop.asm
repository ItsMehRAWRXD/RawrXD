; Simple test using xor and inc to set exit code
bits 64
default rel

section .text
global main

main:
    xor ecx, ecx    ; ecx = 0
    inc ecx         ; ecx = 1
    inc ecx         ; ecx = 2
    ; ... would need 40 more incs to get to 42
    ; Let's use a different approach - push/pop
    push 42
    pop ecx
    ret
