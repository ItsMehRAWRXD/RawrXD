; Simple test for real assembler
.386
.model flat, stdcall
option casemap:none

.code
start:
    mov eax, 42
    ret
end start
