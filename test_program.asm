; Test program - demonstrates working toolchain
; Assembles to PE executable that returns 42

section .text
global _start

_start:
    ; Set up stack frame
    push    rbp
    mov     rbp, rsp
    
    ; Return 42 (success code)
    mov     eax, 42
    
    ; Restore stack and return
    pop     rbp
    ret
