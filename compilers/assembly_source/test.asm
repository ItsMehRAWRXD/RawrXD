; Test assembly file for RawrXD compiler
; This is a simple test program

section .data
    message db "Hello, World!", 0

section .text
    global _start

_start:
    ; Entry point
    nop
    nop
    ret
