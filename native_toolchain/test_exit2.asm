; Minimal x64 assembly with proper exit
; Assemble: minimal_assembler_v5.exe test_exit2.asm test_exit2.obj
; Link: linker_v4.exe test_exit2.obj test_exit2.exe

section .text
global main
extern ExitProcess

main:
    ; Return 42
    mov     rax, 42
    mov     rcx, rax
    call    ExitProcess
    ret
