; Minimal x64 assembly with proper exit for MSVC
; Assemble: ml64.exe /c test_exit_msvc.asm
; Link: link.exe /SUBSYSTEM:CONSOLE /ENTRY:main test_exit_msvc.obj kernel32.lib

.code
main PROC
    ; Return 42
    mov     rax, 42
    mov     rcx, rax
    call    ExitProcess
main ENDP

END
