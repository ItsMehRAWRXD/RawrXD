; Test program that exits with code 42
; Assemble: ml64 /c /Fo test_exit.obj test_exit.asm
; Link: link /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:test_exit.exe test_exit.obj kernel32.lib

.CODE
EXTERN ExitProcess:PROC

main PROC
    mov rcx, 42
    call ExitProcess
main ENDP

END
