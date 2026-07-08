; Complete x64 test with Windows API
data SEGMENT ALIGN(16) READ WRITE
    message db "Hello from RawrXD!", 0
data ENDS

code SEGMENT ALIGN(16) READ EXECUTE
extrn ExitProcess : PROC
extrn GetStdHandle : PROC
extrn WriteFile : PROC

_start:
    ; Exit with code 42
    mov rcx, 42
    call ExitProcess
    ret
code ENDS
END
