; launcher_simple.asm - Simple launcher for Sovereign runtime
; Pure x64 MASM

OPTION CASEMAP:NONE

EXTERN ExitProcess:PROC

.DATA
szMsg   DB 'Launcher ready - would start Sovereign_Engine.exe', 13, 10, 0

.CODE

Start PROC
    ; Exit with code 0
    xor     rcx, rcx
    call    ExitProcess
Start ENDP

END Start
