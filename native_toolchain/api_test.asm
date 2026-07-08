; API Test - Uses actual Windows API imports
; Assemble: ml64 /c /Fo api_test_ml64.obj api_test.asm
; Link: link /SUBSYSTEM:CONSOLE /ENTRY:Start api_test_ml64.obj kernel32.lib

EXTERN ExitProcess:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC

.CODE
Start:
    ; Get stdout handle
    mov rcx, 0FFFFFFF5h         ; STD_OUTPUT_HANDLE = -11
    call GetStdHandle
    
    ; Exit
    xor rcx, rcx
    call ExitProcess

END
