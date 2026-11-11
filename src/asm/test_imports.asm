; Test program with Windows API imports
; Tests: GetModuleHandleA, ExitProcess
EXTERN GetModuleHandleA:PROC
EXTERN ExitProcess:PROC

_TEXT SEGMENT
main PROC
    ; Call GetModuleHandleA(NULL)
    xor rcx, rcx
    sub rsp, 40
    call GetModuleHandleA
    add rsp, 40
    
    ; Exit with code 0
    xor rcx, rcx
    sub rsp, 40
    call ExitProcess
    add rsp, 40
    
    ; Should never reach here
    ret
main ENDP
_TEXT ENDS

END
