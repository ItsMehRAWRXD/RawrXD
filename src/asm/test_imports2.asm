; Simple test with Windows API imports
EXTERN GetModuleHandleA:PROC
EXTERN ExitProcess:PROC

.CODE
main:
    xor rcx, rcx
    sub rsp, 40
    call GetModuleHandleA
    add rsp, 40
    
    xor rcx, rcx
    call ExitProcess
    
    ret

END main
