; Minimal test - just exit with code 0
option casemap:none

extrn ExitProcess:proc

.code
mainCRTStartup PROC
    sub rsp, 28h
    xor ecx, ecx
    call ExitProcess
mainCRTStartup ENDP
end
