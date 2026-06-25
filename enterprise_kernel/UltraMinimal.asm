; Ultra-minimal test - just ExitProcess
option casemap:none

EXTERN ExitProcess:PROC

.code
align 8

main PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    mov rcx, 42
    call ExitProcess
    
    ; Should never reach here
    xor rcx, rcx
    call ExitProcess
    
main ENDP

END
