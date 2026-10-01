OPTION CASEMAP:NONE
EXTERN shutdown:PROC
EXTERN closesocket:PROC
PUBLIC RemoteSocket_CloseGraceful
SD_BOTH EQU 2
.code
RemoteSocket_CloseGraceful PROC
    push rbx
    sub rsp,20h
    mov rbx,rcx
    mov edx,SD_BOTH
    call shutdown
    mov rcx,rbx
    call closesocket
    add rsp,20h
    pop rbx
    ret
RemoteSocket_CloseGraceful ENDP
END
