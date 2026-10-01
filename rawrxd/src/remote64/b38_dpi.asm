OPTION CASEMAP:NONE
EXTERN GetDpiForWindow:PROC
PUBLIC RemoteDpi_Get
.code
RemoteDpi_Get PROC
    sub rsp,28h
    call GetDpiForWindow
    test eax,eax
    jnz @F
    mov eax,96
@@: add rsp,28h
    ret
RemoteDpi_Get ENDP
END
