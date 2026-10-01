OPTION CASEMAP:NONE
PUBLIC RemoteSession_ValidatePayload
MAX_PAYLOAD EQU 16777216
.code
RemoteSession_ValidatePayload PROC
    xor eax,eax
    cmp rcx,MAX_PAYLOAD
    ja @F
    mov eax,1
@@: ret
RemoteSession_ValidatePayload ENDP
END
