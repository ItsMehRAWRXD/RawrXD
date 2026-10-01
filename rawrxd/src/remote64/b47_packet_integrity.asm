OPTION CASEMAP:NONE
EXTERN RemoteCrc32:PROC
PUBLIC RemotePacket_CheckCrc
.code
RemotePacket_CheckCrc PROC
    ; rcx=data rdx=len r8d=expected
    push rbx
    sub rsp,20h
    mov ebx,r8d
    call RemoteCrc32
    cmp eax,ebx
    sete al
    movzx eax,al
    add rsp,20h
    pop rbx
    ret
RemotePacket_CheckCrc ENDP
END
