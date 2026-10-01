OPTION CASEMAP:NONE
EXTERN RemoteRect_Validate:PROC
PUBLIC RemoteTile_Validate
.code
RemoteTile_Validate PROC
    ; rcx -> x,y,w,h,frameW,frameH dwords
    sub rsp,38h
    mov r10,rcx
    mov ecx,[r10]
    mov edx,[r10+4]
    mov r8d,[r10+8]
    mov r9d,[r10+12]
    mov eax,[r10+16]
    mov [rsp+28h],rax
    mov eax,[r10+20]
    mov [rsp+30h],rax
    call RemoteRect_Validate
    add rsp,38h
    ret
RemoteTile_Validate ENDP
END
