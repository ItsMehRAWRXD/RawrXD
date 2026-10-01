OPTION CASEMAP:NONE
PUBLIC RemoteLatency_OnPong
.code
RemoteLatency_OnPong PROC
    ; rcx=sentMs rdx=nowMs r8=state {rtt qword,jitter qword}
    mov rax,rdx
    sub rax,rcx
    mov r9,[r8]
    mov [r8],rax
    sub r9,rax
    jns @F
    neg r9
@@: mov r10,[r8+8]
    imul r10,3
    add r10,r9
    shr r10,2
    mov [r8+8],r10
    ret
RemoteLatency_OnPong ENDP
END
