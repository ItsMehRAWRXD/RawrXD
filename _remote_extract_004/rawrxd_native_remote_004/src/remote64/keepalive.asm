OPTION CASEMAP:NONE
PUBLIC RemoteKeepalive_ShouldPing
.code
RemoteKeepalive_ShouldPing PROC
    ; rcx=nowMs rdx=lastTrafficMs r8=intervalMs
    mov rax,rcx
    sub rax,rdx
    cmp rax,r8
    setae al
    movzx eax,al
    ret
RemoteKeepalive_ShouldPing ENDP
END
