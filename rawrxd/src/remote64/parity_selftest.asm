OPTION CASEMAP:NONE
EXTERN RemoteReconnect_NextDelay:PROC
EXTERN RemotePermission_Check:PROC
EXTERN RemoteKeepalive_ShouldPing:PROC
EXTERN RemoteResume_ValidateOffset:PROC
PUBLIC RemoteParitySelfTest
.code
RemoteParitySelfTest PROC
    sub rsp,28h
    mov ecx,20
    call RemoteReconnect_NextDelay
    cmp eax,30000
    jne pst_fail
    mov ecx,1Fh
    mov edx,10h
    call RemotePermission_Check
    test eax,eax
    jz pst_fail
    mov rcx,10000
    mov rdx,1000
    mov r8,5000
    call RemoteKeepalive_ShouldPing
    test eax,eax
    jz pst_fail
    mov rcx,1000
    mov rdx,1001
    call RemoteResume_ValidateOffset
    cmp rax,-1
    jne pst_fail
    mov eax,1
    jmp pst_done
pst_fail:
    xor eax,eax
pst_done:
    add rsp,28h
    ret
RemoteParitySelfTest ENDP
END
