OPTION CASEMAP:NONE
EXTERN Sleep:PROC
PUBLIC RemoteFramePacer_Sleep
.code
RemoteFramePacer_Sleep PROC
    ; ecx=fps
    test ecx,ecx
    jz fp_done
    mov eax,1000
    xor edx,edx
    div ecx
    mov ecx,eax
    sub rsp,28h
    call Sleep
    add rsp,28h
fp_done:
    ret
RemoteFramePacer_Sleep ENDP
END
