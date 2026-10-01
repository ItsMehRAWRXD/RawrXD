OPTION CASEMAP:NONE
PUBLIC RemoteHealth_Classify
.code
RemoteHealth_Classify PROC
    ; rcx=lastRxMs, rdx=nowMs -> 0 ok,1 stale,2 dead
    mov rax,rdx
    sub rax,rcx
    cmp rax,5000
    jb rh_ok
    cmp rax,15000
    jb rh_stale
    mov eax,2
    ret
rh_stale:
    mov eax,1
    ret
rh_ok:
    xor eax,eax
    ret
RemoteHealth_Classify ENDP
END
