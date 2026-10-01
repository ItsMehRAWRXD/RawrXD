OPTION CASEMAP:NONE
PUBLIC RemoteSequence_Accept
.code
RemoteSequence_Accept PROC
    ; rcx=last*, rdx=incoming. strictly monotonic.
    mov rax,[rcx]
    cmp rdx,rax
    jbe sq_reject
    mov [rcx],rdx
    mov eax,1
    ret
sq_reject:
    xor eax,eax
    ret
RemoteSequence_Accept ENDP
END
