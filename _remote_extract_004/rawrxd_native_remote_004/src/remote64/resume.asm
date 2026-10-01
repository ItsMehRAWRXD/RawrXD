OPTION CASEMAP:NONE
PUBLIC RemoteResume_ValidateOffset
.code
RemoteResume_ValidateOffset PROC
    ; rcx=fileSize rdx=requestedOffset -> rax accepted offset, -1 invalid
    cmp rdx,rcx
    ja rv_bad
    mov rax,rdx
    ret
rv_bad:
    mov rax,-1
    ret
RemoteResume_ValidateOffset ENDP
END
