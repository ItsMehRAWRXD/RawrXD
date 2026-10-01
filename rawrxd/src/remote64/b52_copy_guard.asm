OPTION CASEMAP:NONE
PUBLIC RemoteRange_Validate
.code
RemoteRange_Validate PROC
    ; rcx=offset rdx=len r8=capacity
    cmp rcx,r8
    ja rv_bad
    mov rax,rcx
    add rax,rdx
    jc rv_bad
    cmp rax,r8
    ja rv_bad
    mov eax,1
    ret
rv_bad:
    xor eax,eax
    ret
RemoteRange_Validate ENDP
END
