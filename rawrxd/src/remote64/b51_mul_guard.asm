OPTION CASEMAP:NONE
PUBLIC RemoteMulU64
.code
RemoteMulU64 PROC
    ; rcx*a rdx*b, r8=result*. eax=1 no overflow.
    mov rax,rcx
    mul rdx
    test rdx,rdx
    jnz mg_bad
    mov [r8],rax
    mov eax,1
    ret
mg_bad:
    xor eax,eax
    ret
RemoteMulU64 ENDP
END
