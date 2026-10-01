OPTION CASEMAP:NONE
PUBLIC RemoteUtf16_Validate
.code
RemoteUtf16_Validate PROC
    ; rcx=UTF16 ptr, rdx=code units. validates surrogate pairing.
u16_loop:
    test rdx,rdx
    jz u16_ok
    movzx eax,WORD PTR [rcx]
    cmp eax,0D800h
    jb u16_next
    cmp eax,0DBFFh
    jbe u16_high
    cmp eax,0DFFFh
    jbe u16_bad
u16_next:
    add rcx,2
    dec rdx
    jmp u16_loop
u16_high:
    cmp rdx,2
    jb u16_bad
    movzx eax,WORD PTR [rcx+2]
    cmp eax,0DC00h
    jb u16_bad
    cmp eax,0DFFFh
    ja u16_bad
    add rcx,4
    sub rdx,2
    jmp u16_loop
u16_ok:
    mov eax,1
    ret
u16_bad:
    xor eax,eax
    ret
RemoteUtf16_Validate ENDP
END
