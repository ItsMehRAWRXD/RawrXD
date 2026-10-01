OPTION CASEMAP:NONE
PUBLIC RemoteRect_Validate
.code
RemoteRect_Validate PROC
    ; rcx=x rdx=y r8=w r9=h; stack +28 frameW +30 frameH
    test r8,r8
    jz rg_bad
    test r9,r9
    jz rg_bad
    mov r10,[rsp+28h]
    mov r11,[rsp+30h]
    cmp rcx,r10
    jae rg_bad
    cmp rdx,r11
    jae rg_bad
    mov rax,rcx
    add rax,r8
    jc rg_bad
    cmp rax,r10
    ja rg_bad
    mov rax,rdx
    add rax,r9
    jc rg_bad
    cmp rax,r11
    ja rg_bad
    mov eax,1
    ret
rg_bad:
    xor eax,eax
    ret
RemoteRect_Validate ENDP
END
