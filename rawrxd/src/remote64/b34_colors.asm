OPTION CASEMAP:NONE
PUBLIC RemoteColor_BGRAtoRGBA
.code
RemoteColor_BGRAtoRGBA PROC
    ; rcx pixels, rdx count, r8 dst
    test rdx,rdx
    jz cc_done
cc_loop:
    mov eax,[rcx]
    mov r9d,eax
    and eax,0FF00FF00h
    mov r10d,r9d
    and r9d,000000FFh
    shl r9d,16
    and r10d,00FF0000h
    shr r10d,16
    or eax,r9d
    or eax,r10d
    mov [r8],eax
    add rcx,4
    add r8,4
    dec rdx
    jnz cc_loop
cc_done:
    ret
RemoteColor_BGRAtoRGBA ENDP
END
