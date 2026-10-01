OPTION CASEMAP:NONE
PUBLIC RemoteFrameId_Next
PUBLIC RemoteFrameId_Accept
.code
RemoteFrameId_Next PROC
    mov rax,[rcx]
    inc rax
    mov [rcx],rax
    ret
RemoteFrameId_Next ENDP
RemoteFrameId_Accept PROC
    ; rcx=last*, rdx=incoming; allows only exact next frame.
    mov rax,[rcx]
    inc rax
    cmp rdx,rax
    jne fi_bad
    mov [rcx],rdx
    mov eax,1
    ret
fi_bad:
    xor eax,eax
    ret
RemoteFrameId_Accept ENDP
END
