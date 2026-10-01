OPTION CASEMAP:NONE
PUBLIC RemoteNonce_FromSequence
.code
RemoteNonce_FromSequence PROC
    ; rcx=4-byte session salt, rdx=sequence, r8=12-byte nonce
    mov eax,[rcx]
    mov [r8],eax
    mov [r8+4],rdx
    ret
RemoteNonce_FromSequence ENDP
END
