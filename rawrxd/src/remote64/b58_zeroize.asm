OPTION CASEMAP:NONE
PUBLIC RemoteSecureZero
.code
RemoteSecureZero PROC
    ; rcx=p rdx=n; volatile stores prevent optimizing C/C++ callers from eliding.
    test rdx,rdx
    jz sz_done
sz_loop:
    mov BYTE PTR [rcx],0
    inc rcx
    dec rdx
    jnz sz_loop
sz_done:
    mfence
    ret
RemoteSecureZero ENDP
END
