OPTION CASEMAP:NONE
PUBLIC RemoteCloseState_Begin
PUBLIC RemoteCloseState_Complete
.code
; 0 open, 1 closing, 2 closed
RemoteCloseState_Begin PROC
    xor eax,eax
    mov edx,1
    lock cmpxchg DWORD PTR [rcx],edx
    sete al
    movzx eax,al
    ret
RemoteCloseState_Begin ENDP
RemoteCloseState_Complete PROC
    mov DWORD PTR [rcx],2
    mfence
    ret
RemoteCloseState_Complete ENDP
END
