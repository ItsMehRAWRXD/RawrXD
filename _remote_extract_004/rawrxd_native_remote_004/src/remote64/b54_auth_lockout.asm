OPTION CASEMAP:NONE
PUBLIC RemoteAuthFailure_Record
PUBLIC RemoteAuthFailure_Clear
.code
; state failures dword, locked dword. Lock after 5 failures.
RemoteAuthFailure_Record PROC
    inc DWORD PTR [rcx]
    cmp DWORD PTR [rcx],5
    jb af_not
    mov DWORD PTR [rcx+4],1
af_not:
    mov eax,[rcx+4]
    ret
RemoteAuthFailure_Record ENDP
RemoteAuthFailure_Clear PROC
    mov DWORD PTR [rcx],0
    mov DWORD PTR [rcx+4],0
    ret
RemoteAuthFailure_Clear ENDP
END
