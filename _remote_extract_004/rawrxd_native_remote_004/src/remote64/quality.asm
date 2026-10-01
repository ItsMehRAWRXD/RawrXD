OPTION CASEMAP:NONE
PUBLIC RemoteQuality_Update
.code
RemoteQuality_Update PROC
    ; rcx=state [targetFps dword,tile dword,lastRtt qword,lastBytes qword]
    ; rdx=rtt usec, r8=bytes last frame
    mov [rcx+8],rdx
    mov [rcx+16],r8
    mov eax,30
    mov r9d,64
    cmp rdx,150000
    jb q_band
    mov eax,20
    mov r9d,96
    cmp rdx,300000
    jb q_band
    mov eax,10
    mov r9d,128
q_band:
    mov [rcx],eax
    mov [rcx+4],r9d
    ret
RemoteQuality_Update ENDP
END
