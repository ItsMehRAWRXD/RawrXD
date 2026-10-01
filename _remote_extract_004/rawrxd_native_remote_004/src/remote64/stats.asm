OPTION CASEMAP:NONE
EXTERN QueryPerformanceCounter:PROC
EXTERN QueryPerformanceFrequency:PROC
PUBLIC RemoteStats_Now
PUBLIC RemoteStats_DeltaUsec
.code
RemoteStats_Now PROC
    ; rcx -> qword
    sub rsp,28h
    call QueryPerformanceCounter
    add rsp,28h
    ret
RemoteStats_Now ENDP
RemoteStats_DeltaUsec PROC
    ; rcx=start ticks rdx=end ticks
    push rbx
    sub rsp,30h
    mov rbx,rdx
    sub rbx,rcx
    lea rcx,[rsp+20h]
    call QueryPerformanceFrequency
    mov rax,rbx
    mov r8,1000000
    mul r8
    xor edx,edx
    div QWORD PTR [rsp+20h]
    add rsp,30h
    pop rbx
    ret
RemoteStats_DeltaUsec ENDP
END
