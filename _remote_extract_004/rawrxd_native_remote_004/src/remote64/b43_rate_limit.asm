OPTION CASEMAP:NONE
PUBLIC RemoteRateLimit_Take
.code
; state: tokens dword, max dword, lastMs qword, refillPerSec dword
RemoteRateLimit_Take PROC
    ; rcx=state, rdx=nowMs
    push rbx
    mov rbx,rdx
    mov r8,[rcx+8]
    mov r9,rbx
    sub r9,r8
    cmp r9,1000
    jb rl_take
    mov eax,[rcx+16]
    imul r9,rax
    mov rax,r9
    xor edx,edx
    mov r10,1000
    div r10
    add eax,[rcx]
    cmp eax,[rcx+4]
    jbe rl_store
    mov eax,[rcx+4]
rl_store:
    mov [rcx],eax
    mov [rcx+8],rbx
rl_take:
    cmp DWORD PTR [rcx],0
    je rl_no
    dec DWORD PTR [rcx]
    mov eax,1
    pop rbx
    ret
rl_no:
    xor eax,eax
    pop rbx
    ret
RemoteRateLimit_Take ENDP
END
