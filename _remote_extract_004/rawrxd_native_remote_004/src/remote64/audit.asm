OPTION CASEMAP:NONE
EXTERN CreateFileW:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
PUBLIC RemoteAudit_Append
GENERIC_WRITE EQU 40000000h
FILE_SHARE_READ EQU 1
OPEN_ALWAYS EQU 4
FILE_ATTRIBUTE_NORMAL EQU 80h
FILE_END EQU 2
EXTERN SetFilePointerEx:PROC
.code
RemoteAudit_Append PROC
    ; rcx=path UTF16, rdx=record bytes, r8d=len
    push rbx
    push rsi
    sub rsp,48h
    mov rsi,rdx
    mov ebx,r8d
    mov rdx,GENERIC_WRITE
    mov r8d,FILE_SHARE_READ
    xor r9d,r9d
    mov QWORD PTR [rsp+20h],OPEN_ALWAYS
    mov QWORD PTR [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov QWORD PTR [rsp+30h],0
    call CreateFileW
    cmp rax,-1
    je aa_fail
    mov rdi,rax
    mov rcx,rdi
    xor edx,edx
    xor r8d,r8d
    mov r9d,FILE_END
    call SetFilePointerEx
    mov rcx,rdi
    mov rdx,rsi
    mov r8d,ebx
    lea r9,[rsp+38h]
    mov QWORD PTR [rsp+20h],0
    call WriteFile
    mov ebx,eax
    mov rcx,rdi
    call CloseHandle
    mov eax,ebx
    jmp aa_done
aa_fail:
    xor eax,eax
aa_done:
    add rsp,48h
    pop rsi
    pop rbx
    ret
RemoteAudit_Append ENDP
END
