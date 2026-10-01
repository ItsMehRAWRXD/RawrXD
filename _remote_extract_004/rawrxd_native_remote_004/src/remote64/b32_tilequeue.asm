OPTION CASEMAP:NONE
PUBLIC RemoteTileQueue_Push
PUBLIC RemoteTileQueue_Pop
.code
; Queue header: head dword, tail dword, cap dword, stride dword, data qword.
RemoteTileQueue_Push PROC
    ; rcx=queue, rdx=item
    push rbx
    mov rbx,rdx
    mov eax,[rcx+4]
    mov r8d,eax
    inc r8d
    mov eax,r8d
    xor edx,edx
    div DWORD PTR [rcx+8]
    mov r8d,edx
    cmp r8d,[rcx]
    je tq_full
    mov eax,[rcx+4]
    imul eax,[rcx+12]
    mov r9,[rcx+16]
    add r9,rax
    mov edx,[rcx+12]
tq_copy:
    test edx,edx
    jz tq_commit
    mov al,[rbx]
    mov [r9],al
    inc rbx
    inc r9
    dec edx
    jmp tq_copy
tq_commit:
    mov [rcx+4],r8d
    mov eax,1
    pop rbx
    ret
tq_full:
    xor eax,eax
    pop rbx
    ret
RemoteTileQueue_Push ENDP

RemoteTileQueue_Pop PROC
    ; rcx=queue, rdx=dst
    push rbx
    mov rbx,rdx
    mov eax,[rcx]
    cmp eax,[rcx+4]
    je tq_empty
    mov r8d,eax
    imul eax,[rcx+12]
    mov r9,[rcx+16]
    add r9,rax
    mov edx,[rcx+12]
tq_copy2:
    test edx,edx
    jz tq_advance
    mov al,[r9]
    mov [rbx],al
    inc r9
    inc rbx
    dec edx
    jmp tq_copy2
tq_advance:
    inc r8d
    mov eax,r8d
    xor edx,edx
    div DWORD PTR [rcx+8]
    mov [rcx],edx
    mov eax,1
    pop rbx
    ret
tq_empty:
    xor eax,eax
    pop rbx
    ret
RemoteTileQueue_Pop ENDP
END
