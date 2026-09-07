; Deep2OuterGGUF.asm — magic + version guard (8-byte header only)
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN CloseHandle:PROC
PUBLIC Deep2Outer_CheckGgufHeader

.code
Deep2Outer_CheckGgufHeader PROC PUBLIC
    push rbx
    sub rsp, 50h
    xor eax, eax
    test rcx, rcx
    jz G_Done
    mov edx, GENERIC_READ
    mov r8d, FILE_SHARE_READ
    xor r9d, r9d
    mov qword ptr [rsp+20h], OPEN_EXISTING
    mov qword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h], 0
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je G_Done
    mov rbx, rax
    lea rdx, [rsp+40h]
    mov rcx, rbx
    mov r8d, 8
    lea r9, [rsp+48h]
    mov qword ptr [rsp+20h], 0
    call ReadFile
    mov rcx, rbx
    mov ebx, eax
    call CloseHandle
    test ebx, ebx
    jz G_Fail
    cmp dword ptr [rsp+48h], 8
    jb G_Fail
    cmp dword ptr [rsp+40h], GGUF_MAGIC_LE
    jne G_Fail
    mov eax, dword ptr [rsp+44h]
    cmp eax, GGUF_VER_MIN
    jb G_Fail
    cmp eax, GGUF_VER_MAX
    ja G_Fail
    mov eax, 1
    jmp G_Done
G_Fail:
    xor eax, eax
G_Done:
    add rsp, 50h
    pop rbx
    ret
Deep2Outer_CheckGgufHeader ENDP
END
