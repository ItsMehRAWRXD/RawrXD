option casemap:none
include r671_open_diag.inc

ExitProcess PROTO
CreateFileA PROTO
WriteFile PROTO
CloseHandle PROTO
DeleteFileA PROTO

GENERIC_READ  equ 80000000h
GENERIC_WRITE equ 40000000h
FILE_SHARE_READ equ 1
CREATE_ALWAYS equ 2
FILE_ATTRIBUTE_NORMAL equ 00000080h

.data
path db "r671_smoke_tensor.bin",0
vals REAL4 1.0,2.0,3.0,4.0
written DWORD 0

.data?
ctx R671ContextDiag <>

.code
main PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp,40h
    .allocstack 40h
    .endprolog

    lea rcx, path
    call DeleteFileA

    lea rcx, path
    mov edx, GENERIC_READ
    or edx, GENERIC_WRITE
    mov r8d, FILE_SHARE_READ
    xor r9d, r9d
    mov qword ptr [rsp+20h], CREATE_ALWAYS
    mov qword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h], 0
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je prep_fail
    mov rbx, rax

    mov rcx, rbx
    lea rdx, vals
    mov r8d, 16
    lea r9, written
    mov qword ptr [rsp+20h], 0
    call WriteFile
    test eax, eax
    jz prep_close_fail

    mov rcx, rbx
    call CloseHandle
    xor ebx, ebx

    lea rcx, path
    lea rdx, ctx
    call r671_open_diag
    test eax, eax
    jz good

    mov eax, dword ptr ctx.open_stage
    shl eax, 8
    mov ecx, dword ptr ctx.win32_last_error
    and ecx, 0FFh
    or ecx, eax
    jmp exit_ecx

good:
    xor ecx, ecx
    jmp exit_ecx

prep_close_fail:
    mov rcx, rbx
    call CloseHandle
prep_fail:
    mov ecx, 0F000h

exit_ecx:
    add rsp, 40h
    pop rbx
    call ExitProcess
main ENDP
END
