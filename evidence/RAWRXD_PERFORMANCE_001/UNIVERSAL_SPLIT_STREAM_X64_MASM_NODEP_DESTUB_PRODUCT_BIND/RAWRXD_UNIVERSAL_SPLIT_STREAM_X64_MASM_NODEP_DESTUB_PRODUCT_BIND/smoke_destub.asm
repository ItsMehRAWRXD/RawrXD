option casemap:none
include ss_real_provider.inc

CreateFileA PROTO :PTR BYTE,:DWORD,:DWORD,:QWORD,:DWORD,:DWORD,:QWORD
WriteFile    PROTO :QWORD,:QWORD,:DWORD,:PTR DWORD,:QWORD
CloseHandle  PROTO :QWORD
DeleteFileA  PROTO :PTR BYTE
ExitProcess  PROTO :DWORD

GENERIC_WRITE equ 40000000h
CREATE_ALWAYS equ 2

.data
path db "ss_destub_fixture.gguf",0
written DWORD 0

fixture_start LABEL BYTE
    dd 46554747h              ; GGUF
    dd 3                     ; version
    dq 2                     ; tensors
    dq 1                     ; kv pairs

    dq 17
    db "general.alignment"
    dd 4                     ; UINT32
    dd 32

    dq 17
    db "token_embd.weight"
    dd 1
    dq 4
    dd 0                     ; F32
    dq 0

    dq 12
    db "other.weight"
    dd 1
    dq 4
    dd 0
    dq 16

    db 10 dup(0)             ; align 150 -> 160

    dd 3F800000h,40000000h,40400000h,40800000h
    dd 40A00000h,40C00000h,40E00000h,41000000h
fixture_end LABEL BYTE

fixture_bytes equ fixture_end-fixture_start

.data?
fctx SSFileCtx <>
desc SSTensorDesc <>
buf BYTE 16 DUP(?)
got QWORD ?

.code
main PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp,30h
    .allocstack 30h
    .endprolog

    lea rcx,path
    mov edx,GENERIC_WRITE
    xor r8d,r8d
    xor r9d,r9d
    mov qword ptr [rsp+20h],CREATE_ALWAYS
    mov qword ptr [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h],0
    call CreateFileA
    cmp rax,INVALID_HANDLE_VALUE
    je bad
    mov rbx,rax

    mov rcx,rbx
    lea rdx,fixture_start
    mov r8d,fixture_bytes
    lea r9,written
    mov qword ptr [rsp+20h],0
    call WriteFile
    test eax,eax
    jz bad_close
    cmp written,fixture_bytes
    jne bad_close
    mov rcx,rbx
    call CloseHandle

    lea rcx,path
    lea rdx,fctx
    call ss_file_open
    test eax,eax
    jnz bad_delete

    lea rcx,fctx
    lea rdx,desc
    call ss_find_anchor_tensor
    test eax,eax
    jnz bad_fclose
    cmp desc.found,1
    jne bad_fclose
    cmp desc.which_name,1
    jne bad_fclose
    cmp desc.absolute_offset,160
    jne bad_fclose
    cmp desc.storage_bytes,16
    jne bad_fclose

    lea rcx,fctx
    mov rdx,desc.absolute_offset
    mov r8,desc.storage_bytes
    lea r9,buf
    lea rax,got
    mov [rsp+20h],rax
    call ss_file_read_exact
    test eax,eax
    jnz bad_fclose
    cmp got,16
    jne bad_fclose
    cmp dword ptr buf,3F800000h
    jne bad_fclose

    lea rcx,fctx
    call ss_file_close
    lea rcx,path
    call DeleteFileA
    xor ecx,ecx
    call ExitProcess

bad_fclose:
    lea rcx,fctx
    call ss_file_close
bad_delete:
    lea rcx,path
    call DeleteFileA
bad:
    mov ecx,1
    call ExitProcess
bad_close:
    mov rcx,rbx
    call CloseHandle
    jmp bad_delete
main ENDP
END
