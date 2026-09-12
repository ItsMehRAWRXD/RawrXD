option casemap:none
include ss_real_provider.inc

CreateFileA       PROTO :PTR BYTE,:DWORD,:DWORD,:QWORD,:DWORD,:DWORD,:QWORD
GetFileSizeEx     PROTO :QWORD,:PTR QWORD
SetFilePointerEx  PROTO :QWORD,:QWORD,:PTR QWORD,:DWORD
ReadFile          PROTO :QWORD,:QWORD,:DWORD,:PTR DWORD,:QWORD
CloseHandle       PROTO :QWORD

.code

ss_file_open PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp,40h
    .allocstack 40h
    .endprolog
    mov rbx,rdx
    test rcx,rcx
    jz sfo_bad
    test rbx,rbx
    jz sfo_bad
    mov qword ptr [rbx].SSFileCtx.handle,0
    mov qword ptr [rbx].SSFileCtx.file_bytes,0

    mov edx,GENERIC_READ
    mov r8d,FILE_SHARE_READ
    xor r9d,r9d
    mov qword ptr [rsp+20h],OPEN_EXISTING
    mov qword ptr [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h],0
    call CreateFileA
    cmp rax,INVALID_HANDLE_VALUE
    je sfo_open_fail
    mov [rbx].SSFileCtx.handle,rax

    mov rcx,rax
    lea rdx,[rsp+38h]
    call GetFileSizeEx
    test eax,eax
    jz sfo_size_fail
    mov rax,[rsp+38h]
    test rax,rax
    jz sfo_size_fail
    mov [rbx].SSFileCtx.file_bytes,rax
    xor eax,eax
    jmp sfo_done

sfo_size_fail:
    mov rcx,[rbx].SSFileCtx.handle
    call CloseHandle
    mov qword ptr [rbx].SSFileCtx.handle,0
    mov eax,SS_E_SIZE
    jmp sfo_done
sfo_open_fail:
    mov eax,SS_E_OPEN
    jmp sfo_done
sfo_bad:
    mov eax,SS_E_INVALID
sfo_done:
    add rsp,40h
    pop rbx
    ret
ss_file_open ENDP

ss_file_close PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp,20h
    .allocstack 20h
    .endprolog
    mov rbx,rcx
    test rbx,rbx
    jz sfc_bad
    mov rcx,[rbx].SSFileCtx.handle
    test rcx,rcx
    jz sfc_zero
    call CloseHandle
sfc_zero:
    mov qword ptr [rbx].SSFileCtx.handle,0
    mov qword ptr [rbx].SSFileCtx.file_bytes,0
    xor eax,eax
    jmp sfc_done
sfc_bad:
    mov eax,SS_E_INVALID
sfc_done:
    add rsp,20h
    pop rbx
    ret
ss_file_close ENDP

; rcx=file ctx, rdx=offset, r8=bytes, r9=dst, arg5=out_bytes
ss_file_read_exact PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp,38h
    .allocstack 38h
    .endprolog

    mov rbx,rcx
    mov rsi,r8
    mov rdi,r9
    mov r12,[rsp+80h]
    test rbx,rbx
    jz sfr_bad
    test rdi,rdi
    jz sfr_bad
    test r12,r12
    jz sfr_bad
    mov qword ptr [r12],0

    mov rax,rdx
    add rax,rsi
    jc sfr_range
    cmp rax,[rbx].SSFileCtx.file_bytes
    ja sfr_range
    cmp qword ptr [rbx].SSFileCtx.handle,0
    je sfr_bad

    mov rcx,[rbx].SSFileCtx.handle
    xor r8d,r8d
    xor r9d,r9d
    call SetFilePointerEx
    test eax,eax
    jz sfr_read_fail

sfr_loop:
    test rsi,rsi
    jz sfr_ok

    mov r8,rsi
    cmp r8,40000000h
    jbe sfr_chunk_ready
    mov r8d,40000000h
sfr_chunk_ready:
    mov [rsp+30h],r8d
    mov dword ptr [rsp+2Ch],0

    mov rcx,[rbx].SSFileCtx.handle
    mov rdx,rdi
    lea r9,[rsp+2Ch]
    mov qword ptr [rsp+20h],0
    call ReadFile
    test eax,eax
    jz sfr_read_fail

    mov eax,dword ptr [rsp+2Ch]
    cmp eax,dword ptr [rsp+30h]
    jne sfr_read_fail

    mov r8d,eax
    add rdi,r8
    sub rsi,r8
    add qword ptr [r12],r8
    jmp sfr_loop

sfr_ok:
    xor eax,eax
    jmp sfr_done
sfr_range:
    mov eax,SS_E_RANGE
    jmp sfr_done
sfr_read_fail:
    mov eax,SS_E_READ
    jmp sfr_done
sfr_bad:
    mov eax,SS_E_INVALID
sfr_done:
    add rsp,38h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ss_file_read_exact ENDP

ss_mem_init PROC
    test rcx,rcx
    jz smi_bad
    test rdx,rdx
    jz smi_bad
    mov [rcx].SSMemCtx.base,rdx
    mov [rcx].SSMemCtx.bytes,r8
    xor eax,eax
    ret
smi_bad:
    mov eax,SS_E_INVALID
    ret
ss_mem_init ENDP

; rcx=mem ctx, rdx=offset, r8=bytes, r9=dst, arg5=out_bytes
ss_mem_read_exact PROC
    push rsi
    push rdi
    mov r10,[rsp+38h]
    test rcx,rcx
    jz smr_bad
    test r9,r9
    jz smr_bad
    test r10,r10
    jz smr_bad
    mov qword ptr [r10],0
    mov rax,rdx
    add rax,r8
    jc smr_range
    cmp rax,[rcx].SSMemCtx.bytes
    ja smr_range

    mov rsi,[rcx].SSMemCtx.base
    add rsi,rdx
    mov rdi,r9
    mov rcx,r8
    rep movsb
    mov [r10],r8
    xor eax,eax
    jmp smr_done
smr_range:
    mov eax,SS_E_RANGE
    jmp smr_done
smr_bad:
    mov eax,SS_E_INVALID
smr_done:
    pop rdi
    pop rsi
    ret
ss_mem_read_exact ENDP

; direct concrete dispatch, no provider function pointer
ss_provider_read_exact PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog
    test rcx,rcx
    jz spr_bad
    mov r10,[rsp+50h]
    mov eax,[rcx].SSProviderRef.kind
    mov rcx,[rcx].SSProviderRef.ctx
    test rcx,rcx
    jz spr_bad
    mov [rsp+20h],r10
    cmp eax,SS_PROVIDER_FILE
    je spr_file
    cmp eax,SS_PROVIDER_MEM
    je spr_mem
    mov eax,SS_E_INVALID
    jmp spr_done
spr_file:
    call ss_file_read_exact
    jmp spr_done
spr_mem:
    call ss_mem_read_exact
    jmp spr_done
spr_bad:
    mov eax,SS_E_INVALID
spr_done:
    add rsp,28h
    ret
ss_provider_read_exact ENDP

END
