option casemap:none
include r671_abi.inc

ExitProcess PROTO
CreateFileA PROTO
WriteFile PROTO
CloseHandle PROTO

GENERIC_READ  equ 80000000h
GENERIC_WRITE equ 40000000h
FILE_SHARE_READ equ 1
CREATE_ALWAYS equ 2

.data
path db "r671_smoke_tensor.bin",0
vals REAL4 1.0,2.0,3.0,4.0
written DWORD 0

.data?
ctx R671Context <>
lease R671Lease <>
desc R671TensorDesc <>
res R671PrimitiveResult <>

.code
main PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp,40h
    .allocstack 40h
    .endprolog

    ; Create 16-byte F32 backing file (shareable; handle in nonvolatile rbx).
    lea rcx,path
    mov edx,GENERIC_READ
    or edx,GENERIC_WRITE
    mov r8d,FILE_SHARE_READ
    xor r9d,r9d
    mov qword ptr [rsp+20h],CREATE_ALWAYS
    mov qword ptr [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h],0
    call CreateFileA
    cmp rax,INVALID_HANDLE_VALUE
    je bad
    mov rbx,rax

    mov rcx,rbx
    lea rdx,vals
    mov r8d,16
    lea r9,written
    mov qword ptr [rsp+20h],0
    call WriteFile
    test eax,eax
    jz bad_close
    mov rcx,rbx
    call CloseHandle
    xor ebx,ebx

    lea rcx,path
    lea rdx,ctx
    call r671_open
    test eax,eax
    jnz bad_open

    lea rcx,ctx
    xor edx,edx
    mov r8d,16
    mov r9d,1
    lea rax,lease
    mov [rsp+20h],rax
    call r671_tensor_acquire
    test eax,eax
    jnz bad_acq

    mov desc.file_offset,0
    mov desc.byte_length,16
    mov desc.element_count,4
    mov desc.element_bytes,4
    mov desc.tensor_type,0

    lea rcx,lease
    lea rdx,desc
    lea r8,res
    call Deep2R671TensorPrimitive
    test eax,eax
    jnz bad_prim

    cmp res.elements_consumed,4
    jne bad_elem
    cmp res.nonfinite_count,0
    jne bad_nf
    cmp res.scalar_f32_bits,41200000h
    jne bad_sum

    lea rcx,ctx
    lea rdx,lease
    call r671_release
    test eax,eax
    jnz bad_rel
    lea rcx,ctx
    call r671_close
    test eax,eax
    jnz bad_close2

    xor ecx,ecx
    jmp exit_ecx

bad_close:
    mov rcx,rbx
    call CloseHandle
bad:
    mov ecx,1
    jmp exit_ecx
bad_open:
    mov ecx,eax
    test ecx,ecx
    jnz exit_ecx
    mov ecx,10
    jmp exit_ecx
bad_acq:
    mov ecx,11
    jmp exit_ecx
bad_prim:
    mov ecx,12
    jmp exit_ecx
bad_elem:
    mov ecx,13
    jmp exit_ecx
bad_nf:
    mov ecx,14
    jmp exit_ecx
bad_sum:
    mov ecx,15
    jmp exit_ecx
bad_rel:
    mov ecx,16
    jmp exit_ecx
bad_close2:
    mov ecx,17

exit_ecx:
    add rsp,40h
    pop rbx
    call ExitProcess
main ENDP
END
