; uf_ensure.asm — EnsureCurrent / Evict / query masks
INCLUDE UncoherentFabric64.inc

.code

; rcx=tid rdx=dstDomain — migrate any CURRENT replica → dst
UF_EnsureCurrent PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    sub rsp, 40h
    .allocstack 40h
    .endprolog
    mov r12, rcx
    mov r13, rdx
    cmp r13, UF_MAX_DOMAIN
    jae ec_bad
    call UF_FindTensor
    cmp rax, -1
    je ec_nf
    imul rsi, rax, UF_TEN_SIZE
    lea rbx, g_uf_tensors
    add rbx, rsi
    mov ecx, r13d
    mov eax, 1
    shl eax, cl
    test dword ptr [rbx + UF_TEN_RES_CUR + 4], eax
    jz ec_need
    mov rax, [rbx + UF_TEN_GEN0 + r13*8]
    cmp rax, [rbx + UF_TEN_LATEST]
    je ec_ok
ec_need:
    ; find source domain with CURRENT gen
    xor edi, edi
ec_src:
    cmp edi, UF_MAX_DOMAIN
    jae ec_nosrc
    mov ecx, edi
    mov eax, 1
    shl eax, cl
    test dword ptr [rbx + UF_TEN_RES_CUR + 4], eax
    jz ec_src_next
    mov rax, [rbx + UF_TEN_GEN0 + rdi*8]
    cmp rax, [rbx + UF_TEN_LATEST]
    je ec_got
ec_src_next:
    inc edi
    jmp ec_src
ec_got:
    cmp qword ptr [g_uf_allocCb], 0
    je ec_nocb
    cmp qword ptr [g_uf_copyCb], 0
    je ec_nocb
    ; lease source
    lock inc dword ptr [rbx + UF_TEN_LEASE0 + rdi*4]
    ; alloc dst if needed
    cmp qword ptr [rbx + UF_TEN_HANDLE0 + r13*8], 0
    jne ec_have
    mov rcx, [g_uf_ctx]
    mov rdx, r13
    mov r8, [rbx + UF_TEN_BYTES]
    call qword ptr [g_uf_allocCb]
    test rax, rax
    jz ec_alloc
    mov [rbx + UF_TEN_HANDLE0 + r13*8], rax
ec_have:
    mov rcx, [g_uf_ctx]
    mov rdx, rdi
    mov r8, [rbx + UF_TEN_HANDLE0 + rdi*8]
    mov r9, r13
    mov rax, [rbx + UF_TEN_HANDLE0 + r13*8]
    mov [rsp + 20h], rax
    mov rax, [rbx + UF_TEN_BYTES]
    mov [rsp + 28h], rax
    call qword ptr [g_uf_copyCb]
    test eax, eax
    jnz ec_copy
    mov rax, [rbx + UF_TEN_LATEST]
    mov [rbx + UF_TEN_GEN0 + r13*8], rax
    mov ecx, r13d
    mov eax, 1
    shl eax, cl
    lock or dword ptr [rbx + UF_TEN_RES_CUR], eax
    lock or dword ptr [rbx + UF_TEN_RES_CUR + 4], eax
    lock dec dword ptr [rbx + UF_TEN_LEASE0 + rdi*4]
ec_ok:
    xor eax, eax
    jmp ec_out
ec_copy:
    lock dec dword ptr [rbx + UF_TEN_LEASE0 + rdi*4]
    mov eax, UF_ERR_COPY
    jmp ec_out
ec_alloc:
    lock dec dword ptr [rbx + UF_TEN_LEASE0 + rdi*4]
    mov eax, UF_ERR_ALLOC
    jmp ec_out
ec_nosrc:
    mov eax, UF_ERR_NO_SOURCE
    jmp ec_out
ec_nocb:
    mov eax, UF_ERR_NO_CB
    jmp ec_out
ec_nf:
    mov eax, UF_ERR_NOTFOUND
    jmp ec_out
ec_bad:
    mov eax, UF_ERR_PARAM
ec_out:
    add rsp, 40h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
UF_EnsureCurrent ENDP
