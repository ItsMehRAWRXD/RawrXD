; uf_tensor.asm — create / find / bind residency
INCLUDE UncoherentFabric64.inc

.code

; rcx=bytes  rdx=*outTensorId
UF_CreateTensor PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    .endprolog
    test rdx, rdx
    jz ct_bad
    cmp qword ptr [g_uf_ready], 0
    je ct_bad
    mov rsi, rdx
    mov rax, [g_uf_tensorN]
    cmp rax, UF_MAX_TENSOR
    jae ct_full
    imul rbx, rax, UF_TEN_SIZE
    lea rdx, g_uf_tensors
    add rdx, rbx
    mov rbx, [g_uf_nextId]
    mov [rdx + UF_TEN_ID], rbx
    mov [rdx + UF_TEN_BYTES], rcx
    mov qword ptr [rdx + UF_TEN_LATEST], 1
    mov dword ptr [rdx + UF_TEN_RES_CUR], 0
    mov dword ptr [rdx + UF_TEN_RES_CUR + 4], 0
    mov dword ptr [rdx + UF_TEN_OWN_BUSY], 0
    mov dword ptr [rdx + UF_TEN_OWN_BUSY + 4], 0
    xor eax, eax
ct_clr:
    mov qword ptr [rdx + UF_TEN_GEN0 + rax*8], 0
    mov dword ptr [rdx + UF_TEN_LEASE0 + rax*4], 0
    mov qword ptr [rdx + UF_TEN_HANDLE0 + rax*8], 0
    inc eax
    cmp eax, 4
    jb ct_clr
    mov [rsi], rbx
    inc qword ptr [g_uf_nextId]
    inc qword ptr [g_uf_tensorN]
    xor eax, eax
    pop rsi
    pop rbx
    ret
ct_full:
    mov eax, UF_ERR_FULL
    pop rsi
    pop rbx
    ret
ct_bad:
    mov eax, UF_ERR_PARAM
    pop rsi
    pop rbx
    ret
UF_CreateTensor ENDP

; rcx=tensorId → rax = slot index or -1
UF_FindTensor PROC
    xor edx, edx
    mov r8, [g_uf_tensorN]
ft_loop:
    cmp rdx, r8
    jae ft_miss
    imul rax, rdx, UF_TEN_SIZE
    lea r9, g_uf_tensors
    cmp [r9 + rax + UF_TEN_ID], rcx
    je ft_hit
    inc rdx
    jmp ft_loop
ft_hit:
    mov rax, rdx
    ret
ft_miss:
    mov rax, -1
    ret
UF_FindTensor ENDP

; rcx=tensorId rdx=domain r8=handle — mark resident+current at LatestGen
UF_BindResidency PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    cmp rdx, UF_MAX_DOMAIN
    jae br_bad
    call UF_FindTensor
    cmp rax, -1
    je br_nf
    imul rax, rax, UF_TEN_SIZE
    lea rbx, g_uf_tensors
    add rbx, rax
    mov [rbx + UF_TEN_HANDLE0 + rdx*8], r8
    mov rax, [rbx + UF_TEN_LATEST]
    mov [rbx + UF_TEN_GEN0 + rdx*8], rax
    mov ecx, edx
    mov eax, 1
    shl eax, cl
    lock or dword ptr [rbx + UF_TEN_RES_CUR], eax
    lock or dword ptr [rbx + UF_TEN_RES_CUR + 4], eax
    xor eax, eax
    pop rbx
    ret
br_nf:
    mov eax, UF_ERR_NOTFOUND
    pop rbx
    ret
br_bad:
    mov eax, UF_ERR_PARAM
    pop rbx
    ret
UF_BindResidency ENDP
