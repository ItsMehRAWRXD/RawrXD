; uf_lease.asm — acquire / commit / release (UCF-003/004)
INCLUDE UncoherentFabric64.inc

.code

; rcx=tid rdx=domain r8=*outHandle — read lease if CURRENT
UF_AcquireRead PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    .endprolog
    mov rsi, r8
    test rsi, rsi
    jz ar_bad
    cmp rdx, UF_MAX_DOMAIN
    jae ar_bad
    call UF_FindTensor
    cmp rax, -1
    je ar_nf
    imul rax, rax, UF_TEN_SIZE
    lea rbx, g_uf_tensors
    add rbx, rax
    mov ecx, edx
    mov eax, 1
    shl eax, cl
    test dword ptr [rbx + UF_TEN_RES_CUR + 4], eax
    jz ar_stale
    ; lease++
    lock inc dword ptr [rbx + UF_TEN_LEASE0 + rdx*4]
    ; re-validate CURRENT after lease (evict race)
    test dword ptr [rbx + UF_TEN_RES_CUR + 4], eax
    jz ar_undo
    mov rax, [rbx + UF_TEN_GEN0 + rdx*8]
    cmp rax, [rbx + UF_TEN_LATEST]
    jne ar_undo
    mov rax, [rbx + UF_TEN_HANDLE0 + rdx*8]
    mov [rsi], rax
    xor eax, eax
    pop rsi
    pop rbx
    ret
ar_undo:
    lock dec dword ptr [rbx + UF_TEN_LEASE0 + rdx*4]
    mov eax, UF_ERR_STALE
    pop rsi
    pop rbx
    ret
ar_stale:
    mov eax, UF_ERR_STALE
    pop rsi
    pop rbx
    ret
ar_nf:
    mov eax, UF_ERR_NOTFOUND
    pop rsi
    pop rbx
    ret
ar_bad:
    mov eax, UF_ERR_PARAM
    pop rsi
    pop rbx
    ret
UF_AcquireRead ENDP

; rcx=tid rdx=domain r8=*outHandle — exclusive write (leases==0)
UF_AcquireWrite PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    .endprolog
    mov rsi, r8
    test rsi, rsi
    jz aw_bad
    cmp rdx, UF_MAX_DOMAIN
    jae aw_bad
    call UF_FindTensor
    cmp rax, -1
    je aw_nf
    imul rax, rax, UF_TEN_SIZE
    lea rbx, g_uf_tensors
    add rbx, rax
    cmp dword ptr [rbx + UF_TEN_LEASE0 + rdx*4], 0
    jne aw_lease
    mov ecx, edx
    mov eax, 1
    shl eax, cl
    lock bts dword ptr [rbx + UF_TEN_OWN_BUSY + 4], ecx
    jc aw_busy
    lock or dword ptr [rbx + UF_TEN_OWN_BUSY], eax
    lock or dword ptr [rbx + UF_TEN_RES_CUR], eax
    lock inc dword ptr [rbx + UF_TEN_LEASE0 + rdx*4]
    mov rax, [rbx + UF_TEN_HANDLE0 + rdx*8]
    mov [rsi], rax
    xor eax, eax
    pop rsi
    pop rbx
    ret
aw_busy:
    mov eax, UF_ERR_BUSY
    pop rsi
    pop rbx
    ret
aw_lease:
    mov eax, UF_ERR_LEASE
    pop rsi
    pop rbx
    ret
aw_nf:
    mov eax, UF_ERR_NOTFOUND
    pop rsi
    pop rbx
    ret
aw_bad:
    mov eax, UF_ERR_PARAM
    pop rsi
    pop rbx
    ret
UF_AcquireWrite ENDP

; rcx=tid rdx=domain — bump LatestGen; this domain CURRENT; peers STALE
UF_CommitWrite PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    cmp rdx, UF_MAX_DOMAIN
    jae cw_bad
    call UF_FindTensor
    cmp rax, -1
    je cw_nf
    imul rax, rax, UF_TEN_SIZE
    lea rbx, g_uf_tensors
    add rbx, rax
    lock inc qword ptr [rbx + UF_TEN_LATEST]
    mov rax, [rbx + UF_TEN_LATEST]
    mov [rbx + UF_TEN_GEN0 + rdx*8], rax
    mov ecx, edx
    mov eax, 1
    shl eax, cl
    mov dword ptr [rbx + UF_TEN_RES_CUR + 4], eax
    lock or dword ptr [rbx + UF_TEN_RES_CUR], eax
    lock btr dword ptr [rbx + UF_TEN_OWN_BUSY + 4], ecx
    xor eax, eax
    pop rbx
    ret
cw_nf:
    mov eax, UF_ERR_NOTFOUND
    pop rbx
    ret
cw_bad:
    mov eax, UF_ERR_PARAM
    pop rbx
    ret
UF_CommitWrite ENDP

; rcx=tid rdx=domain
UF_Release PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    cmp rdx, UF_MAX_DOMAIN
    jae rl_bad
    call UF_FindTensor
    cmp rax, -1
    je rl_nf
    imul rax, rax, UF_TEN_SIZE
    lea rbx, g_uf_tensors
    add rbx, rax
    lock dec dword ptr [rbx + UF_TEN_LEASE0 + rdx*4]
    xor eax, eax
    pop rbx
    ret
rl_nf:
    mov eax, UF_ERR_NOTFOUND
    pop rbx
    ret
rl_bad:
    mov eax, UF_ERR_PARAM
    pop rbx
    ret
UF_Release ENDP
