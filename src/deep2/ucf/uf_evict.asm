; uf_evict.asm — Evict + query masks/generation
INCLUDE UncoherentFabric64.inc

.code

; rcx=tid rdx=domain
UF_Evict PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    cmp rdx, UF_MAX_DOMAIN
    jae ev_bad
    call UF_FindTensor
    cmp rax, -1
    je ev_nf
    imul rax, rax, UF_TEN_SIZE
    lea rbx, g_uf_tensors
    add rbx, rax
    cmp dword ptr [rbx + UF_TEN_LEASE0 + rdx*4], 0
    jne ev_lease
    mov ecx, edx
    mov eax, 1
    shl eax, cl
    test dword ptr [rbx + UF_TEN_OWN_BUSY + 4], eax
    jnz ev_busy
    ; only remaining CURRENT?
    mov r8d, dword ptr [rbx + UF_TEN_RES_CUR + 4]
    cmp r8d, eax
    je ev_last
    test r8d, eax
    jz ev_ok_clear
    ; free opaque
    cmp qword ptr [g_uf_freeCb], 0
    je ev_nofree
    mov r9, [rbx + UF_TEN_HANDLE0 + rdx*8]
    test r9, r9
    jz ev_nofree
    push rdx
    mov rcx, [g_uf_ctx]
    ; FreeCb(ctx, domain, handle) — domain still in stack
    mov rdx, [rsp]
    mov r8, r9
    call qword ptr [g_uf_freeCb]
    pop rdx
ev_nofree:
    mov qword ptr [rbx + UF_TEN_HANDLE0 + rdx*8], 0
    mov qword ptr [rbx + UF_TEN_GEN0 + rdx*8], 0
    mov ecx, edx
    mov eax, 1
    shl eax, cl
    not eax
    lock and dword ptr [rbx + UF_TEN_RES_CUR], eax
    lock and dword ptr [rbx + UF_TEN_RES_CUR + 4], eax
ev_ok_clear:
    xor eax, eax
    pop rbx
    ret
ev_last:
    mov eax, UF_ERR_LAST_CURRENT
    pop rbx
    ret
ev_busy:
    mov eax, UF_ERR_BUSY
    pop rbx
    ret
ev_lease:
    mov eax, UF_ERR_LEASE
    pop rbx
    ret
ev_nf:
    mov eax, UF_ERR_NOTFOUND
    pop rbx
    ret
ev_bad:
    mov eax, UF_ERR_PARAM
    pop rbx
    ret
UF_Evict ENDP

; rcx=tid rdx=*outMask
UF_QueryCurrentMask PROC
    test rdx, rdx
    jz qm_bad
    push rdx
    call UF_FindTensor
    pop rdx
    cmp rax, -1
    je qm_nf
    imul rax, rax, UF_TEN_SIZE
    lea r8, g_uf_tensors
    mov eax, dword ptr [r8 + rax + UF_TEN_RES_CUR + 4]
    mov [rdx], eax
    xor eax, eax
    ret
qm_nf:
    mov eax, UF_ERR_NOTFOUND
    ret
qm_bad:
    mov eax, UF_ERR_PARAM
    ret
UF_QueryCurrentMask ENDP

UF_QueryResidentMask PROC
    test rdx, rdx
    jz qr_bad
    push rdx
    call UF_FindTensor
    pop rdx
    cmp rax, -1
    je qr_nf
    imul rax, rax, UF_TEN_SIZE
    lea r8, g_uf_tensors
    mov eax, dword ptr [r8 + rax + UF_TEN_RES_CUR]
    mov [rdx], eax
    xor eax, eax
    ret
qr_nf:
    mov eax, UF_ERR_NOTFOUND
    ret
qr_bad:
    mov eax, UF_ERR_PARAM
    ret
UF_QueryResidentMask ENDP

; rcx=tid rdx=*outGen
UF_QueryGeneration PROC
    test rdx, rdx
    jz qg_bad
    push rdx
    call UF_FindTensor
    pop rdx
    cmp rax, -1
    je qg_nf
    imul rax, rax, UF_TEN_SIZE
    lea r8, g_uf_tensors
    mov rax, [r8 + rax + UF_TEN_LATEST]
    mov [rdx], rax
    xor eax, eax
    ret
qg_nf:
    mov eax, UF_ERR_NOTFOUND
    ret
qg_bad:
    mov eax, UF_ERR_PARAM
    ret
UF_QueryGeneration ENDP
