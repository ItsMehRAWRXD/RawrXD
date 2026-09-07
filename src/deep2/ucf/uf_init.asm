; uf_init.asm — init / profile / callbacks / domain register
INCLUDE UncoherentFabric64.inc

.code

UF_FabricInit PROC FRAME
    push rdi
    .pushreg rdi
    .endprolog
    xor eax, eax
    mov qword ptr [g_uf_ready], rax
    mov qword ptr [g_uf_ctx], rax
    mov qword ptr [g_uf_allocCb], rax
    mov qword ptr [g_uf_freeCb], rax
    mov qword ptr [g_uf_copyCb], rax
    mov qword ptr [g_uf_nextId], 1
    mov qword ptr [g_uf_tensorN], rax
    lea rdi, g_uf_domains
    mov ecx, (UF_MAX_DOMAIN * UF_DOM_SIZE) / 8
    xor eax, eax
    rep stosq
    lea rdi, g_uf_tensors
    mov ecx, (UF_MAX_TENSOR * UF_TEN_SIZE) / 8
    xor eax, eax
    rep stosq
    mov qword ptr [g_uf_ready], 1
    xor eax, eax
    pop rdi
    ret
UF_FabricInit ENDP

UF_InitProfile_192G_2x24G_4T PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    lea rbx, g_uf_domains
    mov rax, 192
    shl rax, 30
    mov [rbx + UF_DOM_CAPACITY], rax
    add rbx, UF_DOM_SIZE
    mov rax, 24
    shl rax, 30
    mov [rbx + UF_DOM_CAPACITY], rax
    add rbx, UF_DOM_SIZE
    mov [rbx + UF_DOM_CAPACITY], rax
    add rbx, UF_DOM_SIZE
    mov rax, 4
    shl rax, 40
    mov [rbx + UF_DOM_CAPACITY], rax
    xor eax, eax
    pop rbx
    ret
UF_InitProfile_192G_2x24G_4T ENDP

UF_SetCallbacks PROC
    mov [g_uf_ctx], rcx
    mov [g_uf_allocCb], rdx
    mov [g_uf_freeCb], r8
    mov [g_uf_copyCb], r9
    xor eax, eax
    ret
UF_SetCallbacks ENDP

UF_RegisterDomain PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    cmp rcx, UF_MAX_DOMAIN
    jae uf_reg_bad
    imul rax, rcx, UF_DOM_SIZE
    lea rbx, g_uf_domains
    add rbx, rax
    mov [rbx + UF_DOM_CAPACITY], rdx
    mov [rbx + UF_DOM_FLAGS], r8
    xor eax, eax
    pop rbx
    ret
uf_reg_bad:
    mov eax, UF_ERR_PARAM
    pop rbx
    ret
UF_RegisterDomain ENDP

UF_SetDomainOpaque PROC
    cmp rcx, UF_MAX_DOMAIN
    jae uf_opq_bad
    imul rax, rcx, UF_DOM_SIZE
    lea rbx, g_uf_domains
    mov [rbx + rax + UF_DOM_OPAQUE], rdx
    xor eax, eax
    ret
uf_opq_bad:
    mov eax, UF_ERR_PARAM
    ret
UF_SetDomainOpaque ENDP
