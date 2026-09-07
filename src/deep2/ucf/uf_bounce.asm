; uf_bounce.asm — mechanical BounceChain only
; Semantic authority: rawr_uncoherent_object_fabric.hpp
; This unit realizes atomics/lanes/copy scheduling; it does NOT define
; generation law, acquire/receipt ABI, publication, or device identity.
; A → B → A…  NEXT must not park on CURRENT. Amplitude = MaxHopBytes.
INCLUDE UncoherentFabric64.inc

.code

; rcx=tid rdx=*outMask — resident & (domainGen != latest)
UF_QueryStaleMask PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    .endprolog
    test rdx, rdx
    jz qs_bad
    mov rsi, rdx
    call UF_FindTensor
    cmp rax, -1
    je qs_nf
    imul rax, rax, UF_TEN_SIZE
    lea rbx, g_uf_tensors
    add rbx, rax
    mov r9, [rbx + UF_TEN_LATEST]
    mov r8d, dword ptr [rbx + UF_TEN_RES_CUR]
    xor eax, eax
    xor ecx, ecx
qs_loop:
    cmp ecx, UF_MAX_DOMAIN
    jae qs_done
    mov edx, 1
    shl edx, cl
    test r8d, edx
    jz qs_next
    cmp qword ptr [rbx + UF_TEN_GEN0 + rcx*8], r9
    je qs_next
    or eax, edx
qs_next:
    inc ecx
    jmp qs_loop
qs_done:
    mov [rsi], eax
    xor eax, eax
    pop rsi
    pop rbx
    ret
qs_nf:
    mov eax, UF_ERR_NOTFOUND
    pop rsi
    pop rbx
    ret
qs_bad:
    mov eax, UF_ERR_PARAM
    pop rsi
    pop rbx
    ret
UF_QueryStaleMask ENDP

; rcx=tid rdx=dst — direct Ensure; on COPY fail stage via HOST then dst
UF_EnsureCurrentStaged PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 20h
    .allocstack 20h
    .endprolog
    mov rbx, rcx
    mov rsi, rdx
    call UF_EnsureCurrent
    test eax, eax
    jz es_ok
    cmp eax, UF_ERR_COPY
    je es_stage
    cmp eax, UF_ERR_NO_SOURCE
    je es_stage
    jmp es_out
es_stage:
    ; source → HOST
    mov rcx, rbx
    mov rdx, UF_DOM_HOST
    call UF_EnsureCurrent
    test eax, eax
    jnz es_out
    ; HOST → dst
    mov rcx, rbx
    mov rdx, rsi
    call UF_EnsureCurrent
es_ok:
es_out:
    add rsp, 20h
    pop rsi
    pop rbx
    ret
UF_EnsureCurrentStaged ENDP

; rcx=tid rdx=maxHopBytes r8=laneA r9=laneB — first NEXT=A
UF_BounceChainInit PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    test rcx, rcx
    jz bi_bad
    test rdx, rdx
    jz bi_bad
    lea rbx, g_uf_bounce
    mov [rbx + UFB_TID], rcx
    mov [rbx + UFB_MAX_HOP_BYTES], rdx
    mov rax, r8
    test rax, rax
    jnz bi_a
    mov rax, UF_DOM_GPU0
bi_a:
    mov [rbx + UFB_LANEA], rax
    mov rax, r9
    test rax, rax
    jnz bi_b
    mov rax, UF_DOM_GPU1
bi_b:
    mov [rbx + UFB_LANEB], rax
    mov qword ptr [rbx + UFB_CURRENT], -1
    mov rax, [rbx + UFB_LANEA]
    mov [rbx + UFB_NEXT], rax
    mov qword ptr [rbx + UFB_EXPECT], 1
    mov qword ptr [rbx + UFB_OUT_HANDLE], 0
    mov qword ptr [rbx + UFB_FLAGS], 0
    xor eax, eax
    pop rbx
    ret
bi_bad:
    mov eax, UF_ERR_PARAM
    pop rbx
    ret
UF_BounceChainInit ENDP

; Sync ExpectedGen from tensor LatestGen
UF_BounceChainSync PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    lea rbx, g_uf_bounce
    mov rcx, [rbx + UFB_TID]
    call UF_FindTensor
    cmp rax, -1
    je bs_nf
    imul rax, rax, UF_TEN_SIZE
    lea rdx, g_uf_tensors
    mov rax, [rdx + rax + UF_TEN_LATEST]
    mov [rbx + UFB_EXPECT], rax
    xor eax, eax
    pop rbx
    ret
bs_nf:
    mov eax, UF_ERR_NOTFOUND
    pop rbx
    ret
UF_BounceChainSync ENDP

; rax = next domain
UF_BouncePeekNext PROC
    lea rax, g_uf_bounce
    mov rax, [rax + UFB_NEXT]
    ret
UF_BouncePeekNext ENDP

; rcx=*outHandle — validate expect/amplitude; Ensure NEXT; AcquireWrite
UF_BounceBeginRW PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 20h
    .allocstack 20h
    .endprolog
    mov rsi, rcx
    test rsi, rsi
    jz bb_bad
    lea rbx, g_uf_bounce
    test qword ptr [rbx + UFB_FLAGS], UFB_FLAG_LEASED
    jnz bb_busy
    mov rdi, [rbx + UFB_NEXT]
    cmp rdi, [rbx + UFB_CURRENT]
    je bb_park
    ; amplitude
    mov rcx, [rbx + UFB_TID]
    call UF_FindTensor
    cmp rax, -1
    je bb_nf
    imul rax, rax, UF_TEN_SIZE
    lea rdx, g_uf_tensors
    add rdx, rax
    mov rax, [rdx + UF_TEN_BYTES]
    cmp rax, [rbx + UFB_MAX_HOP_BYTES]
    ja bb_amp
    mov rax, [rdx + UF_TEN_LATEST]
    cmp rax, [rbx + UFB_EXPECT]
    jne bb_stale
    ; ensure NEXT current (staged)
    mov rcx, [rbx + UFB_TID]
    mov rdx, rdi
    call UF_EnsureCurrentStaged
    test eax, eax
    jnz bb_out
    mov rcx, [rbx + UFB_TID]
    mov rdx, rdi
    mov r8, rsi
    call UF_AcquireWrite
    test eax, eax
    jnz bb_out
    or qword ptr [rbx + UFB_FLAGS], UFB_FLAG_LEASED
    mov rax, [rsi]
    mov [rbx + UFB_OUT_HANDLE], rax
    xor eax, eax
    jmp bb_out
bb_park:
    mov eax, UF_ERR_PARK_CURRENT
    jmp bb_out
bb_amp:
    mov eax, UF_E_AMPLITUDE
    jmp bb_out
bb_stale:
    mov eax, UF_ERR_STALE
    jmp bb_out
bb_busy:
    mov eax, UF_ERR_BUSY
    jmp bb_out
bb_nf:
    mov eax, UF_ERR_NOTFOUND
    jmp bb_out
bb_bad:
    mov eax, UF_ERR_PARAM
bb_out:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
UF_BounceBeginRW ENDP

; CommitWrite on NEXT; release; CURRENT=NEXT; flip NEXT; Expect++
UF_BounceCommitRW PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 20h
    .allocstack 20h
    .endprolog
    lea rbx, g_uf_bounce
    test qword ptr [rbx + UFB_FLAGS], UFB_FLAG_LEASED
    jz bc_bad
    mov rsi, [rbx + UFB_NEXT]
    mov rcx, [rbx + UFB_TID]
    mov rdx, rsi
    call UF_CommitWrite
    test eax, eax
    jnz bc_out
    mov rcx, [rbx + UFB_TID]
    mov rdx, rsi
    call UF_Release
    and qword ptr [rbx + UFB_FLAGS], NOT UFB_FLAG_LEASED
    mov [rbx + UFB_CURRENT], rsi
    ; flip NEXT = opposite lane
    mov rax, [rbx + UFB_LANEA]
    cmp rsi, rax
    je bc_to_b
    mov [rbx + UFB_NEXT], rax
    jmp bc_gen
bc_to_b:
    mov rax, [rbx + UFB_LANEB]
    mov [rbx + UFB_NEXT], rax
bc_gen:
    inc qword ptr [rbx + UFB_EXPECT]
    xor eax, eax
bc_out:
    add rsp, 20h
    pop rsi
    pop rbx
    ret
bc_bad:
    mov eax, UF_ERR_PARAM
    add rsp, 20h
    pop rsi
    pop rbx
    ret
UF_BounceCommitRW ENDP
