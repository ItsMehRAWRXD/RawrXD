; ============================================================================
; DEEP2_FULL_DECODE_TOKEN_REAL
; Pure x64 MASM implementation of:
;   real logits -> greedy token select -> real token commit -> state advance
; repeated for N tokens.
;
; No llama.cpp / Ollama / Python / Torch / third-party runtime dependency.
; No TPS calculation and no promotion logic exist in this module.
; ============================================================================

OPTION CASEMAP:NONE
include deep2_decode_abi.inc

PUBLIC Deep2DecodeInit
PUBLIC Deep2SelectArgmaxF32
PUBLIC Deep2RunFullDecode
PUBLIC Deep2DecodeValidateWitness

.const
ALIGN 4
D2_NEG_INF DWORD 0FF800000h

.code

; ----------------------------------------------------------------------------
; int Deep2DecodeInit(Deep2DecodeContext* ctx, const Deep2DecodeBinding* bind)
; RCX=ctx, RDX=bind
; Returns EAX=1 success, 0 failure.
; ----------------------------------------------------------------------------
Deep2DecodeInit PROC
    test rcx, rcx
    jz  d2_init_fail
    test rdx, rdx
    jz  d2_init_bad_bind

    mov rax, qword ptr [rdx + D2_BIND_FORWARD_FN]
    test rax, rax
    jz  d2_init_bad_bind
    mov r8, qword ptr [rdx + D2_BIND_COMMIT_FN]
    test r8, r8
    jz  d2_init_bad_bind
    mov r9, qword ptr [rdx + D2_BIND_ADVANCE_FN]
    test r9, r9
    jz  d2_init_bad_bind

    mov r10, D2DEC_MAGIC
    mov qword ptr [rcx + D2_CTX_MAGIC], r10
    mov dword ptr [rcx + D2_CTX_VERSION], D2DEC_VERSION
    mov dword ptr [rcx + D2_CTX_SIZE], D2DEC_CTX_SIZE

    mov r10, qword ptr [rdx + D2_BIND_USER_CTX]
    mov qword ptr [rcx + D2_CTX_USER_CTX], r10
    mov qword ptr [rcx + D2_CTX_FORWARD_FN], rax
    mov qword ptr [rcx + D2_CTX_COMMIT_FN], r8
    mov qword ptr [rcx + D2_CTX_ADVANCE_FN], r9

    xor eax, eax
    mov qword ptr [rcx + D2_CTX_POSITION], rax
    mov qword ptr [rcx + D2_CTX_GENERATED], rax
    mov qword ptr [rcx + D2_CTX_FORWARD_CALLS], rax
    mov qword ptr [rcx + D2_CTX_COMMIT_CALLS], rax
    mov qword ptr [rcx + D2_CTX_ADVANCE_CALLS], rax
    mov qword ptr [rcx + D2_CTX_LAST_TOKEN], rax
    mov qword ptr [rcx + D2_CTX_LAST_LOGITS], rax
    mov qword ptr [rcx + D2_CTX_LAST_VOCAB], rax
    mov qword ptr [rcx + D2_CTX_RUNTIME_FLAGS], rax
    mov dword ptr [rcx + D2_CTX_ERROR_CODE], D2_ERR_NONE
    mov dword ptr [rcx + D2_CTX_RESERVED0], eax
    mov qword ptr [rcx + D2_CTX_TARGET_TOKENS], rax
    mov qword ptr [rcx + D2_CTX_RESERVED1], rax

    mov eax, 1
    ret

d2_init_bad_bind:
    test rcx, rcx
    jz d2_init_fail
    mov dword ptr [rcx + D2_CTX_ERROR_CODE], D2_ERR_BAD_BINDING
d2_init_fail:
    xor eax, eax
    ret
Deep2DecodeInit ENDP


; ----------------------------------------------------------------------------
; int Deep2SelectArgmaxF32(const float* logits, uint64 count, uint64* out_token)
; RCX=logits, RDX=count, R8=out_token
;
; NaNs are ignored. Ties retain the lowest token id.
; Returns 0 if args invalid or all entries are NaN.
; ----------------------------------------------------------------------------
Deep2SelectArgmaxF32 PROC
    test rcx, rcx
    jz d2_argmax_fail
    test rdx, rdx
    jz d2_argmax_fail
    test r8, r8
    jz d2_argmax_fail

    movss xmm0, dword ptr [D2_NEG_INF]
    xor r9, r9                 ; i
    xor r10, r10               ; best index
    xor r11d, r11d             ; found flag

d2_argmax_loop:
    cmp r9, rdx
    jae d2_argmax_done

    movss xmm1, dword ptr [rcx + r9*4]
    ucomiss xmm1, xmm1
    jp d2_argmax_next           ; skip NaN

    test r11d, r11d
    jz d2_argmax_take

    comiss xmm1, xmm0
    jbe d2_argmax_next          ; <= current best keeps lower id

d2_argmax_take:
    movaps xmm0, xmm1
    mov r10, r9
    mov r11d, 1

d2_argmax_next:
    inc r9
    jmp d2_argmax_loop

d2_argmax_done:
    test r11d, r11d
    jz d2_argmax_fail
    mov qword ptr [r8], r10
    mov eax, 1
    ret

d2_argmax_fail:
    xor eax, eax
    ret
Deep2SelectArgmaxF32 ENDP


; ----------------------------------------------------------------------------
; int Deep2RunFullDecode(Deep2DecodeContext* ctx, uint64 token_count)
; RCX=ctx, RDX=token_count
;
; The function returns success only after token_count complete cycles:
;   forward -> observed real logits -> select -> commit -> advance
;
; FULL_DECODE_OBSERVED is set only at the end when the observed counters agree.
; ----------------------------------------------------------------------------
Deep2RunFullDecode PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64                ; 32 shadow + locals, preserves call alignment

    mov rbx, rcx               ; ctx
    mov r12, rdx               ; requested token count

    test rbx, rbx
    jz d2_run_fail_noctx

    mov rax, D2DEC_MAGIC
    cmp qword ptr [rbx + D2_CTX_MAGIC], rax
    jne d2_run_badabi
    cmp dword ptr [rbx + D2_CTX_VERSION], D2DEC_VERSION
    jne d2_run_badabi
    cmp dword ptr [rbx + D2_CTX_SIZE], D2DEC_CTX_SIZE
    jne d2_run_badabi

    test r12, r12
    jz d2_run_badtarget

    mov rax, qword ptr [rbx + D2_CTX_FORWARD_FN]
    test rax, rax
    jz d2_run_badbinding
    mov rax, qword ptr [rbx + D2_CTX_COMMIT_FN]
    test rax, rax
    jz d2_run_badbinding
    mov rax, qword ptr [rbx + D2_CTX_ADVANCE_FN]
    test rax, rax
    jz d2_run_badbinding

    ; Per-run observed fields start clean. Position is intentionally preserved.
    xor eax, eax
    mov qword ptr [rbx + D2_CTX_GENERATED], rax
    mov qword ptr [rbx + D2_CTX_FORWARD_CALLS], rax
    mov qword ptr [rbx + D2_CTX_COMMIT_CALLS], rax
    mov qword ptr [rbx + D2_CTX_ADVANCE_CALLS], rax
    mov qword ptr [rbx + D2_CTX_LAST_TOKEN], rax
    mov qword ptr [rbx + D2_CTX_LAST_LOGITS], rax
    mov qword ptr [rbx + D2_CTX_LAST_VOCAB], rax
    mov qword ptr [rbx + D2_CTX_RUNTIME_FLAGS], rax
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_NONE
    mov qword ptr [rbx + D2_CTX_TARGET_TOKENS], r12

    xor r13, r13               ; completed cycles

d2_run_loop:
    cmp r13, r12
    jae d2_run_finish

    ; locals:
    ; [rsp+32] = logits pointer
    ; [rsp+40] = vocab count
    ; [rsp+48] = selected token
    xor eax, eax
    mov qword ptr [rsp+32], rax
    mov qword ptr [rsp+40], rax
    mov qword ptr [rsp+48], rax

    ; ForwardFn(user_ctx, position, &logits, &vocab)
    mov rcx, qword ptr [rbx + D2_CTX_USER_CTX]
    mov rdx, qword ptr [rbx + D2_CTX_POSITION]
    lea r8, [rsp+32]
    lea r9, [rsp+40]
    mov rax, qword ptr [rbx + D2_CTX_FORWARD_FN]
    call rax
    test eax, eax
    jz d2_run_forward_fail

    inc qword ptr [rbx + D2_CTX_FORWARD_CALLS]

    mov r14, qword ptr [rsp+32]
    mov r15, qword ptr [rsp+40]
    test r14, r14
    jz d2_run_badlogits
    test r15, r15
    jz d2_run_badlogits

    mov qword ptr [rbx + D2_CTX_LAST_LOGITS], r14
    mov qword ptr [rbx + D2_CTX_LAST_VOCAB], r15
    or qword ptr [rbx + D2_CTX_RUNTIME_FLAGS], D2_FLAG_FULL_FORWARD_OBSERVED

    ; Select actual token from returned logits.
    mov rcx, r14
    mov rdx, r15
    lea r8, [rsp+48]
    call Deep2SelectArgmaxF32
    test eax, eax
    jz d2_run_select_fail

    mov rsi, qword ptr [rsp+48]
    mov qword ptr [rbx + D2_CTX_LAST_TOKEN], rsi
    or qword ptr [rbx + D2_CTX_RUNTIME_FLAGS], D2_FLAG_TOKEN_SELECTED

    ; CommitFn(user_ctx, token, position, 0)
    mov rcx, qword ptr [rbx + D2_CTX_USER_CTX]
    mov rdx, rsi
    mov r8, qword ptr [rbx + D2_CTX_POSITION]
    xor r9d, r9d
    mov rax, qword ptr [rbx + D2_CTX_COMMIT_FN]
    call rax
    test eax, eax
    jz d2_run_commit_fail

    inc qword ptr [rbx + D2_CTX_COMMIT_CALLS]
    inc qword ptr [rbx + D2_CTX_GENERATED]
    or qword ptr [rbx + D2_CTX_RUNTIME_FLAGS], D2_FLAG_TOKEN_COMMITTED

    ; AdvanceFn(user_ctx, token, next_position, 0)
    mov rcx, qword ptr [rbx + D2_CTX_USER_CTX]
    mov rdx, rsi
    mov r8, qword ptr [rbx + D2_CTX_POSITION]
    inc r8
    xor r9d, r9d
    mov rax, qword ptr [rbx + D2_CTX_ADVANCE_FN]
    call rax
    test eax, eax
    jz d2_run_advance_fail

    inc qword ptr [rbx + D2_CTX_ADVANCE_CALLS]
    inc qword ptr [rbx + D2_CTX_POSITION]
    or qword ptr [rbx + D2_CTX_RUNTIME_FLAGS], D2_FLAG_STATE_ADVANCED

    inc r13
    jmp d2_run_loop

d2_run_finish:
    ; All counters must independently agree with the requested token count.
    cmp qword ptr [rbx + D2_CTX_GENERATED], r12
    jne d2_run_counter_fail
    cmp qword ptr [rbx + D2_CTX_FORWARD_CALLS], r12
    jne d2_run_counter_fail
    cmp qword ptr [rbx + D2_CTX_COMMIT_CALLS], r12
    jne d2_run_counter_fail
    cmp qword ptr [rbx + D2_CTX_ADVANCE_CALLS], r12
    jne d2_run_counter_fail

    or qword ptr [rbx + D2_CTX_RUNTIME_FLAGS], D2_FLAG_FULL_DECODE_OBSERVED
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_NONE
    mov eax, 1
    jmp d2_run_exit

d2_run_badabi:
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_BAD_ABI
    jmp d2_run_fail
d2_run_badbinding:
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_BAD_BINDING
    jmp d2_run_fail
d2_run_badtarget:
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_BAD_TARGET
    jmp d2_run_fail
d2_run_forward_fail:
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_FORWARD_FAILED
    jmp d2_run_fail
d2_run_badlogits:
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_BAD_LOGITS
    jmp d2_run_fail
d2_run_select_fail:
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_SELECT_FAILED
    jmp d2_run_fail
d2_run_commit_fail:
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_COMMIT_FAILED
    jmp d2_run_fail
d2_run_advance_fail:
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_ADVANCE_FAILED
    jmp d2_run_fail
d2_run_counter_fail:
    mov dword ptr [rbx + D2_CTX_ERROR_CODE], D2_ERR_COUNTER_MISMATCH
    jmp d2_run_fail

d2_run_fail:
    ; Critical rule: a partial/failed run can never retain FULL_DECODE_OBSERVED.
    mov rax, NOT D2_FLAG_FULL_DECODE_OBSERVED
    and qword ptr [rbx + D2_CTX_RUNTIME_FLAGS], rax
    xor eax, eax
    jmp d2_run_exit

d2_run_fail_noctx:
    xor eax, eax

d2_run_exit:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2RunFullDecode ENDP


; ----------------------------------------------------------------------------
; int Deep2DecodeValidateWitness(const Deep2DecodeContext* ctx)
;
; Mechanical witness check only. It does not create state and does not repair
; missing counters/flags. EAX=1 iff a completed decode already exists.
; ----------------------------------------------------------------------------
Deep2DecodeValidateWitness PROC
    test rcx, rcx
    jz d2_witness_fail

    mov rax, D2DEC_MAGIC
    cmp qword ptr [rcx + D2_CTX_MAGIC], rax
    jne d2_witness_fail
    cmp dword ptr [rcx + D2_CTX_VERSION], D2DEC_VERSION
    jne d2_witness_fail
    cmp dword ptr [rcx + D2_CTX_SIZE], D2DEC_CTX_SIZE
    jne d2_witness_fail
    cmp dword ptr [rcx + D2_CTX_ERROR_CODE], D2_ERR_NONE
    jne d2_witness_fail

    mov rdx, qword ptr [rcx + D2_CTX_TARGET_TOKENS]
    test rdx, rdx
    jz d2_witness_fail

    cmp qword ptr [rcx + D2_CTX_GENERATED], rdx
    jne d2_witness_fail
    cmp qword ptr [rcx + D2_CTX_FORWARD_CALLS], rdx
    jne d2_witness_fail
    cmp qword ptr [rcx + D2_CTX_COMMIT_CALLS], rdx
    jne d2_witness_fail
    cmp qword ptr [rcx + D2_CTX_ADVANCE_CALLS], rdx
    jne d2_witness_fail

    mov rax, qword ptr [rcx + D2_CTX_RUNTIME_FLAGS]
    mov rdx, D2_REQUIRED_FULL_DECODE_FLAGS
    and rax, rdx
    cmp rax, rdx
    jne d2_witness_fail

    mov eax, 1
    ret

d2_witness_fail:
    xor eax, eax
    ret
Deep2DecodeValidateWitness ENDP

END
