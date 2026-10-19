option casemap:none
include ..\include\deep2_nodep.inc

PUBLIC Deep2DecodeInit
PUBLIC Deep2DecodeSetPosition
PUBLIC Deep2DecodeSeedLiveState
PUBLIC Deep2DecodeSetTarget
PUBLIC Deep2DecodeBeginToken
PUBLIC Deep2ObserveForward
PUBLIC Deep2RunFullDecode
EXTERN Deep2AttemptDecodeGrant:PROC

.code

; rcx=ctx, rdx=config
Deep2DecodeInit PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    test rcx, rcx
    jz init_fail
    test rdx, rdx
    jz init_fail
    mov rbx, rcx
    xor rax, rax
    mov qword ptr [rbx+D2_CTX_MAGIC], rax
    mov qword ptr [rbx+D2_CTX_POSITION], rax
    mov qword ptr [rbx+D2_CTX_TARGET_TOKENS], rax
    mov qword ptr [rbx+D2_CTX_GENERATED], rax
    mov qword ptr [rbx+D2_CTX_EXEC_GENERATION], rax
    mov qword ptr [rbx+D2_CTX_FORWARD_CALLS], rax
    mov qword ptr [rbx+D2_CTX_SELECT_CALLS], rax
    mov qword ptr [rbx+D2_CTX_COMMIT_CALLS], rax
    mov qword ptr [rbx+D2_CTX_ADVANCE_CALLS], rax
    mov qword ptr [rbx+D2_CTX_FULL_FORWARD_OBS], rax
    mov qword ptr [rbx+D2_CTX_TOKEN_SELECT_OBS], rax
    mov qword ptr [rbx+D2_CTX_TOKEN_COMMIT_OBS], rax
    mov qword ptr [rbx+D2_CTX_STATE_ADVANCE_OBS], rax
    mov qword ptr [rbx+D2_CTX_LOGITS_HANDLE], rax
    mov qword ptr [rbx+D2_CTX_VOCAB], rax
    mov qword ptr [rbx+D2_CTX_SELECTED_TOKEN], rax
    mov qword ptr [rbx+D2_CTX_SELECTED_AUX], rax
    mov qword ptr [rbx+D2_CTX_BLOCK_CURSOR], rax
    mov qword ptr [rbx+D2_CTX_BLOCKS_ENTERED], rax
    mov qword ptr [rbx+D2_CTX_BLOCKS_COMPLETED], rax
    mov qword ptr [rbx+D2_CTX_KV_POSITION], rax
    mov qword ptr [rbx+D2_CTX_EXPECTED_POSITION], rax
    mov qword ptr [rbx+D2_CTX_PROMPT_TOKENS], rax
    mov qword ptr [rbx+D2_CTX_PLAN_GENERATION], rax
    mov qword ptr [rbx+D2_CTX_TICKET_GENERATION], rax
    mov dword ptr [rbx+D2_CTX_FLAGS], 0
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_NONE
    mov dword ptr [rbx+D2_CTX_AUTHORITY], 0
    mov dword ptr [rbx+D2_CTX_FAIL_STAGE], D2_FW_NONE
    mov dword ptr [rbx+D2_CTX_FAIL_REASON], 0

    mov rax, [rdx+D2_CFG_USER]
    mov [rbx+D2_CTX_USER], rax
    mov rax, [rdx+D2_CFG_FORWARD_FN]
    test rax, rax
    jz init_badcfg
    mov [rbx+D2_CTX_FORWARD_FN], rax
    mov rax, [rdx+D2_CFG_SELECT_FN]
    test rax, rax
    jz init_badcfg
    mov [rbx+D2_CTX_SELECT_FN], rax
    mov rax, [rdx+D2_CFG_COMMIT_FN]
    test rax, rax
    jz init_badcfg
    mov [rbx+D2_CTX_COMMIT_FN], rax
    mov rax, [rdx+D2_CFG_ADVANCE_FN]
    test rax, rax
    jz init_badcfg
    mov [rbx+D2_CTX_ADVANCE_FN], rax

    mov rax, D2DEC_MAGIC
    mov [rbx+D2_CTX_MAGIC], rax
    mov dword ptr [rbx+D2_CTX_VERSION], D2DEC_VERSION
    mov eax, 1
    pop rbx
    ret
init_badcfg:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_BAD_CONFIG
init_fail:
    xor eax, eax
    pop rbx
    ret
Deep2DecodeInit ENDP

; rcx=ctx, rdx=absolute next-token position
Deep2DecodeSetPosition PROC
    test rcx, rcx
    jz sp_fail
    mov rax, D2DEC_MAGIC
    cmp [rcx+D2_CTX_MAGIC], rax
    jne sp_fail
    mov [rcx+D2_CTX_POSITION], rdx
    mov [rcx+D2_CTX_EXPECTED_POSITION], rdx
    mov eax, 1
    ret
sp_fail:
    xor eax, eax
    ret
Deep2DecodeSetPosition ENDP

; rcx=ctx, rdx=kv_pos, r8=prompt_tokens, r9=expected_next_position
Deep2DecodeSeedLiveState PROC
    test rcx, rcx
    jz seed_fail
    mov rax, D2DEC_MAGIC
    cmp [rcx+D2_CTX_MAGIC], rax
    jne seed_fail
    mov [rcx+D2_CTX_KV_POSITION], rdx
    mov [rcx+D2_CTX_PROMPT_TOKENS], r8
    mov [rcx+D2_CTX_EXPECTED_POSITION], r9
    mov [rcx+D2_CTX_POSITION], r9
    mov eax, 1
    ret
seed_fail:
    xor eax, eax
    ret
Deep2DecodeSeedLiveState ENDP

; rcx=ctx, rdx=target tokens
Deep2DecodeSetTarget PROC
    test rcx, rcx
    jz st_fail
    test rdx, rdx
    jz st_bad
    mov [rcx+D2_CTX_TARGET_TOKENS], rdx
    mov eax, 1
    ret
st_bad:
    mov dword ptr [rcx+D2_CTX_ERROR], D2_ERR_BAD_TARGET
st_fail:
    xor eax, eax
    ret
Deep2DecodeSetTarget ENDP

; Legal per-token executor reset only. Does NOT clear KV, position, model, weights, or input.
Deep2DecodeBeginToken PROC
    test rcx, rcx
    jz bt_fail
    inc qword ptr [rcx+D2_CTX_EXEC_GENERATION]
    mov qword ptr [rcx+D2_CTX_BLOCK_CURSOR], 0
    mov qword ptr [rcx+D2_CTX_BLOCKS_ENTERED], 0
    mov qword ptr [rcx+D2_CTX_BLOCKS_COMPLETED], 0
    mov qword ptr [rcx+D2_CTX_FULL_FORWARD_OBS], 0
    mov qword ptr [rcx+D2_CTX_LOGITS_HANDLE], 0
    mov qword ptr [rcx+D2_CTX_VOCAB], 0
    mov dword ptr [rcx+D2_CTX_FAIL_STAGE], D2_FW_NONE
    mov dword ptr [rcx+D2_CTX_FAIL_REASON], 0
    inc qword ptr [rcx+D2_CTX_PLAN_GENERATION]
    inc qword ptr [rcx+D2_CTX_TICKET_GENERATION]
    mov eax, 1
    ret
bt_fail:
    xor eax, eax
    ret
Deep2DecodeBeginToken ENDP

; rcx=ctx, rdx=blocks_entered, r8=blocks_completed, r9=flags
; flags bit0=final_norm_real, bit1=lm_head_real, bit2=continuity_valid
Deep2ObserveForward PROC
    test rcx, rcx
    jz of_fail
    mov [rcx+D2_CTX_BLOCKS_ENTERED], rdx
    mov [rcx+D2_CTX_BLOCKS_COMPLETED], r8
    cmp rdx, r8
    jne of_unproven
    test rdx, rdx
    jz of_unproven
    mov rax, r9
    and eax, 7
    cmp eax, 7
    jne of_unproven
    mov qword ptr [rcx+D2_CTX_FULL_FORWARD_OBS], 1
    or dword ptr [rcx+D2_CTX_AUTHORITY], D2_AUTH_FULL_FORWARD
    mov eax, 1
    ret
of_unproven:
    mov qword ptr [rcx+D2_CTX_FULL_FORWARD_OBS], 0
    mov dword ptr [rcx+D2_CTX_ERROR], D2_ERR_FORWARD_UNPROVEN
of_fail:
    xor eax, eax
    ret
Deep2ObserveForward ENDP

; callback ABI:
; ForwardFn(user, position, &opaque_logits_handle, &vocab) -> eax != 0
; SelectFn(user, opaque_logits_handle, vocab, &token) -> eax != 0
; CommitFn(user, token, position, ctx) -> eax != 0
; AdvanceFn(user, new_position, ctx, 0) -> eax != 0
Deep2RunFullDecode PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov rbx, rcx
    test rbx, rbx
    jz run_badctx
    mov rax, D2DEC_MAGIC
    cmp [rbx+D2_CTX_MAGIC], rax
    jne run_badctx
    mov rax, [rbx+D2_CTX_TARGET_TOKENS]
    test rax, rax
    jz run_badtarget
    mov rsi, [rbx+D2_CTX_GENERATED]

run_loop:
    cmp rsi, [rbx+D2_CTX_TARGET_TOKENS]
    jae run_done

    mov rcx, rbx
    call Deep2DecodeBeginToken
    test eax, eax
    jz run_badctx

    ; position must be the live next decode position supplied by product state.
    mov rax, [rbx+D2_CTX_POSITION]
    cmp rax, [rbx+D2_CTX_EXPECTED_POSITION]
    jne run_badpos

    ; ForwardFn(user, pos, &logits_handle, &vocab)
    mov rcx, [rbx+D2_CTX_USER]
    mov rdx, [rbx+D2_CTX_POSITION]
    lea r8, [rbx+D2_CTX_LOGITS_HANDLE]
    lea r9, [rbx+D2_CTX_VOCAB]
    mov rax, [rbx+D2_CTX_FORWARD_FN]
    call rax
    test eax, eax
    jz run_fwfail
    inc qword ptr [rbx+D2_CTX_FORWARD_CALLS]

    cmp qword ptr [rbx+D2_CTX_FULL_FORWARD_OBS], 1
    jne run_fwunproven
    cmp qword ptr [rbx+D2_CTX_LOGITS_HANDLE], 0
    je run_badlogits
    cmp qword ptr [rbx+D2_CTX_VOCAB], 0
    je run_badlogits

    ; SelectFn(user, opaque_logits_handle, vocab, &token)
    mov rcx, [rbx+D2_CTX_USER]
    mov rdx, [rbx+D2_CTX_LOGITS_HANDLE]
    mov r8, [rbx+D2_CTX_VOCAB]
    lea r9, [rbx+D2_CTX_SELECTED_TOKEN]
    mov rax, [rbx+D2_CTX_SELECT_FN]
    call rax
    test eax, eax
    jz run_selectfail
    inc qword ptr [rbx+D2_CTX_SELECT_CALLS]
    inc qword ptr [rbx+D2_CTX_TOKEN_SELECT_OBS]
    or dword ptr [rbx+D2_CTX_AUTHORITY], D2_AUTH_TOKEN_SELECTED

    ; CommitFn(user, token, position, ctx)
    mov rcx, [rbx+D2_CTX_USER]
    mov rdx, [rbx+D2_CTX_SELECTED_TOKEN]
    mov r8, [rbx+D2_CTX_POSITION]
    mov r9, rbx
    mov rax, [rbx+D2_CTX_COMMIT_FN]
    call rax
    test eax, eax
    jz run_commitfail
    inc qword ptr [rbx+D2_CTX_COMMIT_CALLS]
    inc qword ptr [rbx+D2_CTX_TOKEN_COMMIT_OBS]
    or dword ptr [rbx+D2_CTX_AUTHORITY], D2_AUTH_TOKEN_COMMITTED

    ; AdvanceFn(user, new_position, ctx, 0)
    mov rdi, [rbx+D2_CTX_POSITION]
    inc rdi
    mov rcx, [rbx+D2_CTX_USER]
    mov rdx, rdi
    mov r8, rbx
    xor r9d, r9d
    mov rax, [rbx+D2_CTX_ADVANCE_FN]
    call rax
    test eax, eax
    jz run_advancefail
    inc qword ptr [rbx+D2_CTX_ADVANCE_CALLS]
    inc qword ptr [rbx+D2_CTX_STATE_ADVANCE_OBS]
    or dword ptr [rbx+D2_CTX_AUTHORITY], D2_AUTH_STATE_ADVANCED

    mov [rbx+D2_CTX_POSITION], rdi
    mov [rbx+D2_CTX_EXPECTED_POSITION], rdi
    mov [rbx+D2_CTX_KV_POSITION], rdi
    inc qword ptr [rbx+D2_CTX_GENERATED]
    mov rsi, [rbx+D2_CTX_GENERATED]
    jmp run_loop

run_done:
    mov rcx, rbx
    call Deep2AttemptDecodeGrant
    test eax, eax
    jz run_auth_unproven
    mov eax, 1
    jmp run_exit

run_badctx:
    test rbx, rbx
    jz run_zero
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_BAD_CTX
    jmp run_zero
run_badtarget:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_BAD_TARGET
    jmp run_zero
run_badpos:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_BAD_POSITION
    mov dword ptr [rbx+D2_CTX_FAIL_STAGE], D2_FW_POSITION_MISMATCH
    jmp run_zero
run_fwfail:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_FORWARD_FAILED
    jmp run_zero
run_fwunproven:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_FORWARD_UNPROVEN
    jmp run_zero
run_badlogits:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_BAD_LOGITS
    jmp run_zero
run_selectfail:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_SELECT_FAILED
    jmp run_zero
run_commitfail:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_COMMIT_FAILED
    jmp run_zero
run_advancefail:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_ADVANCE_FAILED
    jmp run_zero
run_auth_unproven:
    mov dword ptr [rbx+D2_CTX_ERROR], D2_ERR_AUTH_UNPROVEN
run_zero:
    xor eax, eax
run_exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2RunFullDecode ENDP

END
