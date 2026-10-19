option casemap:none
include authoritative_decode.inc

.code

AuthoritativeDecodeEvaluate PROC FRAME
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
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov rsi, rcx
    mov rdi, rdx

    ; Zero derived output.
    xor eax, eax
    mov rcx, SIZEOF DerivedDecodeRuntime
    mov rdx, rdi
zero_loop:
    test rcx, rcx
    jz init_witnesses
    mov byte ptr [rdx], al
    inc rdx
    dec rcx
    jmp zero_loop

init_witnesses:
    xor ebx, ebx
iw_loop:
    cmp ebx, DECODE_WITNESS_COUNT
    jae d01
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[rbx*8], PROOF_NOT_RUN
    inc ebx
    jmp iw_loop

; D01 PRODUCT_OPEN
d01:
    cmp [rsi].RawDecodeRuntime.product_open_attempts, 0
    je d02
    mov rax, [rsi].RawDecodeRuntime.product_open_success
    cmp rax, [rsi].RawDecodeRuntime.product_open_attempts
    jne d01_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D01_PRODUCT_OPEN*8], PROOF_PASS
    jmp d02
d01_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D01_PRODUCT_OPEN*8], PROOF_FAIL

; D02 SESSION_ENTER
d02:
    cmp [rsi].RawDecodeRuntime.session_enter_attempts, 0
    je d03
    mov rax, [rsi].RawDecodeRuntime.session_enter_success
    cmp rax, [rsi].RawDecodeRuntime.session_enter_attempts
    jne d02_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D02_SESSION_ENTER*8], PROOF_PASS
    jmp d03
d02_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D02_SESSION_ENTER*8], PROOF_FAIL

; D03 DECODE_ENTER
d03:
    cmp [rsi].RawDecodeRuntime.decode_enter_count, 0
    je d04
    mov rax, [rsi].RawDecodeRuntime.decode_exit_count
    cmp rax, [rsi].RawDecodeRuntime.decode_enter_count
    jne d03_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D03_DECODE_ENTER*8], PROOF_PASS
    jmp d04
d03_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D03_DECODE_ENTER*8], PROOF_FAIL

; D04 LAYER_FORWARD
d04:
    cmp [rsi].RawDecodeRuntime.expected_layer_forwards, 0
    je d05
    mov rax, [rsi].RawDecodeRuntime.layer_forward_calls
    cmp rax, [rsi].RawDecodeRuntime.expected_layer_forwards
    jne d04_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D04_LAYER_FORWARD*8], PROOF_PASS
    jmp d05
d04_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D04_LAYER_FORWARD*8], PROOF_FAIL

; D05 LMHEAD
d05:
    cmp [rsi].RawDecodeRuntime.generated_tokens, 0
    je d06
    mov rax, [rsi].RawDecodeRuntime.lmhead_calls
    cmp rax, [rsi].RawDecodeRuntime.generated_tokens
    jb d05_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D05_LMHEAD*8], PROOF_PASS
    jmp d06
d05_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D05_LMHEAD*8], PROOF_FAIL

; D06 LOGITS
d06:
    cmp [rsi].RawDecodeRuntime.generated_tokens, 0
    je d07
    mov rax, [rsi].RawDecodeRuntime.logits_ready_count
    cmp rax, [rsi].RawDecodeRuntime.generated_tokens
    jne d06_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D06_LOGITS*8], PROOF_PASS
    jmp d07
d06_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D06_LOGITS*8], PROOF_FAIL

; D07 TOKEN_SELECT
d07:
    cmp [rsi].RawDecodeRuntime.generated_tokens, 0
    je d08
    mov rax, [rsi].RawDecodeRuntime.token_select_count
    cmp rax, [rsi].RawDecodeRuntime.generated_tokens
    jne d07_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D07_TOKEN_SELECT*8], PROOF_PASS
    jmp d08
d07_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D07_TOKEN_SELECT*8], PROOF_FAIL

; D08 TOKEN_COMMIT
d08:
    cmp [rsi].RawDecodeRuntime.generated_tokens, 0
    je d09
    mov rax, [rsi].RawDecodeRuntime.token_commit_count
    cmp rax, [rsi].RawDecodeRuntime.generated_tokens
    jne d08_fail
    cmp [rsi].RawDecodeRuntime.zero_token_commit_count, 0
    jne d08_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D08_TOKEN_COMMIT*8], PROOF_PASS
    jmp d09
d08_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D08_TOKEN_COMMIT*8], PROOF_FAIL

; D09 STEP_MONOTONIC
d09:
    cmp [rsi].RawDecodeRuntime.generated_tokens, 0
    je d10
    cmp [rsi].RawDecodeRuntime.step_regression_count, 0
    jne d09_fail
    mov rax, [rsi].RawDecodeRuntime.last_step_id
    cmp rax, [rsi].RawDecodeRuntime.first_step_id
    jb d09_fail

    ; Inclusive step span must equal generated token count.
    sub rax, [rsi].RawDecodeRuntime.first_step_id
    inc rax
    cmp rax, [rsi].RawDecodeRuntime.generated_tokens
    jne d09_fail

    ; One monotonic step observation per generated token.
    mov rax, [rsi].RawDecodeRuntime.step_observation_count
    cmp rax, [rsi].RawDecodeRuntime.generated_tokens
    jne d09_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D09_STEP_MONOTONIC*8], PROOF_PASS
    jmp d10
d09_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D09_STEP_MONOTONIC*8], PROOF_FAIL

; D10 NO_DUP_COMMIT
d10:
    cmp [rsi].RawDecodeRuntime.token_commit_count, 0
    je d11
    cmp [rsi].RawDecodeRuntime.duplicate_commit_count, 0
    jne d10_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D10_NO_DUP_COMMIT*8], PROOF_PASS
    jmp d11
d10_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D10_NO_DUP_COMMIT*8], PROOF_FAIL

; D11 OUTPUT_PROGRESS
d11:
    cmp [rsi].RawDecodeRuntime.generated_tokens, 0
    je d12
    cmp [rsi].RawDecodeRuntime.output_bytes, 0
    je d11_fail
    mov rax, [rsi].RawDecodeRuntime.output_tokens_visible
    cmp rax, [rsi].RawDecodeRuntime.generated_tokens
    jne d11_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D11_OUTPUT_PROGRESS*8], PROOF_PASS
    jmp d12
d11_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D11_OUTPUT_PROGRESS*8], PROOF_FAIL

; D12 ERROR_FREE
d12:
    cmp [rsi].RawDecodeRuntime.decode_enter_count, 0
    je d13
    mov rax, [rsi].RawDecodeRuntime.decode_fault_count
    or rax, [rsi].RawDecodeRuntime.av_count
    or rax, [rsi].RawDecodeRuntime.heap_fault_count
    jnz d12_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D12_ERROR_FREE*8], PROOF_PASS
    jmp d13
d12_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D12_ERROR_FREE*8], PROOF_FAIL

; D13 SINGLE_PATH_AUTH
d13:
    mov rax, [rsi].RawDecodeRuntime.declared_path
    cmp rax, PATH_HOST
    je d13_host
    cmp rax, PATH_GPU
    je d13_gpu
    cmp rax, PATH_MIXED
    je d13_fail
    jmp d14

d13_host:
    cmp [rsi].RawDecodeRuntime.host_forward_calls, 0
    je d13_fail
    cmp [rsi].RawDecodeRuntime.gpu_forward_calls, 0
    jne d13_fail
    jmp d13_pass

d13_gpu:
    cmp [rsi].RawDecodeRuntime.gpu_forward_calls, 0
    je d13_fail
    cmp [rsi].RawDecodeRuntime.host_forward_calls, 0
    jne d13_fail
    jmp d13_pass

d13_pass:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D13_SINGLE_PATH_AUTH*8], PROOF_PASS
    jmp d14
d13_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D13_SINGLE_PATH_AUTH*8], PROOF_FAIL

; D14 COUNT_CLOSURE
d14:
    cmp [rsi].RawDecodeRuntime.generated_tokens, 0
    je derive_auth
    mov rax, [rsi].RawDecodeRuntime.generated_tokens
    mov rbx, [rsi].RawDecodeRuntime.logits_ready_count
    sub rbx, rax
    mov [rdi].DerivedDecodeRuntime.count_closure_delta, rbx
    test rbx, rbx
    jne d14_fail

    mov rbx, [rsi].RawDecodeRuntime.token_select_count
    cmp rbx, rax
    jne d14_fail
    mov rbx, [rsi].RawDecodeRuntime.token_commit_count
    cmp rbx, rax
    jne d14_fail
    mov rbx, [rsi].RawDecodeRuntime.output_tokens_visible
    cmp rbx, rax
    jne d14_fail
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D14_COUNT_CLOSURE*8], PROOF_PASS
    jmp derive_auth

d14_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D14_COUNT_CLOSURE*8], PROOF_FAIL

derive_auth:
    xor r12d, r12d ; pass
    xor r13d, r13d ; fail
    xor ebx, ebx   ; notrun
    xor ecx, ecx

count_loop:
    cmp ecx, 14
    jae count_done
    mov rax, [rdi].DerivedDecodeRuntime.witness_state[rcx*8]
    cmp rax, PROOF_PASS
    je c_pass
    cmp rax, PROOF_FAIL
    je c_fail
    inc rbx
    jmp c_next
c_pass:
    inc r12
    jmp c_next
c_fail:
    inc r13
c_next:
    inc ecx
    jmp count_loop

count_done:
    mov [rdi].DerivedDecodeRuntime.passing_witnesses, r12
    mov [rdi].DerivedDecodeRuntime.failing_witnesses, r13
    mov [rdi].DerivedDecodeRuntime.notrun_witnesses, rbx

    ; D15 conjunction only.
    cmp r12, 14
    jne auth_fail
    test r13, r13
    jnz auth_fail
    test rbx, rbx
    jnz auth_fail

    ; Decode-specific minimum endurance.
    cmp [rsi].RawDecodeRuntime.generated_tokens, 128
    jb auth_fail

    ; Never authorize a full-model/full-layer materializing path.
    cmp [rsi].RawDecodeRuntime.full_model_materialization, 0
    jne auth_fail
    cmp [rsi].RawDecodeRuntime.full_layer_materialization, 0
    jne auth_fail

    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D15_AUTH_DERIVATION*8], PROOF_PASS
    mov qword ptr [rdi].DerivedDecodeRuntime.decode_authorized, 1
    jmp done

auth_fail:
    mov qword ptr [rdi].DerivedDecodeRuntime.witness_state[D15_AUTH_DERIVATION*8], PROOF_FAIL
    mov qword ptr [rdi].DerivedDecodeRuntime.decode_authorized, 0

done:
    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
AuthoritativeDecodeEvaluate ENDP

END
