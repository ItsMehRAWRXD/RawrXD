option casemap:none
include tokencode15.inc

.code

TokenCodeEvaluate PROC FRAME
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
    push r14
    .pushreg r14
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rsi, rcx
    mov rdi, rdx

    ; Clear the complete result so stale authorization cannot survive.
    xor eax, eax
    mov rcx, SIZEOF TokenCodeResult
    mov rdx, rdi
te_zero:
    test rcx, rcx
    jz te_zero_done
    mov byte ptr [rdx], al
    inc rdx
    dec rcx
    jmp te_zero
te_zero_done:

    test rsi, rsi
    jz te_done
    test rdi, rdi
    jz te_done

    ; Explicit NOT_RUN initialization.
    xor ebx, ebx
te_init:
    cmp ebx, TE_WITNESS_COUNT
    jae te_eval
    mov qword ptr [rdi].TokenCodeResult.witness_state[rbx*8], TE_NOT_RUN
    inc ebx
    jmp te_init

te_eval:
    cmp [rsi].TokenCodeRaw.run_observed, 0
    je te_count

    mov r12, [rsi].TokenCodeRaw.generation_id
    mov r13, [rsi].TokenCodeRaw.generated
    mov r14, [rsi].TokenCodeRaw.encode_request_count

; TE01 — generation binding.
    test r12, r12
    jz te01_fail
    cmp [rsi].TokenCodeRaw.observation_epoch, r12
    jne te01_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE01_GENERATION_BOUND*8], TE_PASS
    jmp te02
te01_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE01_GENERATION_BOUND*8], TE_FAIL

; TE02 — generated > 0.
te02:
    test r13, r13
    jz te02_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE02_GENERATED_NONZERO*8], TE_PASS
    jmp te03
te02_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE02_GENERATED_NONZERO*8], TE_FAIL

; TE03 — one encode request per generated token.
te03:
    test r13, r13
    jz te03_fail
    cmp r14, r13
    jne te03_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE03_REQUEST_CLOSURE*8], TE_PASS
    jmp te04
te03_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE03_REQUEST_CLOSURE*8], TE_FAIL

; TE04 — tokencode count closes exactly to generated.
te04:
    mov rax, [rsi].TokenCodeRaw.tokencode_count
    cmp rax, r13
    jne te04_fail
    test r13, r13
    jz te04_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE04_TOKENCODE_CLOSURE*8], TE_PASS
    jmp te05
te04_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE04_TOKENCODE_CLOSURE*8], TE_FAIL

; TE05 — token input closure.
te05:
    mov rax, [rsi].TokenCodeRaw.token_input_count
    cmp rax, r13
    jne te05_fail
    test r13, r13
    jz te05_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE05_INPUT_CLOSURE*8], TE_PASS
    jmp te06
te05_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE05_INPUT_CLOSURE*8], TE_FAIL

; TE06 — encoded token output closure.
te06:
    mov rax, [rsi].TokenCodeRaw.token_output_count
    cmp rax, r13
    jne te06_fail
    test r13, r13
    jz te06_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE06_OUTPUT_CLOSURE*8], TE_PASS
    jmp te07
te06_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE06_OUTPUT_CLOSURE*8], TE_FAIL

; TE07 — vocabulary range is valid and all observed token IDs are in range.
te07:
    mov rax, [rsi].TokenCodeRaw.vocab_size
    test rax, rax
    jz te07_fail
    cmp [rsi].TokenCodeRaw.out_of_vocab_count, 0
    jne te07_fail
    mov rcx, [rsi].TokenCodeRaw.min_token_id
    cmp rcx, [rsi].TokenCodeRaw.max_token_id
    ja te07_fail
    cmp [rsi].TokenCodeRaw.max_token_id, rax
    jae te07_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE07_VOCAB_BOUNDS*8], TE_PASS
    jmp te08
te07_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE07_VOCAB_BOUNDS*8], TE_FAIL

; TE08 — commit count closes exactly.
te08:
    mov rax, [rsi].TokenCodeRaw.encode_commit_count
    cmp rax, r13
    jne te08_fail
    test r13, r13
    jz te08_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE08_ENCODE_COMMIT_CLOSURE*8], TE_PASS
    jmp te09
te08_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE08_ENCODE_COMMIT_CLOSURE*8], TE_FAIL

; TE09 — no duplicate encode commit.
te09:
    cmp [rsi].TokenCodeRaw.duplicate_encode_count, 0
    jne te09_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE09_NO_DUPLICATE_ENCODE*8], TE_PASS
    jmp te10
te09_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE09_NO_DUPLICATE_ENCODE*8], TE_FAIL

; TE10 — inclusive position span equals generated.
te10:
    mov rax, [rsi].TokenCodeRaw.last_position
    cmp rax, [rsi].TokenCodeRaw.first_position
    jb te10_fail
    sub rax, [rsi].TokenCodeRaw.first_position
    inc rax
    cmp rax, r13
    jne te10_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE10_MONOTONIC_POSITION_SPAN*8], TE_PASS
    jmp te11
te10_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE10_MONOTONIC_POSITION_SPAN*8], TE_FAIL

; TE11 — one position observation per generated token.
te11:
    mov rax, [rsi].TokenCodeRaw.position_observation_count
    cmp rax, r13
    jne te11_fail
    test r13, r13
    jz te11_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE11_POSITION_OBSERVATION*8], TE_PASS
    jmp te12
te11_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE11_POSITION_OBSERVATION*8], TE_FAIL

; TE12 — encode -> decode roundtrip must close exactly with zero mismatches.
te12:
    mov rax, [rsi].TokenCodeRaw.decode_roundtrip_count
    cmp rax, r13
    jne te12_fail
    cmp [rsi].TokenCodeRaw.roundtrip_mismatch_count, 0
    jne te12_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE12_DECODE_ROUNDTRIP*8], TE_PASS
    jmp te13
te12_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE12_DECODE_ROUNDTRIP*8], TE_FAIL

; TE13 — exact byte emission closure.
te13:
    mov rax, [rsi].TokenCodeRaw.output_bytes_expected
    test rax, rax
    jz te13_fail
    cmp [rsi].TokenCodeRaw.output_bytes_written, rax
    jne te13_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE13_OUTPUT_BYTES_CLOSURE*8], TE_PASS
    jmp te14
te13_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE13_OUTPUT_BYTES_CLOSURE*8], TE_FAIL

; TE14 — no buffer/error/stale/nonfinite faults.
te14:
    mov rax, [rsi].TokenCodeRaw.buffer_overflow_count
    or rax, [rsi].TokenCodeRaw.encode_error_count
    or rax, [rsi].TokenCodeRaw.stale_generation_faults
    or rax, [rsi].TokenCodeRaw.nonfinite_state_count
    jnz te14_fail
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE14_BUFFER_AND_ERROR_FREE*8], TE_PASS
    jmp te_count
te14_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE14_BUFFER_AND_ERROR_FREE*8], TE_FAIL

; TE15 — conjunction only. NOT_RUN never equals PASS.
te_count:
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor ebx, ebx
te_count_loop:
    cmp ebx, 14
    jae te_count_done
    mov rax, [rdi].TokenCodeResult.witness_state[rbx*8]
    cmp rax, TE_PASS
    je te_count_pass
    cmp rax, TE_FAIL
    je te_count_fail
    inc r14
    jmp te_count_next
te_count_pass:
    inc r12
    jmp te_count_next
te_count_fail:
    inc r13
te_count_next:
    inc ebx
    jmp te_count_loop

te_count_done:
    mov [rdi].TokenCodeResult.passing_witnesses, r12
    mov [rdi].TokenCodeResult.failing_witnesses, r13
    mov [rdi].TokenCodeResult.notrun_witnesses, r14

    cmp r12, 14
    jne te_auth_fail
    test r13, r13
    jnz te_auth_fail
    test r14, r14
    jnz te_auth_fail

    mov qword ptr [rdi].TokenCodeResult.witness_state[TE15_AUTH_DERIVATION*8], TE_PASS
    mov qword ptr [rdi].TokenCodeResult.tokencode_authorized, 1
    jmp te_done

te_auth_fail:
    mov qword ptr [rdi].TokenCodeResult.witness_state[TE15_AUTH_DERIVATION*8], TE_FAIL
    mov qword ptr [rdi].TokenCodeResult.tokencode_authorized, 0

te_done:
    add rsp, 20h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
TokenCodeEvaluate ENDP

END
