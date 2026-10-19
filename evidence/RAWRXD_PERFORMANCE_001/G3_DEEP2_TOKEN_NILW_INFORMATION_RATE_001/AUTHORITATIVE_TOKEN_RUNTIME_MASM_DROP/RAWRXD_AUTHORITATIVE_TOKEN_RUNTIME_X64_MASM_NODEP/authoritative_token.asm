option casemap:none
include authoritative_token.inc

.code

; MulDivU64
; rcx=a, rdx=b, r8=divisor
; rax=(a*b)/divisor
; r9=0 success, r9=1 arithmetic fault
MulDivU64 PROC
    xor r9d, r9d
    test r8, r8
    jz md_fault

    mov rax, rcx
    mul rdx                    ; RDX:RAX = a*b
    cmp rdx, r8               ; quotient would overflow 64b if high >= divisor
    jae md_fault
    div r8
    ret

md_fault:
    xor eax, eax
    mov r9d, 1
    ret
MulDivU64 ENDP

; SetWitness
; rcx=result*, edx=index, r8=state
SetWitness PROC
    mov qword ptr [rcx].DerivedTokenRuntime.witness_state[rdx*8], r8
    ret
SetWitness ENDP

; AuthoritativeTokenEvaluate(raw*, derived*)
; Windows x64 ABI: rcx=raw, rdx=derived.
AuthoritativeTokenEvaluate PROC FRAME
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
    push r15
    .pushreg r15
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov rsi, rcx              ; raw
    mov rdi, rdx              ; derived

    ; Zero derived structure.
    xor eax, eax
    mov rcx, SIZEOF DerivedTokenRuntime
    mov rdx, rdi
zero_loop:
    test rcx, rcx
    jz zero_done
    mov byte ptr [rdx], al
    inc rdx
    dec rcx
    jmp zero_loop
zero_done:

    ; Default all 15 witnesses to NOT_RUN.
    xor ebx, ebx
init_w:
    cmp ebx, WITNESS_COUNT
    jae derive_metrics
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[rbx*8], PROOF_NOT_RUN
    inc ebx
    jmp init_w

derive_metrics:
    ; TOTAL / ACTIVE must be present before ratio derivation.
    mov r12, [rsi].RawTokenRuntime.total_logical_weights
    mov r13, [rsi].RawTokenRuntime.active_logical_weight_visits

    ; Run-level opportunity = total_model_weights * generated_tokens.
    ; This makes TOKEN_NILW explicitly per generated token.
    test r12, r12
    jz metric_fault
    mov r14, [rsi].RawTokenRuntime.generated_tokens
    test r14, r14
    jz metrics_done
    mov rax, r12
    mul r14
    test rdx, rdx
    jnz metric_fault
    mov r15, rax              ; total logical weight opportunities in run

    ; physicalization_ppm = active logical weight visits / opportunities.
    mov rcx, r13
    mov rdx, 1000000
    mov r8, r15
    call MulDivU64
    test r9, r9
    jnz metric_fault
    mov [rdi].DerivedTokenRuntime.physicalization_ppm, rax

    ; Select numerator family and derive total_new_bits + active_bpw.
    mov rax, [rsi].RawTokenRuntime.form
    cmp rax, NILW_FORM_A
    je derive_form_a
    cmp rax, NILW_FORM_B
    je derive_form_b
    jmp metrics_done

derive_form_a:
    ; active_bpw = active_representation_bits * 1e6 / active_weight_visits
    test r13, r13
    jz metric_fault
    mov rcx, [rsi].RawTokenRuntime.active_representation_bits
    mov rdx, 1000000
    mov r8, r13
    call MulDivU64
    test r9, r9
    jnz metric_fault
    mov [rdi].DerivedTokenRuntime.active_bpw_x1e6, rax

    ; new_information_fraction = new_information / active_representation
    mov r14, [rsi].RawTokenRuntime.active_representation_bits
    test r14, r14
    jz metrics_done
    mov rcx, [rsi].RawTokenRuntime.new_information_bits
    mov rdx, 1000000
    mov r8, r14
    call MulDivU64
    test r9, r9
    jnz metric_fault
    mov [rdi].DerivedTokenRuntime.new_information_fraction_ppm, rax

    ; total_new_bits = new_information_bits + overhead_bits
    mov rax, [rsi].RawTokenRuntime.new_information_bits
    add rax, [rsi].RawTokenRuntime.overhead_bits
    jc metric_fault
    mov [rdi].DerivedTokenRuntime.total_new_bits, rax
    jmp derive_common

derive_form_b:
    ; active_bpw = new_payload_bits * 1e6 / active_weight_visits
    test r13, r13
    jz metric_fault
    mov rcx, [rsi].RawTokenRuntime.new_payload_bits
    mov rdx, 1000000
    mov r8, r13
    call MulDivU64
    test r9, r9
    jnz metric_fault
    mov [rdi].DerivedTokenRuntime.active_bpw_x1e6, rax

    ; total_new_bits = new_payload_bits + overhead_bits
    mov rax, [rsi].RawTokenRuntime.new_payload_bits
    add rax, [rsi].RawTokenRuntime.overhead_bits
    jc metric_fault
    mov [rdi].DerivedTokenRuntime.total_new_bits, rax

derive_common:
    ; token_nilw = total_new_bits * 1e9 / (tokens * total_weights)
    mov rcx, [rdi].DerivedTokenRuntime.total_new_bits
    mov rdx, 1000000000
    mov r8, r15
    call MulDivU64
    test r9, r9
    jnz metric_fault
    mov [rdi].DerivedTokenRuntime.token_nilw_x1e9, rax

    ; bytes/token = total_new_bits / 8 / generated_tokens
    mov r14, [rsi].RawTokenRuntime.generated_tokens
    test r14, r14
    jz metrics_done
    mov rax, [rdi].DerivedTokenRuntime.total_new_bits
    xor edx, edx
    mov rcx, 8
    div rcx
    xor edx, edx
    div r14
    mov [rdi].DerivedTokenRuntime.new_payload_bytes_per_token, rax

    ; TPS x1000 = generated_tokens * 1e12 / wall_ns
    mov r15, [rsi].RawTokenRuntime.wall_ns
    test r15, r15
    jz metrics_done
    mov rcx, r14
    mov rdx, 1000000000000
    mov r8, r15
    call MulDivU64
    test r9, r9
    jnz metric_fault
    mov [rdi].DerivedTokenRuntime.tps_x1000, rax

    ; information_rate_Bps = (total_new_bits / 8) * 1e9 / wall_ns
    ; = total_new_bits * 125000000 / wall_ns  (BYTES/s, not bits/s)
    mov rcx, [rdi].DerivedTokenRuntime.total_new_bits
    mov rdx, 125000000
    mov r8, r15
    call MulDivU64
    test r9, r9
    jnz metric_fault
    mov [rdi].DerivedTokenRuntime.information_rate_Bps, rax
    jmp metrics_done

metric_fault:
    mov qword ptr [rdi].DerivedTokenRuntime.arithmetic_fault, 1

metrics_done:
    ; W01 ACTIVE_SUBSET
    mov rax, [rsi].RawTokenRuntime.active_subset_samples
    test rax, rax
    jz w01_done
    cmp [rsi].RawTokenRuntime.generated_tokens, 0
    je w01_done
    mov rax, r13
    test rax, rax
    jz w01_fail
    mov rax, r12
    mul [rsi].RawTokenRuntime.generated_tokens
    test rdx, rdx
    jnz w01_fail
    cmp r13, rax
    jae w01_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W01_ACTIVE_SUBSET*8], PROOF_PASS
    jmp w01_done
w01_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W01_ACTIVE_SUBSET*8], PROOF_FAIL
w01_done:

    ; W02 NEW_PAYLOAD
    mov rax, [rsi].RawTokenRuntime.payload_bits_fetched
    test rax, rax
    jz w02_done
    mov rbx, [rsi].RawTokenRuntime.form
    cmp rbx, NILW_FORM_A
    je w02_a
    cmp rbx, NILW_FORM_B
    je w02_b
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W02_NEW_PAYLOAD*8], PROOF_FAIL
    jmp w02_done
w02_a:
    cmp [rsi].RawTokenRuntime.new_information_bits, 0
    je w02_fail
    jmp w02_pass
w02_b:
    cmp [rsi].RawTokenRuntime.new_payload_bits, 0
    je w02_fail
w02_pass:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W02_NEW_PAYLOAD*8], PROOF_PASS
    jmp w02_done
w02_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W02_NEW_PAYLOAD*8], PROOF_FAIL
w02_done:

    ; W03 REUSE
    mov rax, [rsi].RawTokenRuntime.reuse_events
    or rax, [rsi].RawTokenRuntime.reused_bits
    jz w03_done
    cmp [rsi].RawTokenRuntime.reuse_events, 0
    je w03_fail
    cmp [rsi].RawTokenRuntime.reused_bits, 0
    je w03_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W03_REUSE*8], PROOF_PASS
    jmp w03_done
w03_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W03_REUSE*8], PROOF_FAIL
w03_done:

    ; W04 OVERHEAD - explicit measurement event required, zero overhead allowed.
    cmp [rsi].RawTokenRuntime.overhead_samples, 0
    je w04_done
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W04_OVERHEAD*8], PROOF_PASS
w04_done:

    ; W05 FORM_SELECTION
    mov rax, [rsi].RawTokenRuntime.form
    cmp rax, NILW_FORM_A
    je w05_a
    cmp rax, NILW_FORM_B
    je w05_b
    cmp rax, 0
    je w05_done
    jmp w05_fail
w05_a:
    cmp [rsi].RawTokenRuntime.active_representation_bits, 0
    je w05_fail
    cmp [rsi].RawTokenRuntime.new_payload_bits, 0
    jne w05_fail
    mov rax, [rsi].RawTokenRuntime.new_information_bits
    cmp rax, [rsi].RawTokenRuntime.active_representation_bits
    ja w05_fail
    jmp w05_pass
w05_b:
    cmp [rsi].RawTokenRuntime.new_payload_bits, 0
    je w05_fail
    cmp [rsi].RawTokenRuntime.active_representation_bits, 0
    jne w05_fail
    cmp [rsi].RawTokenRuntime.new_information_bits, 0
    jne w05_fail
w05_pass:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W05_FORM_SELECTION*8], PROOF_PASS
    jmp w05_done
w05_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W05_FORM_SELECTION*8], PROOF_FAIL
w05_done:

    ; W06 ACTIVE_BPW
    cmp [rdi].DerivedTokenRuntime.active_bpw_x1e6, 0
    je w06_done
    cmp [rdi].DerivedTokenRuntime.arithmetic_fault, 0
    jne w06_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W06_ACTIVE_BPW*8], PROOF_PASS
    jmp w06_done
w06_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W06_ACTIVE_BPW*8], PROOF_FAIL
w06_done:

    ; W07 TOKEN_NILW: hard target <= 0.0008 => x1e9 <= 800000.
    cmp [rdi].DerivedTokenRuntime.total_new_bits, 0
    je w07_done
    cmp [rdi].DerivedTokenRuntime.arithmetic_fault, 0
    jne w07_fail
    cmp [rdi].DerivedTokenRuntime.token_nilw_x1e9, 800000
    ja w07_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W07_TOKEN_NILW*8], PROOF_PASS
    jmp w07_done
w07_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W07_TOKEN_NILW*8], PROOF_FAIL
w07_done:

    ; W08 BANDWIDTH <= 1 GB/s
    cmp [rsi].RawTokenRuntime.wall_ns, 0
    je w08_done
    cmp [rdi].DerivedTokenRuntime.arithmetic_fault, 0
    jne w08_fail
    cmp [rdi].DerivedTokenRuntime.information_rate_Bps, 1000000000
    ja w08_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W08_BANDWIDTH*8], PROOF_PASS
    jmp w08_done
w08_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W08_BANDWIDTH*8], PROOF_FAIL
w08_done:

    ; W09 TOKEN_RATE >= 10 TPS and >=128 tokens
    cmp [rsi].RawTokenRuntime.generated_tokens, 0
    je w09_done
    cmp [rsi].RawTokenRuntime.generated_tokens, 128
    jb w09_fail
    cmp [rdi].DerivedTokenRuntime.tps_x1000, 10000
    jb w09_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W09_TOKEN_RATE*8], PROOF_PASS
    jmp w09_done
w09_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W09_TOKEN_RATE*8], PROOF_FAIL
w09_done:

    ; W10 <=100 MB/token
    cmp [rsi].RawTokenRuntime.generated_tokens, 0
    je w10_done
    cmp [rdi].DerivedTokenRuntime.new_payload_bytes_per_token, 100000000
    ja w10_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W10_PAYLOAD_PER_TOKEN*8], PROOF_PASS
    jmp w10_done
w10_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W10_PAYLOAD_PER_TOKEN*8], PROOF_FAIL
w10_done:

    ; W11 no model or layer materialization.
    mov rax, [rsi].RawTokenRuntime.full_model_materialization
    or rax, [rsi].RawTokenRuntime.full_layer_materialization
    jnz w11_fail
    ; Only mark PASS once a nonzero live token run exists.
    cmp [rsi].RawTokenRuntime.generated_tokens, 0
    je w11_done
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W11_FULL_MATERIAL*8], PROOF_PASS
    jmp w11_done
w11_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W11_FULL_MATERIAL*8], PROOF_FAIL
w11_done:

    ; W12 quality samples >0 and zero failures.
    cmp [rsi].RawTokenRuntime.quality_samples, 0
    je w12_done
    cmp [rsi].RawTokenRuntime.quality_failures, 0
    jne w12_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W12_QUALITY*8], PROOF_PASS
    jmp w12_done
w12_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W12_QUALITY*8], PROOF_FAIL
w12_done:

    ; W13 longrun stability.
    cmp [rsi].RawTokenRuntime.generated_tokens, 128
    jb w13_done
    mov rax, [rsi].RawTokenRuntime.longrun_failures
    or rax, [rsi].RawTokenRuntime.payload_budget_overflow
    or rax, [rsi].RawTokenRuntime.stale_generation_faults
    jnz w13_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W13_LONGRUN*8], PROOF_PASS
    jmp w13_done
w13_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W13_LONGRUN*8], PROOF_FAIL
w13_done:

    ; W14 exact accounting closure.
    cmp [rsi].RawTokenRuntime.payload_bits_fetched, 0
    je w14_done
    mov rax, [rsi].RawTokenRuntime.payload_bits_fetched
    cmp rax, [rsi].RawTokenRuntime.component_bits_sum
    jne w14_fail
    cmp rax, [rsi].RawTokenRuntime.class_bits_sum
    jne w14_fail
    cmp [rsi].RawTokenRuntime.unaccounted_bits, 0
    jne w14_fail
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W14_ACCOUNTING*8], PROOF_PASS
    jmp w14_done
w14_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W14_ACCOUNTING*8], PROOF_FAIL
w14_done:

    ; Derive W15 and counts from W01..W14 only.
    xor r12d, r12d            ; pass
    xor r13d, r13d            ; fail
    xor r14d, r14d            ; notrun
    xor ebx, ebx
count_loop:
    cmp ebx, 14
    jae count_done
    mov rax, [rdi].DerivedTokenRuntime.witness_state[rbx*8]
    cmp rax, PROOF_PASS
    je count_pass
    cmp rax, PROOF_FAIL
    je count_fail
    inc r14
    jmp count_next
count_pass:
    inc r12
    jmp count_next
count_fail:
    inc r13
count_next:
    inc ebx
    jmp count_loop

count_done:
    mov [rdi].DerivedTokenRuntime.passing_witnesses, r12
    mov [rdi].DerivedTokenRuntime.failing_witnesses, r13
    mov [rdi].DerivedTokenRuntime.notrun_witnesses, r14

    cmp r12, 14
    jne auth_fail
    test r13, r13
    jnz auth_fail
    test r14, r14
    jnz auth_fail
    cmp [rdi].DerivedTokenRuntime.arithmetic_fault, 0
    jne auth_fail

    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W15_AUTH_DERIVATION*8], PROOF_PASS
    mov qword ptr [rdi].DerivedTokenRuntime.authorized_pass, 1
    jmp eval_done

auth_fail:
    mov qword ptr [rdi].DerivedTokenRuntime.witness_state[W15_AUTH_DERIVATION*8], PROOF_FAIL
    mov qword ptr [rdi].DerivedTokenRuntime.authorized_pass, 0

eval_done:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
AuthoritativeTokenEvaluate ENDP

END
