option casemap:none
include tokencode_tokenid_domain.inc

.code

TokenIdEvaluate PROC FRAME
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rsi, rcx
    mov rdi, rdx

    ; Fail closed.
    xor eax, eax
    mov rcx, SIZEOF TokenIdResult
    mov rdx, rdi
tid_zero:
    test rcx, rcx
    jz tid_zero_done
    mov byte ptr [rdx], al
    inc rdx
    dec rcx
    jmp tid_zero
tid_zero_done:

    test rsi, rsi
    jz tid_done
    test rdi, rdi
    jz tid_done
    cmp [rsi].TokenIdRaw.run_observed, 0
    je tid_done

; 1. Generation binding.
    mov rax, [rsi].TokenIdRaw.generation_id
    test rax, rax
    jz tid_done
    cmp [rsi].TokenIdRaw.observation_epoch, rax
    jne tid_done
    mov qword ptr [rdi].TokenIdResult.generation_bound, TID_PASS

; 2. Complete observation count.
    mov rax, [rsi].TokenIdRaw.generated
    test rax, rax
    jz tid_done
    cmp [rsi].TokenIdRaw.token_id_check_count, rax
    jne tid_done
    mov qword ptr [rdi].TokenIdResult.checks_complete, TID_PASS

; 3. Explicit mode.
    mov rax, [rsi].TokenIdRaw.token_id_mode
    cmp rax, TOKEN_ID_MODE_BOUNDED
    je tid_bounded
    cmp rax, TOKEN_ID_MODE_U64_FULL
    je tid_u64_full
    jmp tid_done

tid_bounded:
    mov qword ptr [rdi].TokenIdResult.mode_valid, TID_PASS

    ; vocab_count must be nonzero.
    mov rax, [rsi].TokenIdRaw.vocab_count
    test rax, rax
    jz tid_done

    ; end = base + count, checked for uint64 overflow.
    add rax, [rsi].TokenIdRaw.vocab_base_id
    jc tid_arith_fault
    mov [rdi].TokenIdResult.bounded_end_exclusive, rax

    ; min <= max.
    mov rcx, [rsi].TokenIdRaw.min_observed_token_id
    cmp rcx, [rsi].TokenIdRaw.max_observed_token_id
    ja tid_done

    ; min >= base.
    cmp rcx, [rsi].TokenIdRaw.vocab_base_id
    jb tid_done

    ; max < end-exclusive.
    mov rcx, [rsi].TokenIdRaw.max_observed_token_id
    cmp rcx, rax
    jae tid_done

    mov qword ptr [rdi].TokenIdResult.range_valid, TID_PASS
    jmp tid_common

tid_u64_full:
    ; Explicit U64-full mode:
    ; every unsigned QWORD token ID is representable. There is no finite
    ; end-exclusive addition and therefore no sentinel/wraparound bypass.
    mov qword ptr [rdi].TokenIdResult.mode_valid, TID_PASS

    ; We still require observed min <= observed max.
    mov rax, [rsi].TokenIdRaw.min_observed_token_id
    cmp rax, [rsi].TokenIdRaw.max_observed_token_id
    ja tid_done

    mov qword ptr [rdi].TokenIdResult.range_valid, TID_PASS
    jmp tid_common

tid_arith_fault:
    mov qword ptr [rdi].TokenIdResult.arithmetic_fault, 1
    jmp tid_done

tid_common:
; 4. Runtime OOV evidence must remain zero even in U64-full mode.
    cmp [rsi].TokenIdRaw.out_of_vocab_count, 0
    jne tid_done
    mov qword ptr [rdi].TokenIdResult.no_oov, TID_PASS

; 5. Reject signed-negative IDs reinterpreted as huge unsigned IDs.
    cmp [rsi].TokenIdRaw.negative_token_id_count, 0
    jne tid_done
    mov qword ptr [rdi].TokenIdResult.no_negative_reinterpret, TID_PASS

; 6. Encode/decode token-ID roundtrip must agree.
    mov rax, [rsi].TokenIdRaw.token_id_decode_mismatch
    or rax, [rsi].TokenIdRaw.token_id_encode_mismatch
    jnz tid_done
    mov qword ptr [rdi].TokenIdResult.roundtrip_ids_match, TID_PASS

; 7. Final derivation.
    cmp [rdi].TokenIdResult.generation_bound, TID_PASS
    jne tid_done
    cmp [rdi].TokenIdResult.mode_valid, TID_PASS
    jne tid_done
    cmp [rdi].TokenIdResult.checks_complete, TID_PASS
    jne tid_done
    cmp [rdi].TokenIdResult.range_valid, TID_PASS
    jne tid_done
    cmp [rdi].TokenIdResult.no_oov, TID_PASS
    jne tid_done
    cmp [rdi].TokenIdResult.no_negative_reinterpret, TID_PASS
    jne tid_done
    cmp [rdi].TokenIdResult.roundtrip_ids_match, TID_PASS
    jne tid_done
    cmp [rdi].TokenIdResult.arithmetic_fault, 0
    jne tid_done

    mov qword ptr [rdi].TokenIdResult.token_id_authorized, 1

tid_done:
    add rsp, 20h
    pop rdi
    pop rsi
    ret
TokenIdEvaluate ENDP

END
