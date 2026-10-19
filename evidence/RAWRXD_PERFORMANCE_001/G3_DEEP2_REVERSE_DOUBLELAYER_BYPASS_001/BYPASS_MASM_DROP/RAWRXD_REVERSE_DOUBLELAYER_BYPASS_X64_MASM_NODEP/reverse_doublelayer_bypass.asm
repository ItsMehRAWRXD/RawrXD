option casemap:none
include reverse_doublelayer_bypass.inc

.code

ReverseDoubleLayerEvaluate PROC FRAME
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
    mov rdi, rdx

    ; Fail closed.
    xor eax, eax
    mov rcx, SIZEOF RDLResult
    mov rdx, rdi
rdl_zero:
    test rcx, rcx
    jz rdl_zero_done
    mov byte ptr [rdx], al
    inc rdx
    dec rcx
    jmp rdl_zero
rdl_zero_done:

    test rsi, rsi
    jz rdl_done
    test rdi, rdi
    jz rdl_done

    mov rbx, [rsi].RDLRaw.generation_id
    test rbx, rbx
    jz rdl_done

; ---------------------------------------------------------------------------
; ABSOLUTE VETO — checked before either normal or bypass authorization.
; ---------------------------------------------------------------------------
    cmp [rsi].RDLRaw.stale_generation_faults, 0
    je rdl_generation
    mov qword ptr [rdi].RDLResult.stale_generation_veto, RDL_TRUE
    jmp rdl_done

; ---------------------------------------------------------------------------
; Generation coherence for normal authority.
; ---------------------------------------------------------------------------
rdl_generation:
    cmp [rsi].RDLRaw.scheduler_epoch, rbx
    jne rdl_bypass
    cmp [rsi].RDLRaw.token_epoch, rbx
    jne rdl_bypass
    cmp [rsi].RDLRaw.decode_epoch, rbx
    jne rdl_bypass
    cmp [rsi].RDLRaw.working_set_epoch, rbx
    jne rdl_bypass
    cmp [rsi].RDLRaw.quality_epoch, rbx
    jne rdl_bypass
    cmp [rsi].RDLRaw.tensor_math_epoch, rbx
    jne rdl_bypass
    mov qword ptr [rdi].RDLResult.generation_coherent, RDL_TRUE

; ---------------------------------------------------------------------------
; Normal positive-owner aggregation.
; ---------------------------------------------------------------------------
    cmp [rsi].RDLRaw.scheduler_authorized, 1
    jne rdl_bypass
    cmp [rsi].RDLRaw.token_authorized, 1
    jne rdl_bypass
    cmp [rsi].RDLRaw.decode_authorized, 1
    jne rdl_bypass
    cmp [rsi].RDLRaw.working_set_authorized, 1
    jne rdl_bypass
    cmp [rsi].RDLRaw.quality_authorized, 1
    jne rdl_bypass
    cmp [rsi].RDLRaw.tensor_math_authorized, 1
    jne rdl_bypass
    mov qword ptr [rdi].RDLResult.normal_owner_ready, RDL_TRUE

; ---------------------------------------------------------------------------
; Normal product closure.
; ---------------------------------------------------------------------------
    cmp [rsi].RDLRaw.product_open, 1
    jne rdl_bypass
    cmp [rsi].RDLRaw.session_enter, 1
    jne rdl_bypass
    cmp [rsi].RDLRaw.generated_tokens, 0
    je rdl_bypass

    mov rax, [rsi].RDLRaw.generated_tokens
    cmp [rsi].RDLRaw.token_commit_count, rax
    jne rdl_bypass
    cmp [rsi].RDLRaw.decode_commit_count, rax
    jne rdl_bypass
    mov qword ptr [rdi].RDLResult.product_closure, RDL_TRUE

; ---------------------------------------------------------------------------
; Normal authorization path.
; ---------------------------------------------------------------------------
    cmp [rdi].RDLResult.normal_owner_ready, 1
    jne rdl_bypass
    cmp [rdi].RDLResult.generation_coherent, 1
    jne rdl_bypass
    cmp [rdi].RDLResult.product_closure, 1
    jne rdl_bypass
    mov qword ptr [rdi].RDLResult.final_authority, RDL_TRUE
    jmp rdl_done

; ---------------------------------------------------------------------------
; Reverse/bypass path.
;
; This path may skip normal positive-owner aggregation, but it CANNOT bypass:
;   - generation_id != 0
;   - stale_generation_faults == 0  (already checked above)
;   - bypass_epoch == generation_id
;   - bypass_live_generation == 1
;   - generated_tokens > 0
;   - exact token/decode commit closure
;   - bypass_fault_count == 0
; ---------------------------------------------------------------------------
rdl_bypass:
    cmp [rsi].RDLRaw.bypass_request, 1
    jne rdl_done

    cmp [rsi].RDLRaw.bypass_epoch, rbx
    jne rdl_done
    cmp [rsi].RDLRaw.bypass_live_generation, 1
    jne rdl_done
    mov qword ptr [rdi].RDLResult.bypass_generation_bound, RDL_TRUE

    mov rax, [rsi].RDLRaw.generated_tokens
    test rax, rax
    jz rdl_done
    cmp [rsi].RDLRaw.bypass_token_commit_count, rax
    jne rdl_done
    cmp [rsi].RDLRaw.bypass_decode_commit_count, rax
    jne rdl_done
    mov qword ptr [rdi].RDLResult.bypass_commit_closure, RDL_TRUE

    cmp [rsi].RDLRaw.bypass_fault_count, 0
    jne rdl_done
    mov qword ptr [rdi].RDLResult.bypass_fault_free, RDL_TRUE

    ; Re-check absolute stale veto immediately before bypass authorization.
    cmp [rsi].RDLRaw.stale_generation_faults, 0
    jne rdl_stale_veto

    mov qword ptr [rdi].RDLResult.bypass_authorized, RDL_TRUE
    mov qword ptr [rdi].RDLResult.final_authority, RDL_TRUE
    jmp rdl_done

rdl_stale_veto:
    mov qword ptr [rdi].RDLResult.stale_generation_veto, RDL_TRUE
    mov qword ptr [rdi].RDLResult.bypass_authorized, RDL_FALSE
    mov qword ptr [rdi].RDLResult.final_authority, RDL_FALSE

rdl_done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
ReverseDoubleLayerEvaluate ENDP

END
