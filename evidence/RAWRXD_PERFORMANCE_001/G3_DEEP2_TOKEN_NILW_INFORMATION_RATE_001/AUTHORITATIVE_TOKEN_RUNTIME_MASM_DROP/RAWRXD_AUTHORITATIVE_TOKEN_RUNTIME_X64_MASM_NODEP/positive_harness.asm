option casemap:none
include authoritative_token.inc

ExitProcess PROTO

.data?
raw     RawTokenRuntime <>
derived DerivedTokenRuntime <>

.code
main PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog

    ; Exact envelope vector (Form B).
    mov raw.form, NILW_FORM_B
    mov rax, 1000000000000
    mov raw.total_logical_weights, rax
    mov rax, 640000000000
    mov raw.active_logical_weight_visits, rax
    mov rax, 102400000000
    mov raw.new_payload_bits, rax
    mov rax, 409600000000
    mov raw.reused_bits, rax
    mov raw.reuse_events, 1000
    mov raw.generated_tokens, 128
    mov rax, 12800000000
    mov raw.wall_ns, rax
    mov raw.quality_samples, 128
    mov rax, 102400000000
    mov raw.component_bits_sum, rax
    mov raw.class_bits_sum, rax
    mov raw.payload_bits_fetched, rax
    mov raw.active_subset_samples, 128
    mov raw.overhead_samples, 128

    lea rcx, raw
    lea rdx, derived
    call AuthoritativeTokenEvaluate

    cmp derived.authorized_pass, 1
    jne bad

    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
