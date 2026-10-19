option casemap:none
include nilw15.inc

.code

; rcx=witness* → CF=0; fills derived rate/nilw/phys fields
Nilw15DeriveRates PROC FRAME
    push rsi
    .pushreg rsi
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rsi, rcx

    mov rcx, qword ptr [rsi].Nilw15Witness.active_logical_weights
    mov rdx, 1000000
    mov r8, qword ptr [rsi].Nilw15Witness.total_logical_weights
    call Nilw15MulDiv
    jc dr_fail
    mov qword ptr [rsi].Nilw15Witness.physicalization_ppm, rax

    mov rcx, qword ptr [rsi].Nilw15Witness.total_new_bits
    mov rdx, 1000000000
    mov r8, qword ptr [rsi].Nilw15Witness.total_logical_weights
    call Nilw15MulDiv
    jc dr_fail
    mov qword ptr [rsi].Nilw15Witness.token_nilw_x1e9, rax

    mov rcx, qword ptr [rsi].Nilw15Witness.generated_tokens
    mov rdx, 1000000000000
    mov r8, qword ptr [rsi].Nilw15Witness.wall_ns
    call Nilw15MulDiv
    jc dr_fail
    mov qword ptr [rsi].Nilw15Witness.tps_x1000, rax

    mov rcx, qword ptr [rsi].Nilw15Witness.total_new_bits
    mov rdx, 1000000000
    mov r8, qword ptr [rsi].Nilw15Witness.wall_ns
    call Nilw15MulDiv
    jc dr_fail
    mov qword ptr [rsi].Nilw15Witness.information_rate_bps, rax

    mov rax, qword ptr [rsi].Nilw15Witness.generated_tokens
    test rax, rax
    jz dr_fail
    mov rcx, 8
    mul rcx
    jc dr_fail
    mov r8, rax
    mov rax, qword ptr [rsi].Nilw15Witness.total_new_bits
    xor edx, edx
    div r8
    mov qword ptr [rsi].Nilw15Witness.mean_payload_bytes_token, rax
    clc
    jmp dr_done
dr_fail:
    stc
dr_done:
    add rsp, 28h
    pop rsi
    ret
Nilw15DeriveRates ENDP

END
