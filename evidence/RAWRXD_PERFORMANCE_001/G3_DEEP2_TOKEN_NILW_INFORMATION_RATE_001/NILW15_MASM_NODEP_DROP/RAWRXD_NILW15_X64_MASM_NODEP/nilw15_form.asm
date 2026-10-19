option casemap:none
include nilw15.inc

.code

; rcx=witness* → CF=0; sets total_new_bits + active_bpw_x1e6
Nilw15FormNumerator PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    mov rsi, rcx
    mov rax, qword ptr [rsi].Nilw15Witness.form
    cmp rax, NILW_FORM_A
    je fa
    cmp rax, NILW_FORM_B
    je fb
    jmp fn_fail

fa:
    cmp qword ptr [rsi].Nilw15Witness.active_representation_bits, 0
    je fn_fail
    cmp qword ptr [rsi].Nilw15Witness.new_payload_bits, 0
    jne fn_fail
    mov rax, qword ptr [rsi].Nilw15Witness.new_information_bits
    cmp rax, qword ptr [rsi].Nilw15Witness.active_representation_bits
    ja fn_fail
    mov rbx, rax
    add rbx, qword ptr [rsi].Nilw15Witness.overhead_bits
    jc fn_fail
    mov qword ptr [rsi].Nilw15Witness.total_new_bits, rbx
    mov rcx, qword ptr [rsi].Nilw15Witness.active_representation_bits
    jmp do_bpw

fb:
    cmp qword ptr [rsi].Nilw15Witness.new_payload_bits, 0
    je fn_fail
    cmp qword ptr [rsi].Nilw15Witness.active_representation_bits, 0
    jne fn_fail
    cmp qword ptr [rsi].Nilw15Witness.new_information_bits, 0
    jne fn_fail
    mov rbx, qword ptr [rsi].Nilw15Witness.new_payload_bits
    add rbx, qword ptr [rsi].Nilw15Witness.overhead_bits
    jc fn_fail
    mov qword ptr [rsi].Nilw15Witness.total_new_bits, rbx
    mov rcx, qword ptr [rsi].Nilw15Witness.new_payload_bits

do_bpw:
    mov rdx, 1000000
    mov r8, qword ptr [rsi].Nilw15Witness.active_logical_weights
    call Nilw15MulDiv
    jc fn_fail
    mov qword ptr [rsi].Nilw15Witness.active_bpw_x1e6, rax
    clc
    jmp fn_done

fn_fail:
    stc
fn_done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
Nilw15FormNumerator ENDP

END
