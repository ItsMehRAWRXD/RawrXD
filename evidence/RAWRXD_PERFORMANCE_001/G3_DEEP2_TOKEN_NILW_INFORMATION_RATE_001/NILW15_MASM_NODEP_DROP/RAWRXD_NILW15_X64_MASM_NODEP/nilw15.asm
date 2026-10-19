option casemap:none
include nilw15.inc

.code

; rcx=witness*, rdx=result*
; RAW → derive metrics → derive W01..W14 → W15=AND(W01..W14)
Nilw15Evaluate PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rsi, rcx
    mov rdi, rdx
    lea rax, qword ptr [rsi].Nilw15Witness.witness_state
    xor ebx, ebx
wipe:
    mov qword ptr [rax+rbx*8], PROOF_FAIL
    inc ebx
    cmp ebx, WITNESS_COUNT
    jb wipe
    mov rcx, rsi
    call Nilw15DeriveWitnesses
    jc fail
    lea rax, qword ptr [rsi].Nilw15Witness.witness_state
    mov qword ptr [rax+WIT_AUTH_DERIVATION*8], PROOF_PASS
    mov qword ptr [rdi].Nilw15Result.authorized_pass, 1
    mov qword ptr [rdi].Nilw15Result.passing_witnesses, 14
    xor eax, eax
    mov qword ptr [rdi].Nilw15Result.failing_witnesses, rax
    mov qword ptr [rdi].Nilw15Result.notrun_witnesses, rax
    jmp done
fail:
    xor eax, eax
    mov qword ptr [rdi].Nilw15Result.authorized_pass, rax
    lea rax, qword ptr [rsi].Nilw15Witness.witness_state
    mov qword ptr [rax+WIT_AUTH_DERIVATION*8], PROOF_FAIL
    xor ebx, ebx
    xor r8d, r8d
    xor r9d, r9d
rc: cmp ebx, WITNESS_COUNT
    jae rcd
    lea rax, qword ptr [rsi].Nilw15Witness.witness_state
    mov rax, qword ptr [rax+rbx*8]
    cmp rax, PROOF_PASS
    jne rf
    inc r8
    jmp rn
rf: cmp rax, PROOF_FAIL
    jne rn
    inc r9
rn: inc ebx
    jmp rc
rcd:
    mov qword ptr [rdi].Nilw15Result.passing_witnesses, r8
    mov qword ptr [rdi].Nilw15Result.failing_witnesses, r9
    xor eax, eax
    mov qword ptr [rdi].Nilw15Result.notrun_witnesses, rax
done:
    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    ret
Nilw15Evaluate ENDP
END
