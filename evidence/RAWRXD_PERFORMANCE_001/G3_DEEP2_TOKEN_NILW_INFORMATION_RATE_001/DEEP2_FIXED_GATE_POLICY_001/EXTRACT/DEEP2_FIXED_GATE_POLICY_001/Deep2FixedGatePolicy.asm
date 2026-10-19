option casemap:none
include Deep2FixedGatePolicy.inc

.code

; RCX = GatePolicy*
; RAX = 1 on success, 0 on null.
Deep2FixedGatePolicy_Init PROC
    test rcx, rcx
    jz short init_bad
    mov rax, DEEP2_GATE_MAGIC
    mov [rcx].GatePolicy.magic, rax
    mov rax, DEEP2_GATE_VERSION
    mov [rcx].GatePolicy.version, rax
    mov rax, DEEP2_BYTES_PER_TOKEN_MAX
    mov [rcx].GatePolicy.bytesPerTokenMax, rax
    mov rax, DEEP2_BYTES_PER_SEC_MAX
    mov [rcx].GatePolicy.bytesPerSecMax, rax
    mov rax, DEEP2_TPS_MILLI_MIN
    mov [rcx].GatePolicy.tpsMilliMin, rax
    mov rax, DEEP2_WINDOW_TOKENS_MIN
    mov [rcx].GatePolicy.windowTokensMin, rax
    mov rax, DEEP2_NILW_NUM
    mov [rcx].GatePolicy.nilwNum, rax
    mov rax, DEEP2_NILW_DEN
    mov [rcx].GatePolicy.nilwDen, rax
    mov eax, 1
    ret
init_bad:
    xor eax, eax
    ret
Deep2FixedGatePolicy_Init ENDP

; RCX = GatePolicy*
; RAX = 1 iff every persisted field exactly equals permanent policy.
Deep2FixedGatePolicy_Validate PROC
    test rcx, rcx
    jz short val_bad
    mov rax, DEEP2_GATE_MAGIC
    cmp [rcx].GatePolicy.magic, rax
    jne short val_bad
    mov rax, DEEP2_GATE_VERSION
    cmp [rcx].GatePolicy.version, rax
    jne short val_bad
    mov rax, DEEP2_BYTES_PER_TOKEN_MAX
    cmp [rcx].GatePolicy.bytesPerTokenMax, rax
    jne short val_bad
    mov rax, DEEP2_BYTES_PER_SEC_MAX
    cmp [rcx].GatePolicy.bytesPerSecMax, rax
    jne short val_bad
    mov rax, DEEP2_TPS_MILLI_MIN
    cmp [rcx].GatePolicy.tpsMilliMin, rax
    jne short val_bad
    mov rax, DEEP2_WINDOW_TOKENS_MIN
    cmp [rcx].GatePolicy.windowTokensMin, rax
    jne short val_bad
    mov rax, DEEP2_NILW_NUM
    cmp [rcx].GatePolicy.nilwNum, rax
    jne short val_bad
    mov rax, DEEP2_NILW_DEN
    cmp [rcx].GatePolicy.nilwDen, rax
    jne short val_bad
    mov eax, 1
    ret
val_bad:
    xor eax, eax
    ret
Deep2FixedGatePolicy_Validate ENDP

; No inputs. RAX=1 iff exact Q4 witness reduces to permanent NILW policy.
; Checks: 4000*5*4*1250 == 1000*1000*100.
Deep2FixedGatePolicy_Q4Witness PROC
    mov rax, DEEP2_Q4_BPW_NUM
    imul rax, DEEP2_Q4_PHYS_NUM
    imul rax, DEEP2_Q4_INFO_NUM
    imul rax, DEEP2_NILW_DEN
    mov r8, rax

    mov rax, DEEP2_Q4_BPW_DEN
    imul rax, DEEP2_Q4_PHYS_DEN
    imul rax, DEEP2_Q4_INFO_DEN
    cmp r8, rax
    sete al
    movzx eax, al
    ret
Deep2FixedGatePolicy_Q4Witness ENDP

; RCX = RuntimeSample*, RDX = GateResult*
; RAX = 1 iff all five invariant gates pass.
;
; Gate semantics:
;   bytes/token <= 100,000,000
;   bytes/sec   <= 1,000,000,000
;   TPS         >= 10.000
;   window      >= 128 tokens
;   NILW        <= 1/1250 (0.0008)
;
; NILW comparison is exact: sampleNum/sampleDen <= 1/1250
; => sampleNum*1250 <= sampleDen. MUL is used so overflow fails closed.
Deep2FixedGatePolicy_Evaluate PROC
    push rbx
    push rsi
    test rcx, rcx
    jz eval_null
    test rdx, rdx
    jz eval_null

    mov rsi, rcx
    mov rbx, rdx
    xor r8d, r8d                    ; pass mask

    mov rax, [rsi].RuntimeSample.bytesPerToken
    cmp rax, DEEP2_BYTES_PER_TOKEN_MAX
    ja short e_bps
    or r8, GATE_BIT_BYTES_PER_TOKEN

e_bps:
    mov rax, [rsi].RuntimeSample.bytesPerSec
    cmp rax, DEEP2_BYTES_PER_SEC_MAX
    ja short e_tps
    or r8, GATE_BIT_BYTES_PER_SEC

e_tps:
    mov rax, [rsi].RuntimeSample.tpsMilli
    cmp rax, DEEP2_TPS_MILLI_MIN
    jb short e_win
    or r8, GATE_BIT_TPS

e_win:
    mov rax, [rsi].RuntimeSample.windowTokens
    cmp rax, DEEP2_WINDOW_TOKENS_MIN
    jb short e_nilw
    or r8, GATE_BIT_WINDOW

e_nilw:
    mov r9, [rsi].RuntimeSample.nilwDen
    test r9, r9
    jz short e_finish                  ; zero denominator = fail closed
    mov rax, [rsi].RuntimeSample.nilwNum
    mov r10, DEEP2_NILW_DEN
    mul r10                            ; RDX:RAX = num*1250
    test rdx, rdx
    jnz short e_finish                 ; overflow beyond 64-bit denominator => fail
    cmp rax, r9
    ja short e_finish
    or r8, GATE_BIT_NILW

e_finish:
    mov [rbx].GateResult.passMask, r8
    mov rax, GATE_ALL_BITS
    xor rax, r8
    and rax, GATE_ALL_BITS
    mov [rbx].GateResult.failMask, rax
    mov qword ptr [rbx].GateResult.policyValid, 1

    ; r8 is caller-volatile; preserve pass mask across Q4Witness
    push r8
    sub rsp, 20h
    call Deep2FixedGatePolicy_Q4Witness
    add rsp, 20h
    mov [rbx].GateResult.fixtureQ4Valid, rax
    pop r8

    cmp r8, GATE_ALL_BITS
    sete al
    movzx eax, al
    pop rsi
    pop rbx
    ret

eval_null:
    xor eax, eax
    pop rsi
    pop rbx
    ret
Deep2FixedGatePolicy_Evaluate ENDP

END
