; smoke_gate_policy.asm — ≤99 lines; link with Deep2FixedGatePolicy.obj
option casemap:none
include Deep2FixedGatePolicy.inc

extrn ExitProcess:PROC
extrn GetStdHandle:PROC
extrn WriteFile:PROC

.data
pol     GatePolicy <>
samp    RuntimeSample <>
res     GateResult <>
okMsg   db "DEEP2_FIXED_GATE_POLICY_SMOKE=PASS",13,10
okLen   equ $ - okMsg
badMsg  db "DEEP2_FIXED_GATE_POLICY_SMOKE=FAIL",13,10
badLen  equ $ - badMsg
written dq 0

.code
fail PROC
    mov ecx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, badMsg
    mov r8d, badLen
    lea r9, written
    sub rsp, 28h
    mov qword ptr [rsp+20h], 0
    call WriteFile
    add rsp, 28h
    mov ecx, 1
    call ExitProcess
fail ENDP

main PROC
    lea rcx, pol
    call Deep2FixedGatePolicy_Init
    test eax, eax
    jz fail
    lea rcx, pol
    call Deep2FixedGatePolicy_Validate
    test eax, eax
    jz fail
    call Deep2FixedGatePolicy_Q4Witness
    test eax, eax
    jz fail

    mov rax, 100000000
    mov samp.bytesPerToken, rax
    mov rax, 1000000000
    mov samp.bytesPerSec, rax
    mov rax, 10000
    mov samp.tpsMilli, rax
    mov rax, 128
    mov samp.windowTokens, rax
    mov rax, 1
    mov samp.nilwNum, rax
    mov rax, 1250
    mov samp.nilwDen, rax
    lea rcx, samp
    lea rdx, res
    call Deep2FixedGatePolicy_Evaluate
    test eax, eax
    jz fail
    cmp res.passMask, GATE_ALL_BITS
    jne fail
    cmp res.failMask, 0
    jne fail

    ; +1 bytes/token must clear bit0 in passMask
    mov rax, 100000001
    mov samp.bytesPerToken, rax
    lea rcx, samp
    lea rdx, res
    call Deep2FixedGatePolicy_Evaluate
    mov rax, res.passMask
    test rax, GATE_BIT_BYTES_PER_TOKEN
    jnz fail_mask
    mov rax, 100000000
    mov samp.bytesPerToken, rax

    mov ecx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, okMsg
    mov r8d, okLen
    lea r9, written
    sub rsp, 28h
    mov qword ptr [rsp+20h], 0
    call WriteFile
    add rsp, 28h
    xor ecx, ecx
    call ExitProcess
fail_mask:
    jmp fail
main ENDP
END
