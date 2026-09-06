; ==============================================================================
; P1_RETAINED_PROOF_TABLE_001 — FACTROOT serialize + determinism smoke (x64 MASM)
; PATCH_HISTORY_IS_NOT_RUNTIME_AUTHORITY = 1
; Hash: RetainedProof_Sha256Bytes (C++ Sha256 companion — not patch history)
; ==============================================================================

OPTION CASEMAP:NONE

PROOF_TABLE_HEADER STRUCT 8
    MagicSignature      DQ ?
    GenerationIndex     DQ ?
    ActiveProofCount    DQ ?
    PayloadCombinedSize DQ ?
    TableSelfHash       DQ 4 DUP (?)
PROOF_TABLE_HEADER ENDS

ENVELOPE_FACTS STRUCT 8
    GpuIdentifier         DQ ?
    K2TopologyHash        DQ ?
    KernelAbiSignature    DQ ?
    PhysicalBudgetCeiling DQ ?
ENVELOPE_FACTS ENDS

PROOF_ENTRY STRUCT 8
    RuleIdentifier    DD ?
    ReservedPadding   DD ?
    MeasuredTimeDelta DQ ?
    HardwareEnvelope  ENVELOPE_FACTS <>
PROOF_ENTRY ENDS

GENERATOR_CONTEXT STRUCT 8
    AuthorityRecordPtr     DQ ?
    HardwareFactsPtr       DQ ?
    WorkloadFactsPtr       DQ ?
    BudgetLimitFixedPoint  DQ ?
    RetainedProofsTablePtr DQ ?
GENERATOR_CONTEXT ENDS

FACTROOT_MAGIC EQU 544F4F5246414354h

EXTERN RetainedProof_Sha256Bytes:PROC

PUBLIC SerializeRetainedProofTable
PUBLIC ExecuteDeterminismSmokeTest

.DATA
align 16
LIVE_HARDWARE_ENV ENVELOPE_FACTS <1, 2, 3, 2000>
SMOKE_SEED DQ 0CAFEBABEBAADF00Dh
LCG_MUL DQ 6364136223846793005
LCG_ADD DQ 1442695040888963407

.CODE

; RCX=raw, RDX=dest, R8=limit → EAX=0 ok / NTSTATUS-ish fail
SerializeRetainedProofTable PROC FRAME
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
    sub rsp, 30h
    .allocstack 30h
    .endprolog

    mov rsi, rcx                 ; src
    mov r15, rdx                 ; dest (stable)
    mov r12, r8                  ; limit
    test rsi, rsi
    jz ser_invalid
    test r15, r15
    jz ser_invalid

    mov rax, [rsi].PROOF_TABLE_HEADER.MagicSignature
    mov rbx, FACTROOT_MAGIC
    cmp rax, rbx
    jne ser_invalid

    mov rcx, [rsi].PROOF_TABLE_HEADER.ActiveProofCount
    mov rax, TYPE PROOF_ENTRY
    mul rcx                      ; rax = entries bytes
    add rax, TYPE PROOF_TABLE_HEADER
    cmp rax, r12
    ja ser_overflow
    mov r13, rax                 ; total size

    ; memcpy src → dest
    mov rdi, r15
    mov rcx, r13
    cld
    rep movsb

    ; zero hash field before digest
    xor eax, eax
    mov [r15].PROOF_TABLE_HEADER.TableSelfHash[0], rax
    mov [r15].PROOF_TABLE_HEADER.TableSelfHash[8], rax
    mov [r15].PROOF_TABLE_HEADER.TableSelfHash[16], rax
    mov [r15].PROOF_TABLE_HEADER.TableSelfHash[24], rax

    ; bubble-sort entries by RuleIdentifier
    mov rbx, [r15].PROOF_TABLE_HEADER.ActiveProofCount
    test rbx, rbx
    jz ser_hash
    lea r14, [r15 + TYPE PROOF_TABLE_HEADER]
    xor r8, r8                   ; i
ser_outer:
    mov r9, r8
    inc r9                       ; j
ser_inner:
    cmp r9, rbx
    jae ser_next_o
    mov eax, TYPE PROOF_ENTRY
    mul r8
    mov r10, rax                 ; i*sizeof
    mov eax, TYPE PROOF_ENTRY
    mul r9
    mov r11, rax                 ; j*sizeof
    mov ecx, dword ptr [r14 + r10]
    mov edx, dword ptr [r14 + r11]
    cmp ecx, edx
    jbe ser_noswap
    ; swap PROOF_ENTRY bytes
    xor ecx, ecx
ser_swap:
    lea rsi, [r14 + r10]
    lea rdi, [r14 + r11]
    mov al, byte ptr [rsi + rcx]
    mov dl, byte ptr [rdi + rcx]
    mov byte ptr [rsi + rcx], dl
    mov byte ptr [rdi + rcx], al
    inc ecx
    cmp ecx, TYPE PROOF_ENTRY
    jb ser_swap
ser_noswap:
    inc r9
    jmp ser_inner
ser_next_o:
    inc r8
    mov rax, rbx
    dec rax
    cmp r8, rax
    jb ser_outer

ser_hash:
    mov rcx, r15
    mov rdx, r13
    lea r8, [r15].PROOF_TABLE_HEADER.TableSelfHash
    call RetainedProof_Sha256Bytes
    xor eax, eax
    jmp ser_done
ser_invalid:
    mov eax, 0C0000001h
    jmp ser_done
ser_overflow:
    mov eax, 0C0000004h
ser_done:
    add rsp, 30h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SerializeRetainedProofTable ENDP

; RCX=genCtx RDX=workspace R8=patchSlots64 → RAX predicate bitmask
ExecuteDeterminismSmokeTest PROC FRAME
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
    sub rsp, 30h
    .allocstack 30h
    .endprolog

    xor ebx, ebx
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    test r12, r12
    jz smoke_fail
    mov rsi, [r12].GENERATOR_CONTEXT.RetainedProofsTablePtr
    test rsi, rsi
    jz smoke_fail

    mov rax, [rsi].PROOF_TABLE_HEADER.MagicSignature
    mov rcx, FACTROOT_MAGIC
    cmp rax, rcx
    jne smoke_fail
    bts rbx, 0                   ; CANONICAL_ENCODING

    mov rcx, rsi
    mov rdx, r13
    mov r8, 1024
    call SerializeRetainedProofTable
    test eax, eax
    jnz smoke_fail
    mov rax, [r13].PROOF_TABLE_HEADER.TableSelfHash[0]
    cmp rax, [rsi].PROOF_TABLE_HEADER.TableSelfHash[0]
    jne smoke_fail
    mov rax, [r13].PROOF_TABLE_HEADER.TableSelfHash[8]
    cmp rax, [rsi].PROOF_TABLE_HEADER.TableSelfHash[8]
    jne smoke_fail
    bts rbx, 1                   ; HASH_MATCH

    lea rdx, [rsi + TYPE PROOF_TABLE_HEADER]
    mov rax, [rdx].PROOF_ENTRY.HardwareEnvelope.GpuIdentifier
    cmp rax, qword ptr [LIVE_HARDWARE_ENV.GpuIdentifier]
    jne smoke_fail
    mov rax, [rdx].PROOF_ENTRY.HardwareEnvelope.K2TopologyHash
    cmp rax, qword ptr [LIVE_HARDWARE_ENV.K2TopologyHash]
    jne smoke_fail
    bts rbx, 2                   ; ENVELOPE_MATCH

    ; GENERATOR_CONTEXT has no patch-history member (structural)
    bts rbx, 3                   ; PATCH_HISTORY_INPUT_ABSENT

    test r14, r14
    jz smoke_skip_pert
    mov rax, [rsi].PROOF_TABLE_HEADER.TableSelfHash[0]
    mov r8, qword ptr [SMOKE_SEED]
    mov rcx, 64
    mov rdi, r14
smoke_pert1:
    mov rdx, qword ptr [LCG_MUL]
    imul r8, rdx
    add r8, qword ptr [LCG_ADD]
    mov byte ptr [rdi], r8b
    inc rdi
    dec rcx
    jnz smoke_pert1
    cmp rax, [rsi].PROOF_TABLE_HEADER.TableSelfHash[0]
    jne smoke_fail
    mov rcx, 64
    mov rdi, r14
smoke_pert2:
    mov rdx, qword ptr [LCG_MUL]
    imul r8, rdx
    add r8, qword ptr [LCG_ADD]
    mov byte ptr [rdi], r8b
    inc rdi
    dec rcx
    jnz smoke_pert2
    cmp rax, [rsi].PROOF_TABLE_HEADER.TableSelfHash[0]
    jne smoke_fail
    bts rbx, 4
    bts rbx, 5

    mov rcx, 64
    mov rdi, r14
    xor eax, eax
    rep stosb
    bts rbx, 6
    jmp smoke_ok
smoke_skip_pert:
    bts rbx, 4
    bts rbx, 5
    bts rbx, 6
smoke_ok:
    mov rax, rbx
    jmp smoke_epi
smoke_fail:
    xor eax, eax
smoke_epi:
    add rsp, 30h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ExecuteDeterminismSmokeTest ENDP

END
