; =============================================================================
; P1_OutcomeReverseRuntime_Smoke_x64.asm
;
; Zero-import deterministic smoke for P1_OutcomeReverseRuntime_x64.asm.
; Process exit code is the only output: 0 = PASS, nonzero = failed predicate.
; The supplied Run B values are exercised as evidence inputs:
;   PREFETCH_LEAD_CYCLES = 21798
;   OVERLAP_CYCLES       = 272832
; =============================================================================

option casemap:none

include P1_OutcomeReverseRuntime_x64.inc

EXTERN P1OR_InitContract:PROC
EXTERN P1OR_RecordSample:PROC
EXTERN P1OR_RecordPublication:PROC
EXTERN P1OR_SealEpoch:PROC
EXTERN P1OR_ShouldRetainRule:PROC
EXTERN P1OR_ProjectReverse:PROC

PUBLIC mainCRTStartup

SMOKE_TSC_HZ                    EQU 00000000FA587C5Dh ; 4,200,103,005 Hz
SMOKE_OUTPUT_HASH               EQU 6A17B23C5D90E4F1h
SMOKE_VRAM_BYTES                EQU 0000000700000000h ; 28 GiB
SMOKE_ACTIVE_BYTES              EQU 00000000C0000000h ; 3 GiB/token
SMOKE_PREFETCH_LEAD             EQU 21798
SMOKE_OVERLAP                   EQU 272832

RECORD_PHASE MACRO contextName:req, phaseValue:req, tickValue:req, flagValue:req
    mov dword ptr [smoke_sample + P1OR_PHASE_SAMPLE.PhaseId], phaseValue
    mov dword ptr [smoke_sample + P1OR_PHASE_SAMPLE.Flags], (P1OR_SAMPLE_VALID OR flagValue)
    mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.StartTsc], 0
    mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.EndTsc], 0
    mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.ElapsedTicks], tickValue
    mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.BytesRead], 0
    mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.BytesWritten], 0
    mov rax, SMOKE_ACTIVE_BYTES
    mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.ActiveBytes], rax
    mov rax, SMOKE_VRAM_BYTES
    mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.VramBytes], rax
    mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.PcieFaults], 0
    mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.TokenSequence], 1
    IF (flagValue AND P1OR_SAMPLE_COMMITTED)
        mov rax, SMOKE_OUTPUT_HASH
        mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.OutputHash], rax
    ELSE
        mov qword ptr [smoke_sample + P1OR_PHASE_SAMPLE.OutputHash], 0
    ENDIF
    lea rcx, contextName
    lea rdx, smoke_sample
    call P1OR_RecordSample
    test eax, eax
    jnz smoke_exit
ENDM

RECORD_PUBLICATION MACRO contextName:req
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.Flags], (P1OR_PUB_SLOT_PUBLISHED OR P1OR_PUB_PREFETCH_CONTAINED OR P1OR_PUB_PROFILER_LIFETIME OR P1OR_PUB_AFFINITY_ATTEMPTED)
    mov dword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.StatusBefore], 0
    mov dword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.StatusPublished], 1
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.SlotIndex], 2
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.PayloadPointer], 100000h
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.PayloadLength], 128
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.ProducerSequence], 41
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.ConsumerSequence], 41
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.PublishedGeneration], 7
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.AcquiredGeneration], 7
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.PublishTsc], 100000
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.AcquireTsc], 110000
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.PrefetchStartTsc], 100100
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.PrefetchEndTsc], 400000
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.PrefetchLeadCycles], SMOKE_PREFETCH_LEAD
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.OverlapCycles], SMOKE_OVERLAP
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.PayloadNonzeroBytes], 64
    mov qword ptr [smoke_publication + P1OR_PUBLICATION_EVIDENCE.Reserved], 0
    lea rcx, contextName
    lea rdx, smoke_publication
    call P1OR_RecordPublication
    test eax, eax
    jnz smoke_exit
ENDM

.data?
ALIGN 8
smoke_baseline_context  P1OR_CONTEXT <>
smoke_candidate_context P1OR_CONTEXT <>
smoke_sample            P1OR_PHASE_SAMPLE <>
smoke_publication       P1OR_PUBLICATION_EVIDENCE <>
smoke_baseline_decision P1OR_DECISION <>
smoke_candidate_decision P1OR_DECISION <>
smoke_rule_decision     P1OR_RULE_DECISION <>
smoke_reverse_projection P1OR_REVERSE_PROJECTION <>

.code

mainCRTStartup PROC
    ; Entry RSP is 8 mod 16. Reserve Win64 shadow space and align calls.
    sub rsp, 28h

    lea rcx, smoke_baseline_context
    mov rdx, SMOKE_TSC_HZ
    call P1OR_InitContract
    test eax, eax
    jnz smoke_exit

    lea rcx, smoke_candidate_context
    mov rdx, SMOKE_TSC_HZ
    call P1OR_InitContract
    test eax, eax
    jnz smoke_exit

    RECORD_PUBLICATION smoke_baseline_context
    RECORD_PUBLICATION smoke_candidate_context

    ; Baseline: 84,000,000 cycles/token, approximately 50 TPS.
    RECORD_PHASE smoke_baseline_context, P1OR_PHASE_WEIGHT_PATH,      50000000, 0
    RECORD_PHASE smoke_baseline_context, P1OR_PHASE_ATTENTION_KV,     12000000, 0
    RECORD_PHASE smoke_baseline_context, P1OR_PHASE_MOE_ROUTER,        8000000, 0
    RECORD_PHASE smoke_baseline_context, P1OR_PHASE_RING_PUBLICATION,  2000000, 0
    RECORD_PHASE smoke_baseline_context, P1OR_PHASE_RESERVE,           8000000, 0
    RECORD_PHASE smoke_baseline_context, P1OR_PHASE_SAMPLE_STREAM, 4000000, (P1OR_SAMPLE_COMMITTED OR P1OR_SAMPLE_AUTHORITATIVE OR P1OR_SAMPLE_COHERENT OR P1OR_SAMPLE_RESIDENT)

    ; Candidate: 40,000,000 cycles/token, approximately 105 TPS.
    RECORD_PHASE smoke_candidate_context, P1OR_PHASE_WEIGHT_PATH,      22000000, 0
    RECORD_PHASE smoke_candidate_context, P1OR_PHASE_ATTENTION_KV,      6000000, 0
    RECORD_PHASE smoke_candidate_context, P1OR_PHASE_MOE_ROUTER,        3000000, 0
    RECORD_PHASE smoke_candidate_context, P1OR_PHASE_RING_PUBLICATION,  1000000, 0
    RECORD_PHASE smoke_candidate_context, P1OR_PHASE_RESERVE,           6000000, 0
    RECORD_PHASE smoke_candidate_context, P1OR_PHASE_SAMPLE_STREAM, 2000000, (P1OR_SAMPLE_COMMITTED OR P1OR_SAMPLE_AUTHORITATIVE OR P1OR_SAMPLE_COHERENT OR P1OR_SAMPLE_RESIDENT)

    lea rcx, smoke_baseline_context
    lea rdx, smoke_baseline_decision
    call P1OR_SealEpoch
    test eax, eax
    jnz smoke_exit

    lea rcx, smoke_candidate_context
    lea rdx, smoke_candidate_decision
    call P1OR_SealEpoch
    test eax, eax
    jnz smoke_exit

    test qword ptr [smoke_candidate_decision + P1OR_DECISION.Flags], P1OR_DECISION_CERT_PASS
    jz   smoke_fail_candidate_contract
    cmp qword ptr [smoke_candidate_decision + P1OR_DECISION.ObservedTps], 100
    jb   smoke_fail_candidate_tps
    test qword ptr [smoke_candidate_decision + P1OR_DECISION.Flags], P1OR_DECISION_ACTIVE_BYTES_PASS
    jz   smoke_fail_active_bytes
    cmp qword ptr [smoke_candidate_decision + P1OR_DECISION.PrefetchLeadCycles], SMOKE_PREFETCH_LEAD
    jne  smoke_fail_prefetch_lead
    cmp qword ptr [smoke_candidate_decision + P1OR_DECISION.OverlapCycles], SMOKE_OVERLAP
    jne  smoke_fail_overlap
    cmp qword ptr [smoke_baseline_decision + P1OR_DECISION.TotalDebtTicks], 0
    je   smoke_fail_baseline_debt

    lea rcx, smoke_baseline_decision
    lea rdx, smoke_candidate_decision
    mov r8, 1000000
    lea r9, smoke_rule_decision
    call P1OR_ShouldRetainRule
    cmp eax, 1
    jne smoke_fail_rule
    test qword ptr [smoke_rule_decision + P1OR_RULE_DECISION.Flags], P1OR_RULE_RETAINED
    jz   smoke_fail_rule_flag

    ; reverse *2.3, inequality tolerance <=0.001, policy limit 23 passes.
    mov rcx, 2300000
    mov rdx, 1000000
    mov r8, 2300000
    lea r9, smoke_reverse_projection
    call P1OR_ProjectReverse
    test eax, eax
    jnz smoke_exit
    cmp qword ptr [smoke_reverse_projection + P1OR_REVERSE_PROJECTION.ProjectedGainTicks], 2300000
    jne smoke_fail_reverse_projection
    test qword ptr [smoke_reverse_projection + P1OR_REVERSE_PROJECTION.Flags], P1OR_REVERSE_WITHIN_EPSILON
    jz   smoke_fail_reverse_epsilon
    cmp dword ptr [smoke_reverse_projection + P1OR_REVERSE_PROJECTION.PassLimit], 23
    jne smoke_fail_reverse_passes

    xor eax, eax
    jmp smoke_exit

smoke_fail_candidate_contract:
    mov eax, 10
    jmp smoke_exit
smoke_fail_candidate_tps:
    mov eax, 11
    jmp smoke_exit
smoke_fail_active_bytes:
    mov eax, 17
    jmp smoke_exit
smoke_fail_prefetch_lead:
    mov eax, 12
    jmp smoke_exit
smoke_fail_overlap:
    mov eax, 13
    jmp smoke_exit
smoke_fail_baseline_debt:
    mov eax, 14
    jmp smoke_exit
smoke_fail_rule:
    mov eax, 15
    jmp smoke_exit
smoke_fail_rule_flag:
    mov eax, 16
    jmp smoke_exit
smoke_fail_reverse_projection:
    mov eax, 18
    jmp smoke_exit
smoke_fail_reverse_epsilon:
    mov eax, 19
    jmp smoke_exit
smoke_fail_reverse_passes:
    mov eax, 20

smoke_exit:
    add rsp, 28h
    ret
mainCRTStartup ENDP

END
