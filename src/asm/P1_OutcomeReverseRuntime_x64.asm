; =============================================================================
; P1_OutcomeReverseRuntime_x64.asm
;
; Outcome-backsolved runtime accounting for the 100 committed TPS / 32 GB
; profile. Pure x64 MASM, Win64 ABI, zero imports, zero heap, zero CRT.
;
; This object measures and seals evidence. It does not patch code. A caller may
; feed retained P1OR_RULE_DECISION records into the immutable RuntimeGenerator.
;
; Build:
;   ml64 /nologo /c /W3 /I src\asm /FoP1_OutcomeReverseRuntime_x64.obj \
;        src\asm\P1_OutcomeReverseRuntime_x64.asm
; =============================================================================

option casemap:none

include P1_OutcomeReverseRuntime_x64.inc

PUBLIC P1OR_GetAbiDescriptor
PUBLIC P1OR_ReadTsc
PUBLIC P1OR_InitContract
PUBLIC P1OR_ResetEpoch
PUBLIC P1OR_SetPhaseBudget
PUBLIC P1OR_SetMaxVram
PUBLIC P1OR_SetMaxActiveBytes
PUBLIC P1OR_BeginSample
PUBLIC P1OR_CommitSample
PUBLIC P1OR_RecordSample
PUBLIC P1OR_RecordPublication
PUBLIC P1OR_SealEpoch
PUBLIC P1OR_ShouldRetainRule
PUBLIC P1OR_ProjectReverse

.const
ALIGN 8

; 10 ms reverse budget at 100 TPS:
; weight 55%, attention/KV 15%, MoE 7.5%, publication 2.5%,
; sample/stream 5%, reserve 15%.
p1or_phase_budget_bps LABEL WORD
    DW 5500, 1500, 750, 250, 500, 1500

ALIGN 8
p1or_abi_descriptor LABEL BYTE
    DQ P1OR_DESCRIPTOR_MAGIC
    DD P1OR_ABI_VERSION
    DD P1OR_PHASE_COUNT
    DQ P1OR_CONTEXT_SIZE
    DQ P1OR_PHASE_SAMPLE_SIZE
    DQ P1OR_PUBLICATION_EVIDENCE_SIZE
    DQ P1OR_DECISION_SIZE
    DQ P1OR_RULE_DECISION_SIZE
    DQ P1OR_REVERSE_PROJECTION_SIZE

.code

; const P1OR_ABI_DESCRIPTOR* P1OR_GetAbiDescriptor(void)
P1OR_GetAbiDescriptor PROC
    lea rax, p1or_abi_descriptor
    ret
P1OR_GetAbiDescriptor ENDP

; uint64_t P1OR_ReadTsc(void)
P1OR_ReadTsc PROC
    lfence
    rdtsc
    shl rdx, 32
    or  rax, rdx
    lfence
    ret
P1OR_ReadTsc ENDP

; uint32_t P1OR_InitContract(P1OR_CONTEXT* context, uint64_t tscHz)
P1OR_InitContract PROC
    test rcx, rcx
    jz   p1or_init_invalid
    test rdx, rdx
    jz   p1or_init_invalid

    mov r11, rcx
    mov r10, rdx

    ; Clear the caller-owned context without touching nonvolatile registers.
    mov r8, r11
    mov r9d, (P1OR_CONTEXT_SIZE / 8)
    xor eax, eax
p1or_init_zero_loop:
    mov qword ptr [r8], rax
    add r8, 8
    dec r9
    jnz p1or_init_zero_loop

    mov rax, P1OR_CONTEXT_MAGIC
    mov qword ptr [r11 + P1OR_CONTEXT.Magic], rax
    mov dword ptr [r11 + P1OR_CONTEXT.Version], P1OR_ABI_VERSION
    mov dword ptr [r11 + P1OR_CONTEXT.PhaseCount], P1OR_PHASE_COUNT
    mov qword ptr [r11 + P1OR_CONTEXT.StateFlags], (P1OR_STATE_READY OR P1OR_STATE_EPOCH_ACTIVE)
    mov qword ptr [r11 + P1OR_CONTEXT.TscHz], r10
    mov qword ptr [r11 + P1OR_CONTEXT.TargetTps], P1OR_TARGET_TPS

    mov rax, r10
    xor edx, edx
    mov r9d, P1OR_TARGET_TPS
    div r9
    test rax, rax
    jz   p1or_init_range
    mov qword ptr [r11 + P1OR_CONTEXT.TargetTicks], rax

    mov rax, P1OR_MAX_VRAM_BYTES
    mov qword ptr [r11 + P1OR_CONTEXT.MaxVramBytes], rax
    mov rax, P1OR_MAX_ACTIVE_BYTES
    mov qword ptr [r11 + P1OR_CONTEXT.MaxActiveBytes], rax
    mov qword ptr [r11 + P1OR_CONTEXT.Epoch], 1

    lea r10, p1or_phase_budget_bps
    xor r8d, r8d
p1or_init_budget_loop:
    movzx r9d, word ptr [r10 + r8*2]
    mov rax, qword ptr [r11 + P1OR_CONTEXT.TargetTicks]
    mul r9
    test rdx, rdx
    jnz p1or_init_range
    mov r9d, P1OR_BASIS_POINTS
    div r9
    mov qword ptr [r11 + P1OR_CONTEXT.PhaseBudgetTicks + r8*8], rax
    inc r8
    cmp r8, P1OR_PHASE_COUNT
    jb  p1or_init_budget_loop

    xor eax, eax
    ret

p1or_init_range:
    mov eax, P1OR_ERANGE
    ret
p1or_init_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_InitContract ENDP

; uint32_t P1OR_ResetEpoch(P1OR_CONTEXT* context)
P1OR_ResetEpoch PROC
    test rcx, rcx
    jz   p1or_reset_invalid
    mov r11, rcx
    mov rax, P1OR_CONTEXT_MAGIC
    cmp qword ptr [r11 + P1OR_CONTEXT.Magic], rax
    jne p1or_reset_invalid

    inc qword ptr [r11 + P1OR_CONTEXT.Epoch]

    ; Clear epoch header fields while retaining the contract and budgets.
    lea r8, [r11 + P1OR_CONTEXT.CommittedTokens]
    mov r9d, ((P1OR_CONTEXT.PhaseBudgetTicks - P1OR_CONTEXT.CommittedTokens) / 8)
    xor eax, eax
p1or_reset_header_loop:
    mov qword ptr [r8], rax
    add r8, 8
    dec r9
    jnz p1or_reset_header_loop

    ; Clear phase accumulators, counters, and reserved tail.
    lea r8, [r11 + P1OR_CONTEXT.PhaseElapsedTicks]
    mov r9d, ((P1OR_CONTEXT_SIZE - P1OR_CONTEXT.PhaseElapsedTicks) / 8)
p1or_reset_phase_loop:
    mov qword ptr [r8], rax
    add r8, 8
    dec r9
    jnz p1or_reset_phase_loop

    mov qword ptr [r11 + P1OR_CONTEXT.StateFlags], (P1OR_STATE_READY OR P1OR_STATE_EPOCH_ACTIVE)
    xor eax, eax
    ret

p1or_reset_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_ResetEpoch ENDP

; uint32_t P1OR_SetPhaseBudget(context, phaseId, budgetTicks)
P1OR_SetPhaseBudget PROC
    test rcx, rcx
    jz   p1or_budget_invalid
    cmp edx, P1OR_PHASE_COUNT
    jae  p1or_budget_range
    test r8, r8
    jz   p1or_budget_range
    mov rax, P1OR_CONTEXT_MAGIC
    cmp qword ptr [rcx + P1OR_CONTEXT.Magic], rax
    jne p1or_budget_invalid
    mov qword ptr [rcx + P1OR_CONTEXT.PhaseBudgetTicks + rdx*8], r8
    xor eax, eax
    ret
p1or_budget_range:
    mov eax, P1OR_ERANGE
    ret
p1or_budget_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_SetPhaseBudget ENDP

; uint32_t P1OR_SetMaxVram(context, maxVramBytes)
P1OR_SetMaxVram PROC
    test rcx, rcx
    jz   p1or_vram_invalid
    test rdx, rdx
    jz   p1or_vram_range
    mov rax, P1OR_CONTEXT_MAGIC
    cmp qword ptr [rcx + P1OR_CONTEXT.Magic], rax
    jne p1or_vram_invalid
    mov qword ptr [rcx + P1OR_CONTEXT.MaxVramBytes], rdx
    xor eax, eax
    ret
p1or_vram_range:
    mov eax, P1OR_ERANGE
    ret
p1or_vram_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_SetMaxVram ENDP

; uint32_t P1OR_SetMaxActiveBytes(context, maxActiveBytesPerToken)
P1OR_SetMaxActiveBytes PROC
    test rcx, rcx
    jz   p1or_active_limit_invalid
    test rdx, rdx
    jz   p1or_active_limit_range
    mov rax, P1OR_CONTEXT_MAGIC
    cmp qword ptr [rcx + P1OR_CONTEXT.Magic], rax
    jne p1or_active_limit_invalid
    mov qword ptr [rcx + P1OR_CONTEXT.MaxActiveBytes], rdx
    xor eax, eax
    ret
p1or_active_limit_range:
    mov eax, P1OR_ERANGE
    ret
p1or_active_limit_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_SetMaxActiveBytes ENDP

; uint32_t P1OR_BeginSample(P1OR_PHASE_SAMPLE* sample, uint32_t phaseId)
P1OR_BeginSample PROC
    test rcx, rcx
    jz   p1or_begin_invalid
    cmp edx, P1OR_PHASE_COUNT
    jae  p1or_begin_range

    mov r10, rcx
    mov r8, rcx
    mov r9d, (P1OR_PHASE_SAMPLE_SIZE / 8)
    xor eax, eax
p1or_begin_zero_loop:
    mov qword ptr [r8], rax
    add r8, 8
    dec r9
    jnz p1or_begin_zero_loop

    mov dword ptr [r10 + P1OR_PHASE_SAMPLE.PhaseId], edx
    mov dword ptr [r10 + P1OR_PHASE_SAMPLE.Flags], P1OR_SAMPLE_VALID
    lfence
    rdtsc
    shl rdx, 32
    or  rax, rdx
    lfence
    mov qword ptr [r10 + P1OR_PHASE_SAMPLE.StartTsc], rax
    xor eax, eax
    ret
p1or_begin_range:
    mov eax, P1OR_ERANGE
    ret
p1or_begin_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_BeginSample ENDP

; uint32_t P1OR_CommitSample(context, sample)
; Captures EndTsc when ElapsedTicks was not supplied by the caller, then tail
; dispatches to P1OR_RecordSample.
P1OR_CommitSample PROC
    test rcx, rcx
    jz   p1or_commit_invalid
    test rdx, rdx
    jz   p1or_commit_invalid
    cmp qword ptr [rdx + P1OR_PHASE_SAMPLE.ElapsedTicks], 0
    jne p1or_commit_record
    cmp qword ptr [rdx + P1OR_PHASE_SAMPLE.StartTsc], 0
    je  p1or_commit_state

    mov r8, rdx
    lfence
    rdtsc
    shl rdx, 32
    or  rax, rdx
    lfence
    mov qword ptr [r8 + P1OR_PHASE_SAMPLE.EndTsc], rax
    sub rax, qword ptr [r8 + P1OR_PHASE_SAMPLE.StartTsc]
    mov qword ptr [r8 + P1OR_PHASE_SAMPLE.ElapsedTicks], rax
    mov rdx, r8
p1or_commit_record:
    jmp P1OR_RecordSample
p1or_commit_state:
    mov eax, P1OR_ESTATE
    ret
p1or_commit_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_CommitSample ENDP

; uint32_t P1OR_RecordSample(context, const sample)
P1OR_RecordSample PROC
    test rcx, rcx
    jz   p1or_record_invalid
    test rdx, rdx
    jz   p1or_record_invalid
    mov r10, rcx
    mov r11, rdx

    mov rax, P1OR_CONTEXT_MAGIC
    cmp qword ptr [r10 + P1OR_CONTEXT.Magic], rax
    jne p1or_record_invalid
    test qword ptr [r10 + P1OR_CONTEXT.StateFlags], P1OR_STATE_EPOCH_ACTIVE
    jz   p1or_record_state
    test dword ptr [r11 + P1OR_PHASE_SAMPLE.Flags], P1OR_SAMPLE_VALID
    jz   p1or_record_state

    mov r8d, dword ptr [r11 + P1OR_PHASE_SAMPLE.PhaseId]
    cmp r8d, P1OR_PHASE_COUNT
    jae p1or_record_range
    mov r9, qword ptr [r11 + P1OR_PHASE_SAMPLE.ElapsedTicks]
    test r9, r9
    jz   p1or_record_range

    add qword ptr [r10 + P1OR_CONTEXT.PhaseElapsedTicks + r8*8], r9
    inc qword ptr [r10 + P1OR_CONTEXT.PhaseSampleCount + r8*8]
    inc qword ptr [r10 + P1OR_CONTEXT.TotalSamples]

    cmp r9, qword ptr [r10 + P1OR_CONTEXT.PhaseMaxTicks + r8*8]
    jbe p1or_record_max_done
    mov qword ptr [r10 + P1OR_CONTEXT.PhaseMaxTicks + r8*8], r9
p1or_record_max_done:

    mov r9, qword ptr [r11 + P1OR_PHASE_SAMPLE.BytesRead]
    add qword ptr [r10 + P1OR_CONTEXT.PhaseBytesRead + r8*8], r9
    mov r9, qword ptr [r11 + P1OR_PHASE_SAMPLE.BytesWritten]
    add qword ptr [r10 + P1OR_CONTEXT.PhaseBytesWritten + r8*8], r9

    mov r9, qword ptr [r11 + P1OR_PHASE_SAMPLE.ActiveBytes]
    cmp r9, qword ptr [r10 + P1OR_CONTEXT.PhaseActiveMax + r8*8]
    jbe p1or_record_active_done
    mov qword ptr [r10 + P1OR_CONTEXT.PhaseActiveMax + r8*8], r9
p1or_record_active_done:
    cmp r9, qword ptr [r10 + P1OR_CONTEXT.PeakActiveBytes]
    jbe p1or_record_active_peak_done
    mov qword ptr [r10 + P1OR_CONTEXT.PeakActiveBytes], r9
p1or_record_active_peak_done:

    mov r9, qword ptr [r11 + P1OR_PHASE_SAMPLE.VramBytes]
    cmp r9, qword ptr [r10 + P1OR_CONTEXT.PeakVramBytes]
    jbe p1or_record_vram_done
    mov qword ptr [r10 + P1OR_CONTEXT.PeakVramBytes], r9
p1or_record_vram_done:

    mov r9, qword ptr [r11 + P1OR_PHASE_SAMPLE.PcieFaults]
    add qword ptr [r10 + P1OR_CONTEXT.PcieFaults], r9

    test dword ptr [r11 + P1OR_PHASE_SAMPLE.Flags], P1OR_SAMPLE_COMMITTED
    jz   p1or_record_done
    mov r9d, dword ptr [r11 + P1OR_PHASE_SAMPLE.Flags]
    cmp qword ptr [r10 + P1OR_CONTEXT.CommittedTokens], 0
    jne p1or_record_commit_aggregate
    mov qword ptr [r10 + P1OR_CONTEXT.CommitFlagsAggregate], r9
    jmp p1or_record_commit_flags_done
p1or_record_commit_aggregate:
    and qword ptr [r10 + P1OR_CONTEXT.CommitFlagsAggregate], r9
p1or_record_commit_flags_done:
    inc qword ptr [r10 + P1OR_CONTEXT.CommittedTokens]
    mov r9, qword ptr [r11 + P1OR_PHASE_SAMPLE.OutputHash]
    mov qword ptr [r10 + P1OR_CONTEXT.LastOutputHash], r9
    mov r9d, dword ptr [r11 + P1OR_PHASE_SAMPLE.Flags]
    mov qword ptr [r10 + P1OR_CONTEXT.LastCommitFlags], r9

p1or_record_done:
    xor eax, eax
    ret
p1or_record_range:
    mov eax, P1OR_ERANGE
    ret
p1or_record_state:
    mov eax, P1OR_ESTATE
    ret
p1or_record_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_RecordSample ENDP

; uint32_t P1OR_RecordPublication(context, const evidence)
; Re-derives ordering/generation/payload/prefetch predicates from raw fields.
; The containment, lifetime, slot-status, and affinity-attempt bits are supplied
; by the boundary that owns those facts.
P1OR_RecordPublication PROC
    test rcx, rcx
    jz   p1or_pub_invalid
    test rdx, rdx
    jz   p1or_pub_invalid
    mov r10, rcx
    mov r11, rdx
    mov rax, P1OR_CONTEXT_MAGIC
    cmp qword ptr [r10 + P1OR_CONTEXT.Magic], rax
    jne p1or_pub_invalid
    test qword ptr [r10 + P1OR_CONTEXT.StateFlags], P1OR_STATE_EPOCH_ACTIVE
    jz   p1or_pub_state

    ; Preserve boundary-owned positive evidence.
    mov r8, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.Flags]
    and r8, (P1OR_PUB_SLOT_PUBLISHED OR P1OR_PUB_PREFETCH_CONTAINED OR P1OR_PUB_PROFILER_LIFETIME OR P1OR_PUB_AFFINITY_ATTEMPTED)

    mov rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.ProducerSequence]
    test rax, rax
    jz   p1or_pub_sequence_done
    cmp rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.ConsumerSequence]
    jne p1or_pub_sequence_done
    or  r8, P1OR_PUB_SEQUENCE_MATCH
p1or_pub_sequence_done:

    mov rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PublishedGeneration]
    test rax, rax
    jz   p1or_pub_generation_done
    cmp rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.AcquiredGeneration]
    jne p1or_pub_generation_done
    or  r8, P1OR_PUB_GENERATION_MATCH
p1or_pub_generation_done:

    mov rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PublishTsc]
    test rax, rax
    jz   p1or_pub_order_done
    mov r9, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.AcquireTsc]
    cmp r9, rax
    jb  p1or_pub_order_done
    or  r8, P1OR_PUB_ACQUIRE_ORDERED
p1or_pub_order_done:

    cmp qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PayloadPointer], 0
    je  p1or_pub_payload_done
    mov rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PayloadLength]
    test rax, rax
    jz   p1or_pub_payload_done
    mov r9, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PayloadNonzeroBytes]
    test r9, r9
    jz   p1or_pub_payload_done
    cmp r9, rax
    ja  p1or_pub_payload_done
    or  r8, (P1OR_PUB_PAYLOAD_NONZERO OR P1OR_PUB_PAYLOAD_BOUNDS)
p1or_pub_payload_done:

    ; Prefetch becomes observable only after publication and with positive
    ; lead/overlap intervals.
    mov rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PrefetchStartTsc]
    cmp rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PublishTsc]
    jb  p1or_pub_prefetch_done
    mov r9, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PrefetchEndTsc]
    cmp r9, rax
    jb  p1or_pub_prefetch_done
    cmp qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PrefetchLeadCycles], 0
    je  p1or_pub_prefetch_done
    cmp qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.OverlapCycles], 0
    je  p1or_pub_prefetch_done
    or  r8, P1OR_PUB_PREFETCH_OBSERVED
p1or_pub_prefetch_done:

    mov qword ptr [r10 + P1OR_CONTEXT.PublicationFlags], r8
    mov rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.PrefetchLeadCycles]
    mov qword ptr [r10 + P1OR_CONTEXT.PrefetchLeadCycles], rax
    mov rax, qword ptr [r11 + P1OR_PUBLICATION_EVIDENCE.OverlapCycles]
    mov qword ptr [r10 + P1OR_CONTEXT.OverlapCycles], rax

    mov rax, r8
    and rax, P1OR_PUB_AUTHORITY_MASK
    cmp rax, P1OR_PUB_AUTHORITY_MASK
    jne p1or_pub_state
    mov rax, r8
    and rax, P1OR_PUB_PREFETCH_MASK
    cmp rax, P1OR_PUB_PREFETCH_MASK
    jne p1or_pub_state
    test r8, P1OR_PUB_PROFILER_LIFETIME
    jz   p1or_pub_state
    xor eax, eax
    ret

p1or_pub_state:
    mov eax, P1OR_ESTATE
    ret
p1or_pub_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_RecordPublication ENDP

; uint32_t P1OR_SealEpoch(context, decision)
P1OR_SealEpoch PROC
    test rcx, rcx
    jz   p1or_seal_invalid
    test rdx, rdx
    jz   p1or_seal_invalid
    mov r10, rcx
    mov r11, rdx
    mov rax, P1OR_CONTEXT_MAGIC
    cmp qword ptr [r10 + P1OR_CONTEXT.Magic], rax
    jne p1or_seal_invalid
    test qword ptr [r10 + P1OR_CONTEXT.StateFlags], P1OR_STATE_EPOCH_ACTIVE
    jz   p1or_seal_state
    cmp qword ptr [r10 + P1OR_CONTEXT.CommittedTokens], 0
    je   p1or_seal_empty

    mov r8, r11
    mov r9d, (P1OR_DECISION_SIZE / 8)
    xor eax, eax
p1or_seal_zero_loop:
    mov qword ptr [r8], rax
    add r8, 8
    dec r9
    jnz p1or_seal_zero_loop

    mov rax, P1OR_DECISION_MAGIC
    mov qword ptr [r11 + P1OR_DECISION.Magic], rax
    mov dword ptr [r11 + P1OR_DECISION.Version], P1OR_ABI_VERSION
    mov dword ptr [r11 + P1OR_DECISION.LargestDebtPhase], 0

    xor r8d, r8d
p1or_seal_phase_loop:
    mov rax, qword ptr [r10 + P1OR_CONTEXT.PhaseElapsedTicks + r8*8]
    add qword ptr [r11 + P1OR_DECISION.TotalTicks], rax
    jc  p1or_seal_range

    mov rax, qword ptr [r10 + P1OR_CONTEXT.PhaseBudgetTicks + r8*8]
    mul qword ptr [r10 + P1OR_CONTEXT.CommittedTokens]
    test rdx, rdx
    jnz p1or_seal_range
    mov r9, qword ptr [r10 + P1OR_CONTEXT.PhaseElapsedTicks + r8*8]
    cmp r9, rax
    jbe p1or_seal_debt_zero
    sub r9, rax
    jmp p1or_seal_debt_ready
p1or_seal_debt_zero:
    xor r9d, r9d
p1or_seal_debt_ready:
    mov qword ptr [r10 + P1OR_CONTEXT.PhaseDebtTicks + r8*8], r9
    mov qword ptr [r11 + P1OR_DECISION.PhaseDebtTicks + r8*8], r9
    add qword ptr [r11 + P1OR_DECISION.TotalDebtTicks], r9
    cmp r9, qword ptr [r11 + P1OR_DECISION.Reserved]
    jbe p1or_seal_largest_done
    mov qword ptr [r11 + P1OR_DECISION.Reserved], r9
    mov dword ptr [r11 + P1OR_DECISION.LargestDebtPhase], r8d
p1or_seal_largest_done:
    inc r8
    cmp r8, P1OR_PHASE_COUNT
    jb  p1or_seal_phase_loop

    mov rax, qword ptr [r11 + P1OR_DECISION.TotalTicks]
    xor edx, edx
    div qword ptr [r10 + P1OR_CONTEXT.CommittedTokens]
    test rax, rax
    jz   p1or_seal_range
    mov qword ptr [r11 + P1OR_DECISION.AverageTicks], rax
    mov r9, rax
    mov rax, qword ptr [r10 + P1OR_CONTEXT.TscHz]
    xor edx, edx
    div r9
    mov qword ptr [r11 + P1OR_DECISION.ObservedTps], rax

    mov rax, qword ptr [r10 + P1OR_CONTEXT.TargetTicks]
    mov qword ptr [r11 + P1OR_DECISION.TargetTicks], rax
    mov rax, qword ptr [r10 + P1OR_CONTEXT.PeakVramBytes]
    mov qword ptr [r11 + P1OR_DECISION.PeakVramBytes], rax
    mov rax, qword ptr [r10 + P1OR_CONTEXT.PeakActiveBytes]
    mov qword ptr [r11 + P1OR_DECISION.PeakActiveBytes], rax
    mov rax, qword ptr [r10 + P1OR_CONTEXT.PcieFaults]
    mov qword ptr [r11 + P1OR_DECISION.PcieFaults], rax
    mov rax, qword ptr [r10 + P1OR_CONTEXT.CommittedTokens]
    mov qword ptr [r11 + P1OR_DECISION.CommittedTokens], rax
    mov rax, qword ptr [r10 + P1OR_CONTEXT.LastOutputHash]
    mov qword ptr [r11 + P1OR_DECISION.OutputHash], rax
    mov rax, qword ptr [r10 + P1OR_CONTEXT.PrefetchLeadCycles]
    mov qword ptr [r11 + P1OR_DECISION.PrefetchLeadCycles], rax
    mov rax, qword ptr [r10 + P1OR_CONTEXT.OverlapCycles]
    mov qword ptr [r11 + P1OR_DECISION.OverlapCycles], rax
    mov rax, qword ptr [r10 + P1OR_CONTEXT.PublicationFlags]
    mov qword ptr [r11 + P1OR_DECISION.PublicationFlags], rax

    xor r8d, r8d
    mov rax, qword ptr [r11 + P1OR_DECISION.AverageTicks]
    cmp rax, qword ptr [r10 + P1OR_CONTEXT.TargetTicks]
    ja  p1or_seal_tps_done
    or  r8, P1OR_DECISION_TPS_PASS
p1or_seal_tps_done:

    mov rax, qword ptr [r10 + P1OR_CONTEXT.PeakVramBytes]
    cmp rax, qword ptr [r10 + P1OR_CONTEXT.MaxVramBytes]
    ja  p1or_seal_vram_done
    or  r8, P1OR_DECISION_VRAM_PASS
p1or_seal_vram_done:

    test qword ptr [r10 + P1OR_CONTEXT.CommitFlagsAggregate], P1OR_SAMPLE_AUTHORITATIVE
    jz   p1or_seal_path_done
    or   r8, P1OR_DECISION_PATH_PASS
p1or_seal_path_done:

    test qword ptr [r10 + P1OR_CONTEXT.CommitFlagsAggregate], P1OR_SAMPLE_COHERENT
    jz   p1or_seal_coherence_done
    or   r8, P1OR_DECISION_COHERENCE_PASS
p1or_seal_coherence_done:

    cmp qword ptr [r10 + P1OR_CONTEXT.PcieFaults], 0
    jne p1or_seal_residency_done
    test qword ptr [r10 + P1OR_CONTEXT.CommitFlagsAggregate], P1OR_SAMPLE_RESIDENT
    jz   p1or_seal_residency_done
    or   r8, P1OR_DECISION_RESIDENCY_PASS
p1or_seal_residency_done:

    mov rax, qword ptr [r10 + P1OR_CONTEXT.PublicationFlags]
    mov r9, rax
    and r9, P1OR_PUB_AUTHORITY_MASK
    cmp r9, P1OR_PUB_AUTHORITY_MASK
    jne p1or_seal_publication_done
    or  r8, P1OR_DECISION_PUBLICATION_PASS
p1or_seal_publication_done:

    mov r9, rax
    and r9, P1OR_PUB_PREFETCH_MASK
    cmp r9, P1OR_PUB_PREFETCH_MASK
    jne p1or_seal_prefetch_done
    cmp qword ptr [r10 + P1OR_CONTEXT.PrefetchLeadCycles], 0
    je  p1or_seal_prefetch_done
    cmp qword ptr [r10 + P1OR_CONTEXT.OverlapCycles], 0
    je  p1or_seal_prefetch_done
    or  r8, P1OR_DECISION_PREFETCH_PASS
p1or_seal_prefetch_done:

    test rax, P1OR_PUB_PROFILER_LIFETIME
    jz   p1or_seal_lifetime_done
    or   r8, P1OR_DECISION_LIFETIME_PASS
p1or_seal_lifetime_done:

    mov rax, qword ptr [r10 + P1OR_CONTEXT.PeakActiveBytes]
    test rax, rax
    jz   p1or_seal_active_bytes_done
    cmp rax, qword ptr [r10 + P1OR_CONTEXT.MaxActiveBytes]
    ja  p1or_seal_active_bytes_done
    or  r8, P1OR_DECISION_ACTIVE_BYTES_PASS
p1or_seal_active_bytes_done:

    mov rax, r8
    and rax, P1OR_DECISION_REQUIRED_MASK
    cmp rax, P1OR_DECISION_REQUIRED_MASK
    jne p1or_seal_cert_done
    or  r8, P1OR_DECISION_CERT_PASS
p1or_seal_cert_done:
    mov qword ptr [r11 + P1OR_DECISION.Flags], r8
    mov qword ptr [r11 + P1OR_DECISION.Reserved], 0
    mov qword ptr [r10 + P1OR_CONTEXT.StateFlags], (P1OR_STATE_READY OR P1OR_STATE_SEALED)
    xor eax, eax
    ret

p1or_seal_range:
    mov eax, P1OR_ERANGE
    ret
p1or_seal_empty:
    mov eax, P1OR_EEMPTY
    ret
p1or_seal_state:
    mov eax, P1OR_ESTATE
    ret
p1or_seal_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_SealEpoch ENDP

; uint32_t P1OR_ShouldRetainRule(
;     const P1OR_DECISION* baseline,
;     const P1OR_DECISION* candidate,
;     uint64_t minimumGainTicks,
;     P1OR_RULE_DECISION* result)
;
; Returns 1 when retained, 0 when rejected. Invalid inputs also reject and leave
; EAX=0 so this predicate remains fail-closed at the caller boundary.
P1OR_ShouldRetainRule PROC
    test rcx, rcx
    jz   p1or_rule_reject
    test rdx, rdx
    jz   p1or_rule_reject
    test r9, r9
    jz   p1or_rule_reject

    mov rax, P1OR_DECISION_MAGIC
    cmp qword ptr [rcx + P1OR_DECISION.Magic], rax
    jne p1or_rule_reject
    cmp qword ptr [rdx + P1OR_DECISION.Magic], rax
    jne p1or_rule_reject

    mov r10, r9
    mov r11d, (P1OR_RULE_DECISION_SIZE / 8)
    xor eax, eax
p1or_rule_zero_loop:
    mov qword ptr [r10], rax
    add r10, 8
    dec r11
    jnz p1or_rule_zero_loop
    mov r10, r9

    mov rax, P1OR_RULE_MAGIC
    mov qword ptr [r10 + P1OR_RULE_DECISION.Magic], rax
    mov dword ptr [r10 + P1OR_RULE_DECISION.Version], P1OR_ABI_VERSION
    mov eax, dword ptr [rcx + P1OR_DECISION.LargestDebtPhase]
    mov dword ptr [r10 + P1OR_RULE_DECISION.ChangedPhase], eax

    mov rax, qword ptr [rcx + P1OR_DECISION.AverageTicks]
    mov qword ptr [r10 + P1OR_RULE_DECISION.BaselineTicks], rax
    mov rax, qword ptr [rdx + P1OR_DECISION.AverageTicks]
    mov qword ptr [r10 + P1OR_RULE_DECISION.CandidateTicks], rax
    mov rax, qword ptr [rcx + P1OR_DECISION.OutputHash]
    mov qword ptr [r10 + P1OR_RULE_DECISION.BaselineHash], rax
    mov rax, qword ptr [rdx + P1OR_DECISION.OutputHash]
    mov qword ptr [r10 + P1OR_RULE_DECISION.CandidateHash], rax

    xor r11d, r11d
    test qword ptr [rdx + P1OR_DECISION.Flags], P1OR_DECISION_CERT_PASS
    jz   p1or_rule_contract_done
    or   r11, P1OR_RULE_CONTRACT_PASS
p1or_rule_contract_done:

    mov rax, qword ptr [rcx + P1OR_DECISION.OutputHash]
    test rax, rax
    jz   p1or_rule_output_done
    cmp rax, qword ptr [rdx + P1OR_DECISION.OutputHash]
    jne p1or_rule_output_done
    or  r11, P1OR_RULE_OUTPUT_STABLE
p1or_rule_output_done:

    mov rax, qword ptr [rcx + P1OR_DECISION.AverageTicks]
    cmp rax, qword ptr [rdx + P1OR_DECISION.AverageTicks]
    jbe p1or_rule_gain_done
    sub rax, qword ptr [rdx + P1OR_DECISION.AverageTicks]
    mov qword ptr [r10 + P1OR_RULE_DECISION.GainTicks], rax
    cmp rax, r8
    jb  p1or_rule_gain_done

    mov r9, P1OR_BASIS_POINTS
    mul r9
    test rdx, rdx
    jnz p1or_rule_gain_done
    div qword ptr [rcx + P1OR_DECISION.AverageTicks]
    mov qword ptr [r10 + P1OR_RULE_DECISION.GainBasisPoints], rax
    or  r11, P1OR_RULE_GAIN_PASS
p1or_rule_gain_done:

    mov rax, r11
    and rax, (P1OR_RULE_CONTRACT_PASS OR P1OR_RULE_OUTPUT_STABLE OR P1OR_RULE_GAIN_PASS)
    cmp rax, (P1OR_RULE_CONTRACT_PASS OR P1OR_RULE_OUTPUT_STABLE OR P1OR_RULE_GAIN_PASS)
    jne p1or_rule_store_reject
    or  r11, P1OR_RULE_RETAINED
    mov qword ptr [r10 + P1OR_RULE_DECISION.Flags], r11
    mov eax, 1
    ret

p1or_rule_store_reject:
    mov qword ptr [r10 + P1OR_RULE_DECISION.Flags], r11
p1or_rule_reject:
    xor eax, eax
    ret
P1OR_ShouldRetainRule ENDP

; uint32_t P1OR_ProjectReverse(
;     uint64_t debtTicks,
;     uint64_t measuredGainTicks,
;     uint64_t referenceTicks,
;     P1OR_REVERSE_PROJECTION* result)
;
; projected = measuredGain * 2.3
; epsilon   = max(reference * 0.001, 1 tick)
; residual  = abs(debt - projected)
;
; The returned 23-pass limit is policy metadata for the caller's measured
; feedback loop. This procedure performs one deterministic projection only.
P1OR_ProjectReverse PROC
    test rcx, rcx
    jz   p1or_reverse_invalid
    test rdx, rdx
    jz   p1or_reverse_invalid
    test r8, r8
    jz   p1or_reverse_invalid
    test r9, r9
    jz   p1or_reverse_invalid

    mov r11, r9
    mov r10d, (P1OR_REVERSE_PROJECTION_SIZE / 8)
    xor eax, eax
p1or_reverse_zero_loop:
    mov qword ptr [r11], rax
    add r11, 8
    dec r10
    jnz p1or_reverse_zero_loop
    mov r11, r9

    mov rax, P1OR_REVERSE_MAGIC
    mov qword ptr [r11 + P1OR_REVERSE_PROJECTION.Magic], rax
    mov dword ptr [r11 + P1OR_REVERSE_PROJECTION.Version], P1OR_ABI_VERSION
    mov dword ptr [r11 + P1OR_REVERSE_PROJECTION.PassLimit], P1OR_REVERSE_MAX_PASSES
    mov qword ptr [r11 + P1OR_REVERSE_PROJECTION.DebtTicks], rcx
    mov qword ptr [r11 + P1OR_REVERSE_PROJECTION.MeasuredGainTicks], rdx
    mov qword ptr [r11 + P1OR_REVERSE_PROJECTION.ReferenceTicks], r8
    mov qword ptr [r11 + P1OR_REVERSE_PROJECTION.MultiplierMilli], P1OR_REVERSE_MULTIPLIER

    mov rax, rdx
    mov r10d, P1OR_REVERSE_MULTIPLIER
    mul r10
    test rdx, rdx
    jnz p1or_reverse_range
    mov r10d, P1OR_REVERSE_SCALE
    div r10
    mov qword ptr [r11 + P1OR_REVERSE_PROJECTION.ProjectedGainTicks], rax

    mov r10, rcx
    xor r9d, r9d
    cmp rax, r10
    jbe p1or_reverse_under
    sub rax, r10
    or  r9, P1OR_REVERSE_OVERSHOOT
    jmp p1or_reverse_residual_ready
p1or_reverse_under:
    sub r10, rax
    mov rax, r10
p1or_reverse_residual_ready:
    mov qword ptr [r11 + P1OR_REVERSE_PROJECTION.ResidualTicks], rax

    mov r10, rax
    mov rax, r8
    mov ecx, P1OR_REVERSE_EPSILON
    mul rcx
    test rdx, rdx
    jnz p1or_reverse_range
    xor edx, edx
    mov ecx, P1OR_REVERSE_SCALE
    div rcx
    test rax, rax
    jnz p1or_reverse_epsilon_ready
    mov eax, 1
p1or_reverse_epsilon_ready:
    mov qword ptr [r11 + P1OR_REVERSE_PROJECTION.EpsilonTicks], rax
    or  r9, P1OR_REVERSE_VALID
    cmp r10, rax
    ja  p1or_reverse_flags_ready
    or  r9, P1OR_REVERSE_WITHIN_EPSILON
p1or_reverse_flags_ready:
    mov qword ptr [r11 + P1OR_REVERSE_PROJECTION.Flags], r9
    xor eax, eax
    ret

p1or_reverse_range:
    mov eax, P1OR_ERANGE
    ret
p1or_reverse_invalid:
    mov eax, P1OR_EINVAL
    ret
P1OR_ProjectReverse ENDP

END
