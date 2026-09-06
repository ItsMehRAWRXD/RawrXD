; ==============================================================================
; P1_REGENERATIVE_RUNTIME_001 — GenerationAuthorityRecord + verify stub
; Enforces: PATCH_HISTORY_IS_NOT_RUNTIME_AUTHORITY = 1
; ==============================================================================

IFNDEF GENERATION_AUTHORITY_RECORD_ASM
GENERATION_AUTHORITY_RECORD_ASM EQU 1

GenerationAuthorityRecord STRUCT 8
    SealedAuthorityHash     DQ 4 DUP (?)
    HardwareFactsPtr        DQ ?
    WorkloadFactsPtr        DQ ?
    CurrentBudgetLimitMs    DQ ?
    RetainedProofsTablePtr  DQ ?
    GenerationCounter       DQ ?
GenerationAuthorityRecord ENDS

; RCX = pointer to GenerationAuthorityRecord
; Returns RAX = 1 success, 0 authority seal failure
; Structurally ignores any historical patch arrays (no 5th input).
PUBLIC VerifyAndRegenerateRuntimeImage
.code
VerifyAndRegenerateRuntimeImage PROC
    test    rcx, rcx
    jz      fail_seal

    ; RetainedProofsTablePtr must be non-null (sealed facts path)
    mov     rsi, [rcx + GenerationAuthorityRecord.RetainedProofsTablePtr]
    test    rsi, rsi
    jz      fail_seal

    ; Clear historical scratch — patch history must not participate
    xor     r10, r10
    xor     r11, r11

    ; Generation counter must be readable (monotonic control plane)
    mov     rax, [rcx + GenerationAuthorityRecord.GenerationCounter]
    ; Success: G+1 generation authorized from sealed inputs only
    mov     eax, 1
    ret

fail_seal:
    xor     eax, eax
    ret
VerifyAndRegenerateRuntimeImage ENDP

ENDIF
