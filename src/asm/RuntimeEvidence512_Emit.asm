; RuntimeEvidence512_Emit.asm — one exported symbol per claim; no generic Emit.
OPTION CASEMAP:NONE

EV_STATUS_FALSE     EQU 0
EV_STATUS_TRUE      EQU 1
EV_STATUS_ENTER     EQU 2
EV_STATUS_COMPLETE  EQU 3
EV_STATUS_ABORT     EQU 4
EV_STATUS_FAULT     EQU 5
EV_STATUS_OBSERVED  EQU 6

CLAIM_FIRST_TOKEN_BOUNDARY EQU 1
CLAIM_HIDDEN_PROBE         EQU 2
CLAIM_HIDDEN_LAST          EQU 3
CLAIM_BOUNDED              EQU 4
CLAIM_VALID                EQU 5
CLAIM_LOGITS_ENTRY         EQU 6
CLAIM_LOGITS_COMPLETE      EQU 7
CLAIM_ATTN_COMPLETE        EQU 8
CLAIM_PATHB_COMPLETE       EQU 9
CLAIM_STREAM_COMPLETE      EQU 10
CLAIM_STREAM_ABORT         EQU 11
CLAIM_TEARDOWN_ENTRY       EQU 12
CLAIM_TEARDOWN_COMPLETE    EQU 13
CLAIM_TEARDOWN_FAULT       EQU 14
CLAIM_WALL_NS              EQU 15
CLAIM_DECODE_TPS_Q32_32    EQU 16
CLAIM_PARITY               EQU 17

EXTERN EvidenceEmitCore:PROC

PUBLIC EvidenceEmitFirstTokenBoundary
PUBLIC EvidenceEmitHiddenProbe
PUBLIC EvidenceEmitHiddenLast
PUBLIC EvidenceEmitBounds
PUBLIC EvidenceEmitValid
PUBLIC EvidenceEmitLogitsEntry
PUBLIC EvidenceEmitLogitsComplete
PUBLIC EvidenceEmitAttnComplete
PUBLIC EvidenceEmitPathBComplete
PUBLIC EvidenceEmitStreamComplete
PUBLIC EvidenceEmitStreamAbort
PUBLIC EvidenceEmitTeardownEntry
PUBLIC EvidenceEmitTeardownComplete
PUBLIC EvidenceEmitTeardownFault
PUBLIC EvidenceEmitWallNs
PUBLIC EvidenceEmitDecodeTpsQ32_32
PUBLIC EvidenceEmitParity

.code

EvidenceEmitFirstTokenBoundary PROC
    mov  r9d, EV_STATUS_ENTER
    mov  r10d, CLAIM_FIRST_TOKEN_BOUNDARY
    jmp  EvidenceEmitCore
EvidenceEmitFirstTokenBoundary ENDP

EvidenceEmitHiddenProbe PROC
    mov  r9d, EV_STATUS_OBSERVED
    mov  r10d, CLAIM_HIDDEN_PROBE
    jmp  EvidenceEmitCore
EvidenceEmitHiddenProbe ENDP

EvidenceEmitHiddenLast PROC
    mov  r9d, EV_STATUS_OBSERVED
    mov  r10d, CLAIM_HIDDEN_LAST
    jmp  EvidenceEmitCore
EvidenceEmitHiddenLast ENDP

EvidenceEmitBounds PROC
    test r9d, r9d
    setnz al
    movzx r9d, al
    mov  r10d, CLAIM_BOUNDED
    jmp  EvidenceEmitCore
EvidenceEmitBounds ENDP

EvidenceEmitValid PROC
    test r9d, r9d
    setnz al
    movzx r9d, al
    mov  r10d, CLAIM_VALID
    jmp  EvidenceEmitCore
EvidenceEmitValid ENDP

EvidenceEmitLogitsEntry PROC
    mov  r9d, EV_STATUS_ENTER
    mov  r10d, CLAIM_LOGITS_ENTRY
    jmp  EvidenceEmitCore
EvidenceEmitLogitsEntry ENDP

EvidenceEmitLogitsComplete PROC
    mov  r9d, EV_STATUS_COMPLETE
    mov  r10d, CLAIM_LOGITS_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitLogitsComplete ENDP

EvidenceEmitAttnComplete PROC
    mov  r9d, EV_STATUS_COMPLETE
    mov  r10d, CLAIM_ATTN_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitAttnComplete ENDP

EvidenceEmitPathBComplete PROC
    mov  r9d, EV_STATUS_COMPLETE
    mov  r10d, CLAIM_PATHB_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitPathBComplete ENDP

EvidenceEmitStreamComplete PROC
    mov  r9d, EV_STATUS_COMPLETE
    mov  r10d, CLAIM_STREAM_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitStreamComplete ENDP

EvidenceEmitStreamAbort PROC
    mov  r9d, EV_STATUS_ABORT
    mov  r10d, CLAIM_STREAM_ABORT
    jmp  EvidenceEmitCore
EvidenceEmitStreamAbort ENDP

EvidenceEmitTeardownEntry PROC
    mov  r9d, EV_STATUS_ENTER
    mov  r10d, CLAIM_TEARDOWN_ENTRY
    jmp  EvidenceEmitCore
EvidenceEmitTeardownEntry ENDP

EvidenceEmitTeardownComplete PROC
    mov  r9d, EV_STATUS_COMPLETE
    mov  r10d, CLAIM_TEARDOWN_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitTeardownComplete ENDP

EvidenceEmitTeardownFault PROC
    mov  r9d, EV_STATUS_FAULT
    mov  r10d, CLAIM_TEARDOWN_FAULT
    jmp  EvidenceEmitCore
EvidenceEmitTeardownFault ENDP

EvidenceEmitWallNs PROC
    mov  r9d, EV_STATUS_OBSERVED
    mov  r10d, CLAIM_WALL_NS
    jmp  EvidenceEmitCore
EvidenceEmitWallNs ENDP

EvidenceEmitDecodeTpsQ32_32 PROC
    mov  r9d, EV_STATUS_OBSERVED
    mov  r10d, CLAIM_DECODE_TPS_Q32_32
    jmp  EvidenceEmitCore
EvidenceEmitDecodeTpsQ32_32 ENDP

EvidenceEmitParity PROC
    test r9d, r9d
    setnz al
    movzx r9d, al
    mov  r10d, CLAIM_PARITY
    jmp  EvidenceEmitCore
EvidenceEmitParity ENDP

END
