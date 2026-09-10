; RuntimeEvidence512.asm
; x64 MASM / ml64.exe
; Zero CRT. Zero external symbols. Caller-owned memory only.
;
; Purpose:
;   Claim-isolated runtime evidence for the seqCap=512 post-first-token audit.
;   A claim exists as runtime evidence only when its corresponding emitter runs.
;   No synthetic "did not fire" records are generated.
;
; Windows x64 ABI.
;
; Build:
;   ml64 /c /FoRuntimeEvidence512.obj RuntimeEvidence512.asm
;
; EvidenceState layout (48 bytes):
;   +00 qword Buffer            ; EvidenceRecord[Capacity]
;   +08 qword Capacity          ; record count, never wraps
;   +16 qword WriteIndex        ; monotonically increasing reservation index
;   +24 qword Dropped           ; incremented when capacity exhausted
;   +32 qword RunId             ; caller-supplied run identity
;   +40 dword SeqCap            ; MUST equal 512
;   +44 dword Flags             ; reserved
;
; EvidenceRecord layout (64 bytes):
;   +00 dword Magic             ; 'RXEV'
;   +04 word  Version           ; 1
;   +06 word  RecordBytes       ; 64
;   +08 dword ClaimId
;   +12 dword Status
;   +16 qword RunId
;   +24 qword Ordinal           ; record reservation index
;   +32 dword SeqCap            ; always 512 for accepted state
;   +36 dword Reserved
;   +40 qword Arg0
;   +48 qword Arg1
;   +56 qword Commit            ; written LAST; 0 means incomplete record
;
; Commit protocol:
;   record fields are written first, then Commit is published with XCHG.
;   Readers MUST ignore records whose Commit != EVREC_COMMIT.
;
; Uniform evidence meaning:
;   Missing corresponding record = NO RUNTIME OBSERVATION for that claim.
;   Another claim's record never substitutes for the missing record.

OPTION CASEMAP:NONE

EVS_BUFFER          EQU 0
EVS_CAPACITY        EQU 8
EVS_WRITE_INDEX     EQU 16
EVS_DROPPED         EQU 24
EVS_RUN_ID          EQU 32
EVS_SEQ_CAP         EQU 40
EVS_FLAGS           EQU 44
EVS_BYTES           EQU 48

EVREC_MAGIC         EQU 56455852h        ; bytes: 52 58 45 56 = "RXEV"
EVREC_VERSION       EQU 1
EVREC_BYTES         EQU 64
EVREC_COMMIT        EQU 0A11CE55A11CE55h

SEQ_CAP_REQUIRED    EQU 512
FLOOR_TPS_MILLI     EQU 5000

; Status values. FALSE/TRUE are deliberately 0/1 so bounds/valid can emit
; the runtime disposition directly without translation downstream.
EV_STATUS_FALSE     EQU 0
EV_STATUS_TRUE      EQU 1
EV_STATUS_ENTER     EQU 2
EV_STATUS_COMPLETE  EQU 3
EV_STATUS_ABORT     EQU 4
EV_STATUS_FAULT     EQU 5
EV_STATUS_OBSERVED  EQU 6

; Claim IDs are unique.  Do not alias them.
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

PUBLIC EvidenceInit512
PUBLIC EvidenceResetRun512
PUBLIC EvidenceGetCommittedCount
PUBLIC EvidenceGetDroppedCount
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

; ---------------------------------------------------------------------------
; EvidenceInit512
;   rcx = EvidenceState*
;   rdx = EvidenceRecord* buffer
;   r8  = capacity in records
;   r9  = runId
;   [rsp+40] = seqCap (5th ABI argument) -- MUST be 512
; Returns eax=1 on success, eax=0 on reject.
; ---------------------------------------------------------------------------
EvidenceInit512 PROC
    test rcx, rcx
    jz   ei_fail
    test rdx, rdx
    jz   ei_fail
    test r8,  r8
    jz   ei_fail

    mov  eax, dword ptr [rsp+40]
    cmp  eax, SEQ_CAP_REQUIRED
    jne  ei_fail

    mov  qword ptr [rcx+EVS_BUFFER],      rdx
    mov  qword ptr [rcx+EVS_CAPACITY],    r8
    mov  qword ptr [rcx+EVS_WRITE_INDEX], 0
    mov  qword ptr [rcx+EVS_DROPPED],     0
    mov  qword ptr [rcx+EVS_RUN_ID],      r9
    mov  dword ptr [rcx+EVS_SEQ_CAP],     eax
    mov  dword ptr [rcx+EVS_FLAGS],       0

    mov  eax, 1
    ret

ei_fail:
    xor  eax, eax
    ret
EvidenceInit512 ENDP

; ---------------------------------------------------------------------------
; EvidenceResetRun512
;   rcx = EvidenceState*
;   rdx = new runId
;   r8d = seqCap, MUST be 512
; Keeps the same caller-owned buffer/capacity.
; Returns eax=1 success, 0 reject.
; ---------------------------------------------------------------------------
EvidenceResetRun512 PROC
    test rcx, rcx
    jz   er_fail
    cmp  r8d, SEQ_CAP_REQUIRED
    jne  er_fail
    cmp  qword ptr [rcx+EVS_BUFFER], 0
    je   er_fail
    cmp  qword ptr [rcx+EVS_CAPACITY], 0
    je   er_fail

    mov  qword ptr [rcx+EVS_WRITE_INDEX], 0
    mov  qword ptr [rcx+EVS_DROPPED],     0
    mov  qword ptr [rcx+EVS_RUN_ID],      rdx
    mov  dword ptr [rcx+EVS_SEQ_CAP],     r8d
    mov  dword ptr [rcx+EVS_FLAGS],       0
    mov  eax, 1
    ret

er_fail:
    xor  eax, eax
    ret
EvidenceResetRun512 ENDP

; ---------------------------------------------------------------------------
; EvidenceGetCommittedCount
;   rcx = EvidenceState*
; Returns min(WriteIndex, Capacity). This is inventory only, not claim evidence.
; ---------------------------------------------------------------------------
EvidenceGetCommittedCount PROC
    test rcx, rcx
    jz   egc_zero
    mov  rax, qword ptr [rcx+EVS_WRITE_INDEX]
    mov  rdx, qword ptr [rcx+EVS_CAPACITY]
    cmp  rax, rdx
    jbe  egc_done
    mov  rax, rdx
egc_done:
    ret
egc_zero:
    xor  eax, eax
    ret
EvidenceGetCommittedCount ENDP

EvidenceGetDroppedCount PROC
    test rcx, rcx
    jz   egd_zero
    mov  rax, qword ptr [rcx+EVS_DROPPED]
    ret
egd_zero:
    xor  eax, eax
    ret
EvidenceGetDroppedCount ENDP

; ---------------------------------------------------------------------------
; PRIVATE writer
;   rcx  = EvidenceState*
;   rdx  = Arg0
;   r8   = Arg1
;   r9d  = Status
;   r10d = ClaimId
; Returns eax=1 committed, eax=0 rejected/dropped.
;
; The public surface NEVER exposes a generic claim-id argument.  A specific
; exported emitter owns each ClaimId.
; ---------------------------------------------------------------------------
EvidenceEmitCore PROC
    test rcx, rcx
    jz   eec_fail

    cmp  dword ptr [rcx+EVS_SEQ_CAP], SEQ_CAP_REQUIRED
    jne  eec_fail

    mov  r11, qword ptr [rcx+EVS_BUFFER]
    test r11, r11
    jz   eec_fail

    cmp  qword ptr [rcx+EVS_CAPACITY], 0
    je   eec_fail

    ; Reserve one immutable slot. Never wrap/overwrite prior evidence.
    mov  rax, 1
    lock xadd qword ptr [rcx+EVS_WRITE_INDEX], rax ; rax = old index
    cmp  rax, qword ptr [rcx+EVS_CAPACITY]
    jb   eec_have_slot

    lock inc qword ptr [rcx+EVS_DROPPED]
    xor  eax, eax
    ret

eec_have_slot:
    ; 64-byte record: address = base + ordinal*64.
    shl  rax, 6
    add  r11, rax
    shr  rax, 6                  ; restore ordinal

    ; Clear commit first. A reader must ignore the slot until final XCHG.
    mov  qword ptr [r11+56], 0

    mov  dword ptr [r11+0],  EVREC_MAGIC
    mov  word  ptr [r11+4],  EVREC_VERSION
    mov  word  ptr [r11+6],  EVREC_BYTES
    mov  dword ptr [r11+8],  r10d
    mov  dword ptr [r11+12], r9d

    mov  r10, qword ptr [rcx+EVS_RUN_ID]
    mov  qword ptr [r11+16], r10
    mov  qword ptr [r11+24], rax

    mov  eax, dword ptr [rcx+EVS_SEQ_CAP]
    mov  dword ptr [r11+32], eax
    mov  dword ptr [r11+36], 0

    mov  qword ptr [r11+40], rdx
    mov  qword ptr [r11+48], r8

    ; Publish LAST. XCHG with memory is atomic and provides a full barrier.
    mov  rax, EVREC_COMMIT
    xchg qword ptr [r11+56], rax

    mov  eax, 1
    ret

eec_fail:
    xor  eax, eax
    ret
EvidenceEmitCore ENDP

; ---------------------------------------------------------------------------
; Claim-specific emitters
; ---------------------------------------------------------------------------

; rcx=state, rdx=firstTokenIndex, r8=tokenId
EvidenceEmitFirstTokenBoundary PROC
    mov  r9d,  EV_STATUS_ENTER
    mov  r10d, CLAIM_FIRST_TOKEN_BOUNDARY
    jmp  EvidenceEmitCore
EvidenceEmitFirstTokenBoundary ENDP

; rcx=state, rdx=probeIndex, r8=rawValueBits
EvidenceEmitHiddenProbe PROC
    mov  r9d,  EV_STATUS_OBSERVED
    mov  r10d, CLAIM_HIDDEN_PROBE
    jmp  EvidenceEmitCore
EvidenceEmitHiddenProbe ENDP

; rcx=state, rdx=lastIndex, r8=rawValueBits
EvidenceEmitHiddenLast PROC
    mov  r9d,  EV_STATUS_OBSERVED
    mov  r10d, CLAIM_HIDDEN_LAST
    jmp  EvidenceEmitCore
EvidenceEmitHiddenLast ENDP

; rcx=state, rdx=index, r8=elementCount, r9d=boundedBool
EvidenceEmitBounds PROC
    test r9d, r9d
    setnz al
    movzx r9d, al
    mov  r10d, CLAIM_BOUNDED
    jmp  EvidenceEmitCore
EvidenceEmitBounds ENDP

; rcx=state, rdx=subjectId/pointer/index, r8=detail, r9d=validBool
EvidenceEmitValid PROC
    test r9d, r9d
    setnz al
    movzx r9d, al
    mov  r10d, CLAIM_VALID
    jmp  EvidenceEmitCore
EvidenceEmitValid ENDP

; rcx=state, rdx=hiddenStatePtr, r8=hiddenCount
EvidenceEmitLogitsEntry PROC
    mov  r9d,  EV_STATUS_ENTER
    mov  r10d, CLAIM_LOGITS_ENTRY
    jmp  EvidenceEmitCore
EvidenceEmitLogitsEntry ENDP

; rcx=state, rdx=argmaxToken, r8=argmaxScoreRawBits
EvidenceEmitLogitsComplete PROC
    mov  r9d,  EV_STATUS_COMPLETE
    mov  r10d, CLAIM_LOGITS_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitLogitsComplete ENDP

; rcx=state, rdx=layerOrStep, r8=detail
EvidenceEmitAttnComplete PROC
    mov  r9d,  EV_STATUS_COMPLETE
    mov  r10d, CLAIM_ATTN_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitAttnComplete ENDP

; rcx=state, rdx=step, r8=detail
EvidenceEmitPathBComplete PROC
    mov  r9d,  EV_STATUS_COMPLETE
    mov  r10d, CLAIM_PATHB_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitPathBComplete ENDP

; rcx=state, rdx=generatedTokenCount, r8=generationWallNs
EvidenceEmitStreamComplete PROC
    mov  r9d,  EV_STATUS_COMPLETE
    mov  r10d, CLAIM_STREAM_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitStreamComplete ENDP

; rcx=state, rdx=abortCode, r8=stageId
EvidenceEmitStreamAbort PROC
    mov  r9d,  EV_STATUS_ABORT
    mov  r10d, CLAIM_STREAM_ABORT
    jmp  EvidenceEmitCore
EvidenceEmitStreamAbort ENDP

; rcx=state, rdx=objectPtr, r8=stageId
EvidenceEmitTeardownEntry PROC
    mov  r9d,  EV_STATUS_ENTER
    mov  r10d, CLAIM_TEARDOWN_ENTRY
    jmp  EvidenceEmitCore
EvidenceEmitTeardownEntry ENDP

; rcx=state, rdx=objectPtr, r8=stageId
EvidenceEmitTeardownComplete PROC
    mov  r9d,  EV_STATUS_COMPLETE
    mov  r10d, CLAIM_TEARDOWN_COMPLETE
    jmp  EvidenceEmitCore
EvidenceEmitTeardownComplete ENDP

; rcx=state, rdx=exceptionCode, r8=faultAddress
EvidenceEmitTeardownFault PROC
    mov  r9d,  EV_STATUS_FAULT
    mov  r10d, CLAIM_TEARDOWN_FAULT
    jmp  EvidenceEmitCore
EvidenceEmitTeardownFault ENDP

; rcx=state, rdx=wallNs, r8=0
EvidenceEmitWallNs PROC
    mov  r9d,  EV_STATUS_OBSERVED
    mov  r10d, CLAIM_WALL_NS
    jmp  EvidenceEmitCore
EvidenceEmitWallNs ENDP

; rcx=state, rdx=TPS in unsigned Q32.32, r8=floor in Q32.32
; The fixed policy floor is 5.000 TPS; caller should pass 5<<32 in r8.
EvidenceEmitDecodeTpsQ32_32 PROC
    mov  r9d,  EV_STATUS_OBSERVED
    mov  r10d, CLAIM_DECODE_TPS_Q32_32
    jmp  EvidenceEmitCore
EvidenceEmitDecodeTpsQ32_32 ENDP

; rcx=state, rdx=parityDetail0, r8=parityDetail1, r9d=passBool
EvidenceEmitParity PROC
    test r9d, r9d
    setnz al
    movzx r9d, al
    mov  r10d, CLAIM_PARITY
    jmp  EvidenceEmitCore
EvidenceEmitParity ENDP

END
