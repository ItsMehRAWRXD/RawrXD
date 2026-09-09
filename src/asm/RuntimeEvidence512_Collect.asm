; RuntimeEvidence512_Collect.asm
; x64 MASM / ml64.exe
; Zero CRT. Zero external symbols. Read-only collector for RuntimeEvidence512.
;
; Compatible with the landed RuntimeEvidence512 ABI:
;   EvidenceState  = 48 bytes
;   EvidenceRecord = 64 bytes
;   Commit @ +56, published last with XCHG
;   SeqCap MUST equal 512
;
; Collector law:
;   - Never writes EvidenceState or EvidenceRecord.
;   - Never manufactures a record for a missing claim.
;   - Never lets one ClaimId satisfy another ClaimId.
;   - A record is accepted only when Commit, magic, version, size, RunId,
;     SeqCap and ClaimId are all valid.
;   - Dropped > 0 is surfaced; it is never converted into an observation.
;   - "closed snapshot" means every RESERVED slot visible to this scan is
;     committed+valid and Dropped==0. Caller must still invoke collection
;     only after the measured run has reached its real completion/join point.
;
; Build:
;   ml64 /c /FoRuntimeEvidence512_Collect.obj RuntimeEvidence512_Collect.asm
;
; Exports:
;   EvidenceSummarize512
;   EvidenceFindClaim512
;   EvidenceCopyCommitted512

OPTION CASEMAP:NONE

; EvidenceState offsets
EVS_BUFFER          EQU 0
EVS_CAPACITY        EQU 8
EVS_WRITE_INDEX     EQU 16
EVS_DROPPED         EQU 24
EVS_RUN_ID          EQU 32
EVS_SEQ_CAP         EQU 40
EVS_FLAGS           EQU 44
EVS_BYTES           EQU 48

; EvidenceRecord offsets
EVREC_MAGIC_OFF     EQU 0
EVREC_VERSION_OFF   EQU 4
EVREC_RECBYTES_OFF  EQU 6
EVREC_CLAIM_ID_OFF  EQU 8
EVREC_STATUS_OFF    EQU 12
EVREC_RUN_ID_OFF    EQU 16
EVREC_ORDINAL_OFF   EQU 24
EVREC_SEQ_CAP_OFF   EQU 32
EVREC_RESERVED_OFF  EQU 36
EVREC_ARG0_OFF      EQU 40
EVREC_ARG1_OFF      EQU 48
EVREC_COMMIT_OFF    EQU 56

EVREC_MAGIC         EQU 56455852h
EVREC_VERSION       EQU 1
EVREC_BYTES         EQU 64
EVREC_COMMIT        EQU 0A11CE55A11CE55h
SEQ_CAP_REQUIRED    EQU 512
CLAIM_ID_MIN        EQU 1
CLAIM_ID_MAX        EQU 17

; EvidenceSummary512 layout (72 bytes)
EVSUM_RUN_ID        EQU 0   ; qword
EVSUM_RESERVED      EQU 8   ; qword raw WriteIndex
EVSUM_CAPACITY      EQU 16  ; qword
EVSUM_COMMITTED     EQU 24  ; qword accepted records in scanned reserved range
EVSUM_DROPPED       EQU 32  ; qword
EVSUM_CLAIM_MASK    EQU 40  ; qword bit (ClaimId-1)
EVSUM_INVALID       EQU 48  ; qword committed but malformed/wrong run/wrong seq/claim
EVSUM_INCOMPLETE    EQU 56  ; qword reserved slot not yet Commit==EVREC_COMMIT
EVSUM_SEQ_CAP       EQU 64  ; dword
EVSUM_FLAGS         EQU 68  ; dword
EVSUM_BYTES         EQU 72

; Summary flags
EVSUMF_SEQCAP_OK          EQU 00000001h
EVSUMF_RESERVED_COMPLETE  EQU 00000002h
EVSUMF_RECORDS_VALID      EQU 00000004h
EVSUMF_NO_DROPS           EQU 00000008h
EVSUMF_CLOSED_SNAPSHOT    EQU 00000010h

PUBLIC EvidenceSummarize512
PUBLIC EvidenceFindClaim512
PUBLIC EvidenceCopyCommitted512

.code

; ---------------------------------------------------------------------------
; EvidenceSummarize512
;   rcx = EvidenceState*
;   rdx = EvidenceSummary512*
;
; Returns:
;   eax = 1 when arguments/state are structurally accepted and SeqCap==512.
;   eax = 0 on hard reject.
;
; Notes:
;   Scans min(WriteIndex, Capacity). A reserved slot without EVREC_COMMIT
;   increments INCOMPLETE. A committed slot with malformed metadata increments
;   INVALID. Only fully valid committed records contribute to COMMITTED/MASK.
;
;   CLOSED_SNAPSHOT is set only when:
;     SeqCap==512
;     + every reserved slot scanned is committed
;     + every committed slot is valid
;     + Dropped==0
;
;   This does NOT invent a runtime "did not fire" observation for absent claims.
; ---------------------------------------------------------------------------
EvidenceSummarize512 PROC FRAME
    test rcx, rcx
    jz   es_fail
    test rdx, rdx
    jz   es_fail

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
    .endprolog

    mov  rsi, rcx                    ; state
    mov  rdi, rdx                    ; summary

    ; Zero 72-byte summary.
    xor  rax, rax
    mov  qword ptr [rdi+0],  rax
    mov  qword ptr [rdi+8],  rax
    mov  qword ptr [rdi+16], rax
    mov  qword ptr [rdi+24], rax
    mov  qword ptr [rdi+32], rax
    mov  qword ptr [rdi+40], rax
    mov  qword ptr [rdi+48], rax
    mov  qword ptr [rdi+56], rax
    mov  qword ptr [rdi+64], rax

    mov  rax, qword ptr [rsi+EVS_RUN_ID]
    mov  qword ptr [rdi+EVSUM_RUN_ID], rax

    mov  rax, qword ptr [rsi+EVS_WRITE_INDEX]
    mov  qword ptr [rdi+EVSUM_RESERVED], rax

    mov  rax, qword ptr [rsi+EVS_CAPACITY]
    mov  qword ptr [rdi+EVSUM_CAPACITY], rax

    mov  rax, qword ptr [rsi+EVS_DROPPED]
    mov  qword ptr [rdi+EVSUM_DROPPED], rax

    mov  eax, dword ptr [rsi+EVS_SEQ_CAP]
    mov  dword ptr [rdi+EVSUM_SEQ_CAP], eax
    cmp  eax, SEQ_CAP_REQUIRED
    jne  es_reject_after_push

    mov  r14, qword ptr [rsi+EVS_BUFFER]
    test r14, r14
    jz   es_reject_after_push

    mov  rax, qword ptr [rsi+EVS_CAPACITY]
    test rax, rax
    jz   es_reject_after_push

    mov  r13, qword ptr [rsi+EVS_WRITE_INDEX]
    mov  rax, qword ptr [rsi+EVS_CAPACITY]
    cmp  r13, rax
    jbe  es_scan_count_ready
    mov  r13, rax
es_scan_count_ready:

    xor  ebx, ebx                    ; scan index
    xor  r12d, r12d                  ; committed valid count
    xor  r15d, r15d                  ; claim mask

es_loop:
    cmp  rbx, r13
    jae  es_done_scan

    mov  r10, rbx
    shl  r10, 6                      ; *64
    add  r10, r14                    ; record*

    mov  r11, EVREC_COMMIT
    cmp  qword ptr [r10+EVREC_COMMIT_OFF], r11
    jne  es_incomplete

    ; Validate immutable metadata AFTER observing commit.
    cmp  dword ptr [r10+EVREC_MAGIC_OFF], EVREC_MAGIC
    jne  es_invalid
    cmp  word ptr [r10+EVREC_VERSION_OFF], EVREC_VERSION
    jne  es_invalid
    cmp  word ptr [r10+EVREC_RECBYTES_OFF], EVREC_BYTES
    jne  es_invalid

    mov  rax, qword ptr [rsi+EVS_RUN_ID]
    cmp  qword ptr [r10+EVREC_RUN_ID_OFF], rax
    jne  es_invalid

    cmp  dword ptr [r10+EVREC_SEQ_CAP_OFF], SEQ_CAP_REQUIRED
    jne  es_invalid

    cmp  qword ptr [r10+EVREC_ORDINAL_OFF], rbx
    jne  es_invalid

    mov  eax, dword ptr [r10+EVREC_CLAIM_ID_OFF]
    cmp  eax, CLAIM_ID_MIN
    jb   es_invalid
    cmp  eax, CLAIM_ID_MAX
    ja   es_invalid

    inc  r12

    ; Exact claim contributes only its own bit.
    mov  ecx, eax
    dec  ecx
    mov  r11, 1
    shl  r11, cl
    or   r15, r11
    jmp  es_next

es_incomplete:
    inc  qword ptr [rdi+EVSUM_INCOMPLETE]
    jmp  es_next

es_invalid:
    inc  qword ptr [rdi+EVSUM_INVALID]

es_next:
    inc  rbx
    jmp  es_loop

es_done_scan:
    mov  qword ptr [rdi+EVSUM_COMMITTED], r12
    mov  qword ptr [rdi+EVSUM_CLAIM_MASK], r15

    mov  eax, EVSUMF_SEQCAP_OK

    cmp  qword ptr [rdi+EVSUM_INCOMPLETE], 0
    jne  es_flags_invalid_check
    or   eax, EVSUMF_RESERVED_COMPLETE

es_flags_invalid_check:
    cmp  qword ptr [rdi+EVSUM_INVALID], 0
    jne  es_flags_drop_check
    or   eax, EVSUMF_RECORDS_VALID

es_flags_drop_check:
    cmp  qword ptr [rdi+EVSUM_DROPPED], 0
    jne  es_flags_close_check
    or   eax, EVSUMF_NO_DROPS

es_flags_close_check:
    mov  ecx, EVSUMF_SEQCAP_OK or EVSUMF_RESERVED_COMPLETE or EVSUMF_RECORDS_VALID or EVSUMF_NO_DROPS
    mov  edx, eax
    and  edx, ecx
    cmp  edx, ecx
    jne  es_store_flags
    or   eax, EVSUMF_CLOSED_SNAPSHOT

es_store_flags:
    mov  dword ptr [rdi+EVSUM_FLAGS], eax
    mov  eax, 1
    jmp  es_epilogue

es_reject_after_push:
    xor  eax, eax

es_epilogue:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

es_fail:
    xor  eax, eax
    ret
EvidenceSummarize512 ENDP


; ---------------------------------------------------------------------------
; EvidenceFindClaim512
;   rcx = EvidenceState*
;   edx = exact ClaimId (1..17)
;
; Returns:
;   rax = pointer to the latest VALID COMMITTED record for exactly that ClaimId,
;         or 0 if none is visible.
;
; No cross-claim fallback exists.
; ---------------------------------------------------------------------------
EvidenceFindClaim512 PROC FRAME
    test rcx, rcx
    jz   efc_fail
    cmp  edx, CLAIM_ID_MIN
    jb   efc_fail
    cmp  edx, CLAIM_ID_MAX
    ja   efc_fail
    cmp  dword ptr [rcx+EVS_SEQ_CAP], SEQ_CAP_REQUIRED
    jne  efc_fail

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
    .endprolog

    mov  rsi, rcx                    ; state
    mov  edi, edx                    ; requested claim

    mov  r12, qword ptr [rsi+EVS_BUFFER]
    test r12, r12
    jz   efc_fail_after_push

    mov  r10, qword ptr [rsi+EVS_CAPACITY]
    test r10, r10
    jz   efc_fail_after_push

    mov  r13, qword ptr [rsi+EVS_WRITE_INDEX]
    mov  r10, qword ptr [rsi+EVS_CAPACITY]
    cmp  r13, r10
    jbe  efc_count_ready
    mov  r13, r10
efc_count_ready:

    xor  ebx, ebx
    xor  eax, eax                    ; latest match pointer

efc_loop:
    cmp  rbx, r13
    jae  efc_done

    mov  r10, rbx
    shl  r10, 6
    add  r10, r12

    mov  r11, EVREC_COMMIT
    cmp  qword ptr [r10+EVREC_COMMIT_OFF], r11
    jne  efc_next
    cmp  dword ptr [r10+EVREC_MAGIC_OFF], EVREC_MAGIC
    jne  efc_next
    cmp  word ptr [r10+EVREC_VERSION_OFF], EVREC_VERSION
    jne  efc_next
    cmp  word ptr [r10+EVREC_RECBYTES_OFF], EVREC_BYTES
    jne  efc_next

    mov  r11, qword ptr [rsi+EVS_RUN_ID]
    cmp  qword ptr [r10+EVREC_RUN_ID_OFF], r11
    jne  efc_next
    cmp  dword ptr [r10+EVREC_SEQ_CAP_OFF], SEQ_CAP_REQUIRED
    jne  efc_next
    cmp  qword ptr [r10+EVREC_ORDINAL_OFF], rbx
    jne  efc_next
    cmp  dword ptr [r10+EVREC_CLAIM_ID_OFF], edi
    jne  efc_next

    mov  rax, r10                    ; exact claim only; latest wins

efc_next:
    inc  rbx
    jmp  efc_loop

efc_done:
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

efc_fail_after_push:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

efc_fail:
    xor  eax, eax
    ret
EvidenceFindClaim512 ENDP


; ---------------------------------------------------------------------------
; EvidenceCopyCommitted512
;   rcx = EvidenceState*
;   rdx = destination EvidenceRecord[]
;   r8  = destination capacity in records
;
; Returns:
;   rax = number of VALID COMMITTED records copied densely.
;
; Copies only records that:
;   Commit==EVREC_COMMIT, magic/version/size valid, RunId matches state,
;   SeqCap==512, ClaimId in 1..17.
;
; The copy is observational. Missing claims are not materialized.
; ---------------------------------------------------------------------------
EvidenceCopyCommitted512 PROC FRAME
    test rcx, rcx
    jz   ecc_fail
    test rdx, rdx
    jz   ecc_fail
    test r8, r8
    jz   ecc_fail
    cmp  dword ptr [rcx+EVS_SEQ_CAP], SEQ_CAP_REQUIRED
    jne  ecc_fail

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
    .endprolog

    mov  rsi, rcx                    ; state
    mov  rdi, rdx                    ; destination base
    mov  r15, r8                     ; destination record capacity

    mov  r12, qword ptr [rsi+EVS_BUFFER]
    test r12, r12
    jz   ecc_zero_after_push

    mov  r10, qword ptr [rsi+EVS_CAPACITY]
    test r10, r10
    jz   ecc_zero_after_push

    mov  r13, qword ptr [rsi+EVS_WRITE_INDEX]
    mov  r10, qword ptr [rsi+EVS_CAPACITY]
    cmp  r13, r10
    jbe  ecc_count_ready
    mov  r13, r10
ecc_count_ready:

    xor  ebx, ebx                    ; source slot index
    xor  r14d, r14d                  ; copied record count

ecc_loop:
    cmp  rbx, r13
    jae  ecc_done
    cmp  r14, r15
    jae  ecc_done

    mov  r10, rbx
    shl  r10, 6
    add  r10, r12                    ; source record*

    mov  r11, EVREC_COMMIT
    cmp  qword ptr [r10+EVREC_COMMIT_OFF], r11
    jne  ecc_next
    cmp  dword ptr [r10+EVREC_MAGIC_OFF], EVREC_MAGIC
    jne  ecc_next
    cmp  word ptr [r10+EVREC_VERSION_OFF], EVREC_VERSION
    jne  ecc_next
    cmp  word ptr [r10+EVREC_RECBYTES_OFF], EVREC_BYTES
    jne  ecc_next

    mov  r11, qword ptr [rsi+EVS_RUN_ID]
    cmp  qword ptr [r10+EVREC_RUN_ID_OFF], r11
    jne  ecc_next
    cmp  dword ptr [r10+EVREC_SEQ_CAP_OFF], SEQ_CAP_REQUIRED
    jne  ecc_next
    cmp  qword ptr [r10+EVREC_ORDINAL_OFF], rbx
    jne  ecc_next

    mov  eax, dword ptr [r10+EVREC_CLAIM_ID_OFF]
    cmp  eax, CLAIM_ID_MIN
    jb   ecc_next
    cmp  eax, CLAIM_ID_MAX
    ja   ecc_next

    ; destination = base + copied*64
    mov  r11, r14
    shl  r11, 6
    add  r11, rdi

    ; Copy exactly 64 bytes as 8 qwords. Commit was observed first and is
    ; immutable after publication under the landed protocol.
    mov  rax, qword ptr [r10+0]
    mov  qword ptr [r11+0], rax
    mov  rax, qword ptr [r10+8]
    mov  qword ptr [r11+8], rax
    mov  rax, qword ptr [r10+16]
    mov  qword ptr [r11+16], rax
    mov  rax, qword ptr [r10+24]
    mov  qword ptr [r11+24], rax
    mov  rax, qword ptr [r10+32]
    mov  qword ptr [r11+32], rax
    mov  rax, qword ptr [r10+40]
    mov  qword ptr [r11+40], rax
    mov  rax, qword ptr [r10+48]
    mov  qword ptr [r11+48], rax
    mov  rax, qword ptr [r10+56]
    mov  qword ptr [r11+56], rax

    inc  r14

ecc_next:
    inc  rbx
    jmp  ecc_loop

ecc_done:
    mov  rax, r14
    jmp  ecc_epilogue

ecc_zero_after_push:
    xor  eax, eax

ecc_epilogue:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

ecc_fail:
    xor  eax, eax
    ret
EvidenceCopyCommitted512 ENDP

END
