; RuntimeEvidence512_IDECollect.asm
; x64 MASM / ml64.exe
; Read-only collector for the combined landed + IDE claim namespace.
; Accepts ClaimId 1..96. Uses a 128-bit claim-presence bitmap.
;
; Does not mutate EvidenceState/EvidenceRecord.
; Does not manufacture missing claim records.
; Does not permit Claim X to satisfy Claim Y.
;
; Exports:
;   EvidenceSummarizeIDE512
;   EvidenceFindIDEClaim512
;   EvidenceCopyIDECommitted512
;
; EvidenceIDESummary512 (88 bytes):
;   +00 qword RunId
;   +08 qword ReservedRaw
;   +16 qword Capacity
;   +24 qword CommittedValid
;   +32 qword Dropped
;   +40 qword ClaimMaskLo      ; ClaimId 1..64 => bits 0..63
;   +48 qword ClaimMaskHi      ; ClaimId 65..128 => bits 0..63
;   +56 qword Invalid
;   +64 qword Incomplete
;   +72 dword SeqCap
;   +76 dword Flags
;   +80 dword MaxClaimId       ; 96
;   +84 dword Reserved
;
; Flags:
;   0x01 SEQCAP_OK
;   0x02 RESERVED_COMPLETE
;   0x04 RECORDS_VALID
;   0x08 NO_DROPS
;   0x10 CLOSED_SNAPSHOT
;
; CLOSED_SNAPSHOT is collector integrity only. It is NOT proof that generation
; or the IDE exited. Call only after the real run/join point.

OPTION CASEMAP:NONE
INCLUDE RuntimeEvidence512_IDEClaims.inc

EVS_BUFFER          EQU 0
EVS_CAPACITY        EQU 8
EVS_WRITE_INDEX     EQU 16
EVS_DROPPED         EQU 24
EVS_RUN_ID          EQU 32
EVS_SEQ_CAP         EQU 40

EVREC_MAGIC_OFF     EQU 0
EVREC_VERSION_OFF   EQU 4
EVREC_RECBYTES_OFF  EQU 6
EVREC_CLAIM_ID_OFF  EQU 8
EVREC_STATUS_OFF    EQU 12
EVREC_RUN_ID_OFF    EQU 16
EVREC_ORDINAL_OFF   EQU 24
EVREC_SEQ_CAP_OFF   EQU 32
EVREC_ARG0_OFF      EQU 40
EVREC_ARG1_OFF      EQU 48
EVREC_COMMIT_OFF    EQU 56

EVIS_RUN_ID         EQU 0
EVIS_RESERVED       EQU 8
EVIS_CAPACITY       EQU 16
EVIS_COMMITTED      EQU 24
EVIS_DROPPED        EQU 32
EVIS_MASK_LO        EQU 40
EVIS_MASK_HI        EQU 48
EVIS_INVALID        EQU 56
EVIS_INCOMPLETE     EQU 64
EVIS_SEQ_CAP        EQU 72
EVIS_FLAGS          EQU 76
EVIS_MAX_CLAIM      EQU 80
EVIS_RESERVED2      EQU 84
EVIS_BYTES          EQU 88

EVISF_SEQCAP_OK          EQU 00000001h
EVISF_RESERVED_COMPLETE  EQU 00000002h
EVISF_RECORDS_VALID      EQU 00000004h
EVISF_NO_DROPS           EQU 00000008h
EVISF_CLOSED_SNAPSHOT    EQU 00000010h

PUBLIC EvidenceSummarizeIDE512
PUBLIC EvidenceFindIDEClaim512
PUBLIC EvidenceCopyIDECommitted512

.code

; ---------------------------------------------------------------------------
; EvidenceSummarizeIDE512
;   rcx = EvidenceState*
;   rdx = EvidenceIDESummary512*
; Returns eax=1 structurally accepted, eax=0 hard reject.
; ---------------------------------------------------------------------------
EvidenceSummarizeIDE512 PROC FRAME
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

    test rcx, rcx
    jz   esi_fail
    test rdx, rdx
    jz   esi_fail

    mov  rsi, rcx
    mov  rdi, rdx

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
    mov  qword ptr [rdi+72], rax
    mov  qword ptr [rdi+80], rax

    mov  rax, qword ptr [rsi+EVS_RUN_ID]
    mov  qword ptr [rdi+EVIS_RUN_ID], rax
    mov  rax, qword ptr [rsi+EVS_WRITE_INDEX]
    mov  qword ptr [rdi+EVIS_RESERVED], rax
    mov  rax, qword ptr [rsi+EVS_CAPACITY]
    mov  qword ptr [rdi+EVIS_CAPACITY], rax
    mov  rax, qword ptr [rsi+EVS_DROPPED]
    mov  qword ptr [rdi+EVIS_DROPPED], rax
    mov  dword ptr [rdi+EVIS_MAX_CLAIM], IDE_CLAIM_MAX

    mov  eax, dword ptr [rsi+EVS_SEQ_CAP]
    mov  dword ptr [rdi+EVIS_SEQ_CAP], eax
    cmp  eax, SEQ_CAP_REQUIRED
    jne  esi_fail

    mov  r14, qword ptr [rsi+EVS_BUFFER]
    test r14, r14
    jz   esi_fail
    mov  rax, qword ptr [rsi+EVS_CAPACITY]
    test rax, rax
    jz   esi_fail

    mov  r13, qword ptr [rsi+EVS_WRITE_INDEX]
    cmp  r13, rax
    jbe  esi_count_ready
    mov  r13, rax
esi_count_ready:

    xor  ebx, ebx
    xor  r12d, r12d
    xor  r15d, r15d              ; mask lo
    xor  edx, edx                 ; mask hi kept in rdx until stored

esi_loop:
    cmp  rbx, r13
    jae  esi_done_scan

    mov  r10, rbx
    shl  r10, 6
    add  r10, r14

    mov  r11, EVREC_COMMIT
    cmp  qword ptr [r10+EVREC_COMMIT_OFF], r11
    jne  esi_incomplete

    cmp  dword ptr [r10+EVREC_MAGIC_OFF], EVREC_MAGIC
    jne  esi_invalid
    cmp  word ptr [r10+EVREC_VERSION_OFF], EVREC_VERSION
    jne  esi_invalid
    cmp  word ptr [r10+EVREC_RECBYTES_OFF], EVREC_BYTES
    jne  esi_invalid

    mov  rax, qword ptr [rsi+EVS_RUN_ID]
    cmp  qword ptr [r10+EVREC_RUN_ID_OFF], rax
    jne  esi_invalid
    cmp  dword ptr [r10+EVREC_SEQ_CAP_OFF], SEQ_CAP_REQUIRED
    jne  esi_invalid
    cmp  qword ptr [r10+EVREC_ORDINAL_OFF], rbx
    jne  esi_invalid

    mov  eax, dword ptr [r10+EVREC_CLAIM_ID_OFF]
    cmp  eax, 1
    jb   esi_invalid
    cmp  eax, IDE_CLAIM_MAX
    ja   esi_invalid

    inc  r12

    cmp  eax, 64
    ja   esi_mask_hi

    mov  ecx, eax
    dec  ecx
    mov  r11, 1
    shl  r11, cl
    or   r15, r11
    jmp  esi_next

esi_mask_hi:
    sub  eax, 65
    mov  ecx, eax
    mov  r11, 1
    shl  r11, cl
    or   rdx, r11
    jmp  esi_next

esi_incomplete:
    inc  qword ptr [rdi+EVIS_INCOMPLETE]
    jmp  esi_next

esi_invalid:
    inc  qword ptr [rdi+EVIS_INVALID]

esi_next:
    inc  rbx
    jmp  esi_loop

esi_done_scan:
    mov  qword ptr [rdi+EVIS_COMMITTED], r12
    mov  qword ptr [rdi+EVIS_MASK_LO], r15
    mov  qword ptr [rdi+EVIS_MASK_HI], rdx

    mov  eax, EVISF_SEQCAP_OK
    cmp  qword ptr [rdi+EVIS_INCOMPLETE], 0
    jne  esi_flag_valid
    or   eax, EVISF_RESERVED_COMPLETE
esi_flag_valid:
    cmp  qword ptr [rdi+EVIS_INVALID], 0
    jne  esi_flag_drop
    or   eax, EVISF_RECORDS_VALID
esi_flag_drop:
    cmp  qword ptr [rdi+EVIS_DROPPED], 0
    jne  esi_flag_close
    or   eax, EVISF_NO_DROPS
esi_flag_close:
    mov  ecx, EVISF_SEQCAP_OK or EVISF_RESERVED_COMPLETE or EVISF_RECORDS_VALID or EVISF_NO_DROPS
    mov  r11d, eax
    and  r11d, ecx
    cmp  r11d, ecx
    jne  esi_store
    or   eax, EVISF_CLOSED_SNAPSHOT
esi_store:
    mov  dword ptr [rdi+EVIS_FLAGS], eax
    mov  eax, 1
    jmp  esi_epilogue

esi_fail:
    xor  eax, eax

esi_epilogue:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret
EvidenceSummarizeIDE512 ENDP

; ---------------------------------------------------------------------------
; EvidenceFindIDEClaim512
;   rcx = EvidenceState*
;   edx = exact ClaimId (1..96)
; Returns rax = latest valid committed record pointer, or 0.
; ---------------------------------------------------------------------------
EvidenceFindIDEClaim512 PROC FRAME
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

    test rcx, rcx
    jz   efic_fail
    cmp  edx, 1
    jb   efic_fail
    cmp  edx, IDE_CLAIM_MAX
    ja   efic_fail
    cmp  dword ptr [rcx+EVS_SEQ_CAP], SEQ_CAP_REQUIRED
    jne  efic_fail

    mov  rsi, rcx
    mov  edi, edx
    mov  r12, qword ptr [rsi+EVS_BUFFER]
    test r12, r12
    jz   efic_fail

    mov  r10, qword ptr [rsi+EVS_CAPACITY]
    test r10, r10
    jz   efic_fail
    mov  r13, qword ptr [rsi+EVS_WRITE_INDEX]
    cmp  r13, r10
    jbe  efic_count
    mov  r13, r10
efic_count:
    xor  ebx, ebx
    xor  eax, eax

efic_loop:
    cmp  rbx, r13
    jae  efic_epilogue

    mov  r10, rbx
    shl  r10, 6
    add  r10, r12

    mov  r11, EVREC_COMMIT
    cmp  qword ptr [r10+EVREC_COMMIT_OFF], r11
    jne  efic_next
    cmp  dword ptr [r10+EVREC_MAGIC_OFF], EVREC_MAGIC
    jne  efic_next
    cmp  word ptr [r10+EVREC_VERSION_OFF], EVREC_VERSION
    jne  efic_next
    cmp  word ptr [r10+EVREC_RECBYTES_OFF], EVREC_BYTES
    jne  efic_next

    mov  r11, qword ptr [rsi+EVS_RUN_ID]
    cmp  qword ptr [r10+EVREC_RUN_ID_OFF], r11
    jne  efic_next
    cmp  dword ptr [r10+EVREC_SEQ_CAP_OFF], SEQ_CAP_REQUIRED
    jne  efic_next
    cmp  qword ptr [r10+EVREC_ORDINAL_OFF], rbx
    jne  efic_next
    cmp  dword ptr [r10+EVREC_CLAIM_ID_OFF], edi
    jne  efic_next

    mov  rax, r10
efic_next:
    inc  rbx
    jmp  efic_loop

efic_fail:
    xor  eax, eax
efic_epilogue:
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret
EvidenceFindIDEClaim512 ENDP

; ---------------------------------------------------------------------------
; EvidenceCopyIDECommitted512
;   rcx = EvidenceState*
;   rdx = destination EvidenceRecord[]
;   r8  = destination capacity records
; Returns rax = copied valid committed record count.
; ---------------------------------------------------------------------------
EvidenceCopyIDECommitted512 PROC FRAME
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

    test rcx, rcx
    jz   ecic_fail
    test rdx, rdx
    jz   ecic_fail
    test r8, r8
    jz   ecic_fail
    cmp  dword ptr [rcx+EVS_SEQ_CAP], SEQ_CAP_REQUIRED
    jne  ecic_fail

    mov  rsi, rcx
    mov  rdi, rdx
    mov  r15, r8

    mov  r12, qword ptr [rsi+EVS_BUFFER]
    test r12, r12
    jz   ecic_fail
    mov  r10, qword ptr [rsi+EVS_CAPACITY]
    test r10, r10
    jz   ecic_fail

    mov  r13, qword ptr [rsi+EVS_WRITE_INDEX]
    cmp  r13, r10
    jbe  ecic_count
    mov  r13, r10
ecic_count:
    xor  ebx, ebx
    xor  r14d, r14d

ecic_loop:
    cmp  rbx, r13
    jae  ecic_done
    cmp  r14, r15
    jae  ecic_done

    mov  r10, rbx
    shl  r10, 6
    add  r10, r12

    mov  r11, EVREC_COMMIT
    cmp  qword ptr [r10+EVREC_COMMIT_OFF], r11
    jne  ecic_next
    cmp  dword ptr [r10+EVREC_MAGIC_OFF], EVREC_MAGIC
    jne  ecic_next
    cmp  word ptr [r10+EVREC_VERSION_OFF], EVREC_VERSION
    jne  ecic_next
    cmp  word ptr [r10+EVREC_RECBYTES_OFF], EVREC_BYTES
    jne  ecic_next

    mov  r11, qword ptr [rsi+EVS_RUN_ID]
    cmp  qword ptr [r10+EVREC_RUN_ID_OFF], r11
    jne  ecic_next
    cmp  dword ptr [r10+EVREC_SEQ_CAP_OFF], SEQ_CAP_REQUIRED
    jne  ecic_next
    cmp  qword ptr [r10+EVREC_ORDINAL_OFF], rbx
    jne  ecic_next

    mov  eax, dword ptr [r10+EVREC_CLAIM_ID_OFF]
    cmp  eax, 1
    jb   ecic_next
    cmp  eax, IDE_CLAIM_MAX
    ja   ecic_next

    mov  r11, r14
    shl  r11, 6
    add  r11, rdi

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
ecic_next:
    inc  rbx
    jmp  ecic_loop

ecic_done:
    mov  rax, r14
    jmp  ecic_epilogue

ecic_fail:
    xor  eax, eax

ecic_epilogue:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret
EvidenceCopyIDECommitted512 ENDP

END
