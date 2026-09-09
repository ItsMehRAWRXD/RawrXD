; RuntimeEvidence512_Core.asm — claim-isolated evidence; zero CRT/externals.
; Caller-owned memory only. Windows x64 ABI. ml64 /c
OPTION CASEMAP:NONE

EVS_BUFFER          EQU 0
EVS_CAPACITY        EQU 8
EVS_WRITE_INDEX     EQU 16
EVS_DROPPED         EQU 24
EVS_RUN_ID          EQU 32
EVS_SEQ_CAP         EQU 40
EVS_FLAGS           EQU 44

EVREC_MAGIC         EQU 56455852h
EVREC_VERSION       EQU 1
EVREC_BYTES         EQU 64
EVREC_COMMIT        EQU 0A11CE55A11CE55h
SEQ_CAP_REQUIRED    EQU 512

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

PUBLIC EvidenceInit512
PUBLIC EvidenceResetRun512
PUBLIC EvidenceGetCommittedCount
PUBLIC EvidenceGetDroppedCount
PUBLIC EvidenceEmitCore

.code

EvidenceInit512 PROC
    test rcx, rcx
    jz   ei_fail
    test rdx, rdx
    jz   ei_fail
    test r8, r8
    jz   ei_fail
    mov  eax, dword ptr [rsp+40]
    cmp  eax, SEQ_CAP_REQUIRED
    jne  ei_fail
    mov  qword ptr [rcx+EVS_BUFFER], rdx
    mov  qword ptr [rcx+EVS_CAPACITY], r8
    mov  qword ptr [rcx+EVS_WRITE_INDEX], 0
    mov  qword ptr [rcx+EVS_DROPPED], 0
    mov  qword ptr [rcx+EVS_RUN_ID], r9
    mov  dword ptr [rcx+EVS_SEQ_CAP], eax
    mov  dword ptr [rcx+EVS_FLAGS], 0
    mov  eax, 1
    ret
ei_fail:
    xor  eax, eax
    ret
EvidenceInit512 ENDP

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
    mov  qword ptr [rcx+EVS_DROPPED], 0
    mov  qword ptr [rcx+EVS_RUN_ID], rdx
    mov  dword ptr [rcx+EVS_SEQ_CAP], r8d
    mov  dword ptr [rcx+EVS_FLAGS], 0
    mov  eax, 1
    ret
er_fail:
    xor  eax, eax
    ret
EvidenceResetRun512 ENDP

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

; rcx=state rdx=Arg0 r8=Arg1 r9d=Status r10d=ClaimId
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
    mov  rax, 1
    lock xadd qword ptr [rcx+EVS_WRITE_INDEX], rax
    cmp  rax, qword ptr [rcx+EVS_CAPACITY]
    jb   eec_have_slot
    lock inc qword ptr [rcx+EVS_DROPPED]
    xor  eax, eax
    ret
eec_have_slot:
    shl  rax, 6
    add  r11, rax
    shr  rax, 6
    mov  qword ptr [r11+56], 0
    mov  dword ptr [r11+0], EVREC_MAGIC
    mov  word  ptr [r11+4], EVREC_VERSION
    mov  word  ptr [r11+6], EVREC_BYTES
    mov  dword ptr [r11+8], r10d
    mov  dword ptr [r11+12], r9d
    mov  r10, qword ptr [rcx+EVS_RUN_ID]
    mov  qword ptr [r11+16], r10
    mov  qword ptr [r11+24], rax
    mov  eax, dword ptr [rcx+EVS_SEQ_CAP]
    mov  dword ptr [r11+32], eax
    mov  dword ptr [r11+36], 0
    mov  qword ptr [r11+40], rdx
    mov  qword ptr [r11+48], r8
    mov  rax, EVREC_COMMIT
    xchg qword ptr [r11+56], rax
    mov  eax, 1
    ret
eec_fail:
    xor  eax, eax
    ret
EvidenceEmitCore ENDP

END
