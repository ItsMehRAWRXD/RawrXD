; AuthorityContractTest.asm
; Link-time callable self-test. Returns a failure bitmask in RAX.
; This test intentionally owns an isolated process-global state and should not
; be invoked in production after real authority has been established.
;
; bit 0: root seal failed
; bit 1: decode mint failed
; bit 2: scheduler mint failed
; bit 3: promotion mint failed
; bit 4: revoke failed to clear decode/promotion
; bit 5: revoked decode was re-minted in same generation
; bit 6: generation advance failed to clear sticky state
; bit 7: decode mint after generation advance failed

option casemap:none
include AuthorityState.inc
EXTERN gAuthorityState:QWORD
EXTERN gAuthorityRoot:QWORD

TEST_ROOT EQU 05A17D0C0FFEE1234h

.code

AuthorityContractTest PROC
    sub  rsp, 28h
    xor  r9d, r9d

    mov  rcx, TEST_ROOT
    call AuthorityRootSeal
    test rax, rax
    jnz  act_1
    or   r9, 1
act_1:
    mov  rcx, TEST_ROOT
    call AuthorityMintDecode
    test rax, AUTH_LIVE_DECODE
    jnz  act_2
    or   r9, 2
act_2:
    mov  rcx, TEST_ROOT
    call AuthorityMintScheduler
    test rax, AUTH_LIVE_SCHEDULER
    jnz  act_3
    or   r9, 4
act_3:
    mov  rcx, TEST_ROOT
    call AuthorityMintPromotion
    test rax, AUTH_LIVE_PROMOTION
    jnz  act_4
    or   r9, 8
act_4:
    mov  rcx, AUTH_LIVE_DECODE
    call AuthorityRevoke
    test rax, (AUTH_LIVE_DECODE OR AUTH_LIVE_PROMOTION)
    jz   act_5
    or   r9, 10h
act_5:
    mov  rcx, TEST_ROOT
    call AuthorityMintDecode
    cmp  rax, -1
    je   act_6
    or   r9, 20h
act_6:
    mov  rcx, TEST_ROOT
    call AuthorityAdvanceGen
    cmp  rax, -1
    jne  act_7
    or   r9, 40h
act_7:
    test rax, (AUTH_LIVE_MASK OR AUTH_REVOKED_MASK)
    jz   act_8
    or   r9, 40h
act_8:
    mov  rcx, TEST_ROOT
    call AuthorityMintDecode
    test rax, AUTH_LIVE_DECODE
    jnz  act_done
    or   r9, 80h
act_done:
    mov  rax, r9
    add  rsp, 28h
    ret
AuthorityContractTest ENDP

PUBLIC AuthorityContractTest

END
