; AuthorityObserveRevoke.asm
; Observer/revoker path. This file is mechanically incapable of manufacturing
; DECODE, SCHEDULER, or PROMOTION live authority: it contains no instruction
; that sets AUTH_LIVE_* bits.
;
; Pure x64 MASM. No CRT / WinAPI / external runtime.

option casemap:none
include AuthorityState.inc
EXTERN gAuthorityState:QWORD
EXTERN gAuthorityRoot:QWORD

.code

; RAX = atomic snapshot.
AuthorityObserve PROC
    mov  rax, qword ptr [gAuthorityState]
    ret
AuthorityObserve ENDP

; RCX low 3 bits = authorities to revoke.
; Revocation is sticky for the current generation.
; Revoking decode or scheduler also clears promotion because promotion depends
; on both authorities. No LIVE bit can transition 0 -> 1 in this routine.
; RAX = resulting state snapshot.
AuthorityRevoke PROC
    mov  r8, rcx
    and  r8, AUTH_LIVE_MASK

ar_retry:
    mov  rax, qword ptr [gAuthorityState]
    mov  rdx, rax

    test r8, AUTH_LIVE_DECODE
    jz   ar_no_decode
    and  rdx, -6                 ; clear LIVE_DECODE(1) + LIVE_PROMOTION(4)
    or   rdx, AUTH_REVOKED_DECODE
ar_no_decode:

    test r8, AUTH_LIVE_SCHEDULER
    jz   ar_no_sched
    and  rdx, -7                 ; clear LIVE_SCHEDULER(2) + LIVE_PROMOTION(4)
    or   rdx, AUTH_REVOKED_SCHEDULER
ar_no_sched:

    test r8, AUTH_LIVE_PROMOTION
    jz   ar_no_promo
    and  rdx, -5                 ; clear LIVE_PROMOTION(4)
    or   rdx, AUTH_REVOKED_PROMOTION
ar_no_promo:

    cmp  rdx, rax
    je   ar_done

    lock cmpxchg qword ptr [gAuthorityState], rdx
    jne  ar_retry
    mov  rax, rdx
ar_done:
    ret
AuthorityRevoke ENDP

PUBLIC AuthorityObserve
PUBLIC AuthorityRevoke

END
