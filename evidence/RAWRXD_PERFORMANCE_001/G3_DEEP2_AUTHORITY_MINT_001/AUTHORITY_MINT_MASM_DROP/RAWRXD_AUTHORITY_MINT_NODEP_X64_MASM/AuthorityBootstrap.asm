; AuthorityBootstrap.asm
; Owns root bootstrap + generation rollover only.
; It never sets DECODE/SCHEDULER/PROMOTION live authority bits.

option casemap:none
include AuthorityState.inc

.data
ALIGN 8
gAuthorityState QWORD 0000000000000000h
gAuthorityRoot  QWORD 0000000000000000h

PUBLIC gAuthorityState
PUBLIC gAuthorityRoot

.code

; RCX = non-zero root capability cookie.
; RAX = 1 success/idempotent, 0 reject.
AuthorityRootSeal PROC
    test rcx, rcx
    jz   ars_fail

    xor  eax, eax
    lock cmpxchg qword ptr [gAuthorityRoot], rcx
    jz   ars_ok                  ; installed into zero slot

    cmp  rax, rcx                ; idempotent same-root seal
    jne  ars_fail
ars_ok:
    mov  eax, 1
    ret
ars_fail:
    xor  eax, eax
    ret
AuthorityRootSeal ENDP

; RCX = current root capability cookie.
; RAX = new state snapshot, or -1 on reject.
; Generation rollover is the only operation that clears sticky revocation.
; It also clears every LIVE bit; a new generation must mint authority again.
AuthorityAdvanceGen PROC
    mov  r10, qword ptr [gAuthorityRoot]
    test r10, r10
    jz   aag_fail
    cmp  rcx, r10
    jne  aag_fail

aag_retry:
    mov  rax, qword ptr [gAuthorityState]
    mov  rdx, rax
    shr  rdx, AUTH_GENERATION_SHIFT
    inc  rdx
    shl  rdx, AUTH_GENERATION_SHIFT
    ; desired state now contains generation only: no LIVE bits, no revoked bits
    lock cmpxchg qword ptr [gAuthorityState], rdx
    jne  aag_retry
    mov  rax, rdx
    ret

aag_fail:
    mov  rax, -1
    ret
AuthorityAdvanceGen ENDP

PUBLIC AuthorityRootSeal
PUBLIC AuthorityAdvanceGen

END
