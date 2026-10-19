; AuthorityMint.asm
; THE ONLY INSTRUCTION PATH ALLOWED TO SET LIVE AUTHORITY BITS.
; Pure x64 MASM. No CRT / WinAPI / external runtime.
;
; Mechanical audit rule:
;   Any instruction that ORs AUTH_LIVE_* into gAuthorityState must live here.
;   Observe/Revoke code never sets a LIVE bit.

option casemap:none
include AuthorityState.inc
EXTERN gAuthorityState:QWORD
EXTERN gAuthorityRoot:QWORD

.code

; RCX = sealed root capability cookie.
; RAX = new/current state snapshot, or -1 on reject.
AuthorityMintDecode PROC
    mov  r10, qword ptr [gAuthorityRoot]
    test r10, r10
    jz   amd_fail
    cmp  rcx, r10
    jne  amd_fail

amd_retry:
    mov  rax, qword ptr [gAuthorityState]
    test rax, AUTH_REVOKED_DECODE
    jnz  amd_fail
    test rax, AUTH_LIVE_DECODE
    jnz  amd_already

    mov  rdx, rax
    or   rdx, AUTH_LIVE_DECODE
    lock cmpxchg qword ptr [gAuthorityState], rdx
    jne  amd_retry
    mov  rax, rdx
    ret

amd_already:
    ret
amd_fail:
    mov  rax, -1
    ret
AuthorityMintDecode ENDP

; RCX = sealed root capability cookie.
; RAX = new/current state snapshot, or -1 on reject.
AuthorityMintScheduler PROC
    mov  r10, qword ptr [gAuthorityRoot]
    test r10, r10
    jz   ams_fail
    cmp  rcx, r10
    jne  ams_fail

ams_retry:
    mov  rax, qword ptr [gAuthorityState]
    test rax, AUTH_REVOKED_SCHEDULER
    jnz  ams_fail
    test rax, AUTH_LIVE_SCHEDULER
    jnz  ams_already

    mov  rdx, rax
    or   rdx, AUTH_LIVE_SCHEDULER
    lock cmpxchg qword ptr [gAuthorityState], rdx
    jne  ams_retry
    mov  rax, rdx
    ret

ams_already:
    ret
ams_fail:
    mov  rax, -1
    ret
AuthorityMintScheduler ENDP

; RCX = sealed root capability cookie.
; Promotion can only be minted while decode + scheduler are both live.
; RAX = new/current state snapshot, or -1 on reject.
AuthorityMintPromotion PROC
    mov  r10, qword ptr [gAuthorityRoot]
    test r10, r10
    jz   amp_fail
    cmp  rcx, r10
    jne  amp_fail

amp_retry:
    mov  rax, qword ptr [gAuthorityState]
    test rax, AUTH_REVOKED_PROMOTION
    jnz  amp_fail

    mov  r11, rax
    and  r11, (AUTH_LIVE_DECODE OR AUTH_LIVE_SCHEDULER)
    cmp  r11, (AUTH_LIVE_DECODE OR AUTH_LIVE_SCHEDULER)
    jne  amp_fail

    test rax, AUTH_LIVE_PROMOTION
    jnz  amp_already

    mov  rdx, rax
    or   rdx, AUTH_LIVE_PROMOTION
    lock cmpxchg qword ptr [gAuthorityState], rdx
    jne  amp_retry
    mov  rax, rdx
    ret

amp_already:
    ret
amp_fail:
    mov  rax, -1
    ret
AuthorityMintPromotion ENDP

PUBLIC AuthorityMintDecode
PUBLIC AuthorityMintScheduler
PUBLIC AuthorityMintPromotion

END
