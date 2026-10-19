; AuthorityState.inc
; Pure x64 MASM authority state contract. No CRT / WinAPI / external runtime.
; LIVE bits may only be SET by AuthorityMint.asm.

option casemap:none

AUTH_LIVE_DECODE        EQU 0000000000000001h
AUTH_LIVE_SCHEDULER     EQU 0000000000000002h
AUTH_LIVE_PROMOTION     EQU 0000000000000004h
AUTH_LIVE_MASK          EQU 0000000000000007h

AUTH_REVOKED_DECODE     EQU 0000000000000100h
AUTH_REVOKED_SCHEDULER  EQU 0000000000000200h
AUTH_REVOKED_PROMOTION  EQU 0000000000000400h
AUTH_REVOKED_MASK       EQU 0000000000000700h

AUTH_GENERATION_SHIFT   EQU 16

AuthorityRootSeal       PROTO
AuthorityAdvanceGen     PROTO
AuthorityMintDecode     PROTO
AuthorityMintScheduler  PROTO
AuthorityMintPromotion  PROTO
AuthorityObserve        PROTO
AuthorityRevoke         PROTO
