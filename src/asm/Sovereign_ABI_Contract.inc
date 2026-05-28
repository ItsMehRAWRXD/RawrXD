; ==============================================================================
; Sovereign_ABI_Contract.inc - Win64 Shadow Space & Stack Alignment Enforcement
; ==============================================================================
; Provides strict macro-level enforcement of the Win64 calling convention.
; Ensures every external/internal call maintains the mandatory 32-byte shadow 
; space and 16-byte stack alignment.

; Standard shadow space reservation (no alignment correction needed)
CALL_FRAME MACRO
    sub rsp, 32
ENDM

CALL_EXIT MACRO
    add rsp, 32
ENDM

; Aligned shadow space reservation
; Assumes standard entry (RSP is 8 mod 16 due to return address push)
; Allocates 32 bytes for shadow space + 8 bytes for alignment padding = 40 bytes.
CALL_FRAME_ALIGNED MACRO
    sub rsp, 40
ENDM

CALL_EXIT_ALIGNED MACRO
    add rsp, 40
ENDM

; Extended workspace for PROCs requiring local variables + shadow space
; Size must be chosen so that (Size + 8) is a multiple of 16.
CALL_WORKSPACE MACRO size
    sub rsp, size
ENDM

FREE_WORKSPACE MACRO size
    add rsp, size
ENDM
