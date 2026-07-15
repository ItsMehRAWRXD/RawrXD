; USG_standalone.asm - Standalone USG test (no CRT)
; =============================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

; Minimal includes - no rawrxd_win64.inc to avoid sprintf_s/strcpy_s deps
EXTERN ExitProcess:PROC

; External from USG.asm
EXTERN USG_Init:PROC
EXTERN USG_Generate21:PROC

; =============================================================================
; CODE SECTION
; =============================================================================
.CODE

; ---------------------------------------------------------------------------
; Standalone entry - no CRT dependencies
; ---------------------------------------------------------------------------
USG_StandaloneEntry PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; Initialize USG with MODE_PEACEFUL | MODE_DIGITAL
    mov     ecx, 00000041h
    call    USG_Init

    ; Generate 21 bars
    call    USG_Generate21

    ; Exit process
    xor     ecx, ecx
    call    ExitProcess

    ; Should never reach here
    add     rsp, 32
    pop     rbp
    ret
USG_StandaloneEntry ENDP

; ---------------------------------------------------------------------------
END

