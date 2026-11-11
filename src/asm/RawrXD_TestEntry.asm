; RawrXD_TestEntry.asm - Minimal test entry point
; =============================================================================
OPTION CASEMAP:NONE
OPTION DOTNAME

INCLUDE rawrxd_win64.inc

; C Runtime functions
EXTERN printf : PROC
EXTERN getchar : PROC

; =============================================================================
; DATA
; =============================================================================
.data
szHello     DB  "RawrXD x64 MASM Build Successful!", 13, 10, 0
szPressKey  DB  "Press any key to exit...", 13, 10, 0

; =============================================================================
; CODE
; =============================================================================
.code

RawrXD_TestEntry_Main PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; Print hello message
    lea     rcx, [szHello]
    call    printf

    ; Print press key message
    lea     rcx, [szPressKey]
    call    printf

    ; Wait for keypress
    call    getchar

    ; Exit
    xor     ecx, ecx
    call    ExitProcess

    add     rsp, 32
    pop     rbp
    ret
RawrXD_TestEntry_Main ENDP

END



