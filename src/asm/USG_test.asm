; USG_test.asm - Test harness for USG
; =============================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

INCLUDE rawrxd_win64.inc

; External functions from USG.asm
EXTERN USG_Init:PROC
EXTERN USG_Generate21:PROC

; C Runtime functions
EXTERN printf : PROC
EXTERN getchar : PROC

; =============================================================================
; DATA SECTION
; =============================================================================
.DATA

szHello     DB  "RawrXD x64 MASM Build Successful!", 13, 10, 0
szUSGStart  DB  "USG: Generating 21 bars...", 13, 10, 0
szUSGDone   DB  "USG: Generation complete!", 13, 10, 0
szPressKey  DB  "Press any key to exit...", 13, 10, 0

; =============================================================================
; CODE SECTION
; =============================================================================
.CODE

; ---------------------------------------------------------------------------
; Entry point
; ---------------------------------------------------------------------------
USG_TestEntry PROC FRAME
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

    ; Print USG start message
    lea     rcx, [szUSGStart]
    call    printf

    ; Initialize USG with MODE_PEACEFUL | MODE_DIGITAL
    mov     ecx, 00000041h
    call    USG_Init

    ; Generate 21 bars
    call    USG_Generate21

    ; Print USG done message
    lea     rcx, [szUSGDone]
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
USG_TestEntry ENDP

; ---------------------------------------------------------------------------
END

