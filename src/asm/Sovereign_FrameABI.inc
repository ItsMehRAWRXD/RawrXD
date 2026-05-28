; ==================================================================================
; SOVEREIGN FRAME ABI - PRODUCTION PARITY LAYER
; ==================================================================================

; ------------------------------
; HARD ABI CONSTANTS
; ------------------------------
SHADOW_SIZE      EQU 32
FRAME_ALIGNMENT  EQU 16
FRAME_TOTAL      EQU 80

; ------------------------------
; ENTRY FRAME (SAFE WIN64 ABI)
; ------------------------------
ENTER_FRAME MACRO
    push rbp
    mov rbp, rsp
    sub rsp, FRAME_TOTAL
    and rsp, -FRAME_ALIGNMENT
ENDM

; ------------------------------
; EXIT FRAME (CLEAN RESTORE)
; ------------------------------
EXIT_FRAME MACRO
    mov rsp, rbp
    pop rbp
    ret
ENDM

; ------------------------------
; SHADOW ZEROING (DETERMINISM)
; ------------------------------
CLEAR_SHADOW MACRO
    xor rax, rax
    mov [rsp+20h], rax
    mov [rsp+28h], rax
    mov [rsp+30h], rax
    mov [rsp+38h], rax
ENDM

; ------------------------------
; SAFE CALL WRAPPER
; ------------------------------
SAFE_CALL MACRO target
    sub rsp, 20h
    call target
    add rsp, 20h
ENDM

; ------------------------------
; ALIGNMENT ASSERTION (DEBUG ONLY HOOK)
; ------------------------------
ASSERT_ALIGNED MACRO
    test rsp, 0Fh
    jz @F
    int 3
@@:
ENDM
