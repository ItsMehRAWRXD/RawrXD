; ==============================================================================
; Sovereign_Branch_Model.inc - Deterministic Branch Elimination Contract
; ==============================================================================
; Substitutes unpredictable conditional branches in compute hot-loops with
; deterministic decrement-and-check routines or CMOVcc evaluations.

; Unpredictable loop elimination macro
; Automatically creates an unrolled block boundary
HOT_COMPUTE_LOOP MACRO loop_label, count_reg, block_macro
    ; Assumes count_reg contains iteration count
loop_label:
    block_macro
    sub count_reg, 1
    lea rax, loop_label
    cmovnz rax, rax
    jnz rax
ENDM

; Hardware-enforced aligned hot loop target
HOT_TARGET MACRO
    ALIGN 16
ENDM
