; ============================================================================
; test_minimal.asm - Absolute minimal test function
; ============================================================================
; This function just returns 0 to verify linkage works
; ============================================================================

OPTION CASEMAP:NONE

.code

; Export the symbol
PUBLIC MASM_Test_Minimal

; ============================================================================
; MASM_Test_Minimal - Returns 0 (success)
; ============================================================================
MASM_Test_Minimal PROC
    xor rax, rax    ; Return 0
    ret
MASM_Test_Minimal ENDP

END
