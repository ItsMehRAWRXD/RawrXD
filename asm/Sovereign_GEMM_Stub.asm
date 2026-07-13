;==============================================================================
; Sovereign_GEMM_Stub.asm
; Stub implementation for missing GEMM kernels
; Only defines symbols NOT already present in other objects
;==============================================================================

.code

; Stub for Sovereign_GEMM_16x16 - referenced by Attention_Output and FFN
; This is the ONLY symbol not defined elsewhere
Sovereign_GEMM_16x16 PROC
    ; Minimal implementation - just return success
    xor eax, eax
    ret
Sovereign_GEMM_16x16 ENDP

END
