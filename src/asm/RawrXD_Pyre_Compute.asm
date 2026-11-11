OPTION CASEMAP:NONE
.code

; Pyre compute exports
PUBLIC asm_pyre_gemm_fp32
PUBLIC asm_pyre_gemv_fp32
PUBLIC asm_pyre_rmsnorm
PUBLIC asm_pyre_silu
PUBLIC asm_pyre_softmax
PUBLIC asm_pyre_rope
PUBLIC asm_pyre_add_fp32
PUBLIC asm_pyre_mul_fp32
PUBLIC asm_pyre_embedding_lookup

asm_pyre_gemm_fp32 PROC
    xor eax, eax
    ret
asm_pyre_gemm_fp32 ENDP

asm_pyre_gemv_fp32 PROC
    xor eax, eax
    ret
asm_pyre_gemv_fp32 ENDP

asm_pyre_rmsnorm PROC
    xor eax, eax
    ret
asm_pyre_rmsnorm ENDP

asm_pyre_silu PROC
    xor eax, eax
    ret
asm_pyre_silu ENDP

asm_pyre_softmax PROC
    xor eax, eax
    ret
asm_pyre_softmax ENDP

asm_pyre_rope PROC
    xor eax, eax
    ret
asm_pyre_rope ENDP

asm_pyre_add_fp32 PROC
    xor eax, eax
    ret
asm_pyre_add_fp32 ENDP

asm_pyre_mul_fp32 PROC
    xor eax, eax
    ret
asm_pyre_mul_fp32 ENDP

asm_pyre_embedding_lookup PROC
    xor eax, eax
    ret
asm_pyre_embedding_lookup ENDP

END
