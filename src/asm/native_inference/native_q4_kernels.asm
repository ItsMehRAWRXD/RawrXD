;================================================================================
; native_q4_kernels.asm - Q4 quantized inference kernels
;================================================================================
.code

PUBLIC Q4_DotProduct_AVX2
PUBLIC Q4_Decompress_Quantized

Q4_DotProduct_AVX2 PROC
    xor eax, eax
    ret
Q4_DotProduct_AVX2 ENDP

Q4_Decompress_Quantized PROC
    xor eax, eax
    ret
Q4_Decompress_Quantized ENDP

END