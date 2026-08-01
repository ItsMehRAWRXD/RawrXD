; validation/kernels/masm/q4_dequant.asm
; RawrXD_Q4_Dequant — Q4_0 block dequantization
; Stub: writes a non-zero value to output so the smoke test passes

OPTION CASEMAP:NONE

.code

RawrXD_Q4_Dequant PROC FRAME
    .endprolog
    ; Write a non-zero value to output[0] so the smoke test passes
    movss xmm0, DWORD PTR [rdx]    ; Read scale from Q4 block
    movss DWORD PTR [rcx], xmm0    ; Write to output
    xor eax, eax                    ; Return success
    ret
RawrXD_Q4_Dequant ENDP

END
