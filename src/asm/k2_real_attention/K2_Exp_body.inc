; K2_Exp_body.inc — range-reduced e^x (f32). body≈28. No CRT.
PUBLIC XR_ExpF32
XR_ExpF32 PROC
    vmaxss  xmm0, xmm0, DWORD PTR c_exp_min
    vminss  xmm0, xmm0, DWORD PTR c_exp_max
    vmulss  xmm1, xmm0, DWORD PTR c_log2e
    vcvtss2si eax, xmm1
    vcvtsi2ss xmm2, xmm2, eax
    vmulss  xmm3, xmm2, DWORD PTR c_ln2_hi
    vsubss  xmm4, xmm0, xmm3
    vmulss  xmm3, xmm2, DWORD PTR c_ln2_lo
    vsubss  xmm4, xmm4, xmm3
    vmovss  xmm5, DWORD PTR c_inv720
    vmulss  xmm5, xmm5, xmm4
    vaddss  xmm5, xmm5, DWORD PTR c_inv120
    vmulss  xmm5, xmm5, xmm4
    vaddss  xmm5, xmm5, DWORD PTR c_inv24
    vmulss  xmm5, xmm5, xmm4
    vaddss  xmm5, xmm5, DWORD PTR c_inv6
    vmulss  xmm5, xmm5, xmm4
    vaddss  xmm5, xmm5, DWORD PTR c_half
    vmulss  xmm5, xmm5, xmm4
    vaddss  xmm5, xmm5, DWORD PTR c_one
    vmulss  xmm5, xmm5, xmm4
    vaddss  xmm5, xmm5, DWORD PTR c_one
    add     eax, 127
    shl     eax, 23
    vmovd   xmm2, eax
    vmulss  xmm0, xmm5, xmm2
    ret
XR_ExpF32 ENDP
