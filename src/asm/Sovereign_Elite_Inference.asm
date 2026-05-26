; Sovereign_Overfeatured_Inference.asm
include Sovereign_Common.inc
.CODE
PUBLIC Sovereign_MatMul_AVX512
Sovereign_MatMul_AVX512 PROC
    xor r10, r10
@@ColLoop:
    vpxord zmm0, zmm0, zmm0
    xor r11, r11
@@RowLoop:
    vmovups zmm2, zmmword ptr [rcx + r11*4]
    vmovups zmm3, zmmword ptr [rdx + r11*4]
    vfmadd231ps zmm0, zmm2, zmm3
    add r11, 16
    cmp r11, r9
    jl @@RowLoop
    vextractf32x4 xmm2, zmm0, 0
    vextractf32x4 xmm3, zmm0, 1
    vextractf32x4 xmm4, zmm0, 2
    vextractf32x4 xmm5, zmm0, 3
    vaddps xmm2, xmm2, xmm3
    vaddps xmm4, xmm4, xmm5
    vaddps xmm2, xmm2, xmm4
    vhaddps xmm2, xmm2, xmm2
    vhaddps xmm2, xmm2, xmm2
    vmovss dword ptr [r8 + r10*4], xmm2
    lea rax, [r9 * 4]
    add rdx, rax
    inc r10
    cmp r10, r9
    jl @@ColLoop
    ret
Sovereign_MatMul_AVX512 ENDP
END
