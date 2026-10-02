; Decoda Beacon v6 fused Lloyd-codebook GEMV primitives.
; Win64 ABI-safe. AVX2 + FMA. No external dependencies.
;
; Every entry consumes one 256-weight block directly from packed codes:
;   rcx = const float* x
;   rdx = const BYTE* packed_codes
;   r8  = const float* centroids
; returns xmm0 = sum_i centroid[code[i]] * x[i]
;
; Dot2: 64-byte code payload, 4 centroids
; Dot3: 96-byte code payload, 8 centroids
; Dot4: 128-byte code payload, 16 centroids

.const
ALIGN 16   ; was ALIGN 32, which ml64 rejects as an invalid combination with
           ; .const's segment alignment (A2189). Every load of these tables is
           ; a VEX memory operand, which carries no alignment requirement,
           ; so this is behaviourally identical.
shift2 DD 0,2,4,6,8,10,12,14
shift3 DD 0,3,6,9,12,15,18,21
shift4 DD 0,4,8,12,16,20,24,28
mask3  DD 3,3,3,3,3,3,3,3
mask7  DD 7,7,7,7,7,7,7,7
mask15 DD 15,15,15,15,15,15,15,15
  shift1 DD 0,1,2,3,4,5,6,7
  mask1  DD 1,1,1,1,1,1,1,1

.code
PUBLIC DecodaV6_Dot2_256
DecodaV6_Dot2_256 PROC
    vmovups xmm4, xmmword ptr [r8]
    vinsertf128 ymm4, ymm4, xmm4, 1
    vxorps ymm0, ymm0, ymm0
    xor r9d, r9d
D2_L:
    cmp r9d, 256
    jae D2_S
    mov eax, r9d
    shr eax, 2
    movzx r10d, word ptr [rdx+rax]
    vmovd xmm2, r10d
    vpbroadcastd ymm2, xmm2
    vpsrlvd ymm2, ymm2, ymmword ptr [shift2]
    vpand ymm2, ymm2, ymmword ptr [mask3]
    vpermps ymm3, ymm2, ymm4
    vmovups ymm2, ymmword ptr [rcx+r9*4]
    vfmadd231ps ymm0, ymm3, ymm2
    add r9d, 8
    jmp D2_L
D2_S:
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    vzeroupper
    ret
DecodaV6_Dot2_256 ENDP

PUBLIC DecodaV6_Dot3_256
DecodaV6_Dot3_256 PROC
    vmovups ymm4, ymmword ptr [r8]
    vxorps ymm0, ymm0, ymm0
    xor r9d, r9d
D3_L:
    cmp r9d, 256
    jae D3_S
    mov eax, r9d
    imul eax, 3
    shr eax, 3                    ; byte offset = (i*3)/8, i multiple of 8 => 3*i/8
    movzx r10d, word ptr [rdx+rax]
    movzx r11d, byte ptr [rdx+rax+2]
    shl r11d, 16
    or r10d, r11d
    vmovd xmm2, r10d
    vpbroadcastd ymm2, xmm2
    vpsrlvd ymm2, ymm2, ymmword ptr [shift3]
    vpand ymm2, ymm2, ymmword ptr [mask7]
    vpermps ymm3, ymm2, ymm4
    vmovups ymm2, ymmword ptr [rcx+r9*4]
    vfmadd231ps ymm0, ymm3, ymm2
    add r9d, 8
    jmp D3_L
D3_S:
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    vzeroupper
    ret
DecodaV6_Dot3_256 ENDP

PUBLIC DecodaV6_Dot4_256
DecodaV6_Dot4_256 PROC
    vmovups ymm4, ymmword ptr [r8]
    vmovups ymm5, ymmword ptr [r8+32]
    vxorps ymm0, ymm0, ymm0
    xor r9d, r9d
D4_L:
    cmp r9d, 256
    jae D4_S
    mov eax, r9d
    shr eax, 1                    ; byte offset = i*4/8
    mov r10d, dword ptr [rdx+rax]
    vmovd xmm2, r10d
    vpbroadcastd ymm2, xmm2
    vpsrlvd ymm2, ymm2, ymmword ptr [shift4]
    vpand ymm2, ymm2, ymmword ptr [mask15]
    vpand ymm3, ymm2, ymmword ptr [mask7]
    vpermps ymm3, ymm3, ymm4
    vpand ymm1, ymm2, ymmword ptr [mask7]
    vpermps ymm1, ymm1, ymm5
    vpslld ymm2, ymm2, 28         ; code bit 3 -> blend sign bit
    vblendvps ymm3, ymm3, ymm1, ymm2
    vmovups ymm2, ymmword ptr [rcx+r9*4]
    vfmadd231ps ymm0, ymm3, ymm2
    add r9d, 8
    jmp D4_L
D4_S:
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    vzeroupper
    ret
DecodaV6_Dot4_256 ENDP
; ---------------------------------------------------------------------------
; Dot0_256 -- M=0 blocks.
;
; The encoder emits NO code planes and NO centroids for M=0 (beacon_core.cpp
; assigns centroids[b]/codes[b] only when k != 0), so the residual contribution
; of an M=0 block is identically zero. This kernel therefore performs NO memory
; reads at all -- touching [rdx] or [r8] here would be an out-of-bounds read,
; because for M=0 both vectors are empty.
;
; It is not a placeholder. It is the correct evaluation of the M=0 residual
; contract, and it is why an M=0 block costs one instruction instead of a
; 32-iteration loop.
;
; The block's NON-residual contribution (rank-1 base, scales, outliers) is
; assembled by the caller; it is not this kernel's contract, exactly as Dot2/3/4
; exclude it.
; ---------------------------------------------------------------------------
PUBLIC DecodaV6_Dot0_256
DecodaV6_Dot0_256 PROC
    vxorps xmm0, xmm0, xmm0
    ret
DecodaV6_Dot0_256 ENDP

; ---------------------------------------------------------------------------
; Dot1_256 -- M=1 blocks: one binary residual plane.
;
; 8 codes x 1 bit = 8 bits = one byte per 8 weights; 256 weights = 32 bytes.
; Centroid table is 2^1 = 2 floats = 8 bytes, so it is loaded with vmovq and
; broadcast, NOT vmovups -- a 16-byte load would read 8 bytes past the table.
; ---------------------------------------------------------------------------
PUBLIC DecodaV6_Dot1_256
DecodaV6_Dot1_256 PROC
    vmovq   xmm4, qword ptr [r8]        ; 2 centroids, exactly
    vpbroadcastq ymm4, xmm4
    vxorps  ymm0, ymm0, ymm0
    xor     r9d, r9d
D1_L:
    cmp     r9d, 256
    jae     D1_S
    mov     eax, r9d
    shr     eax, 3                      ; byte offset = i / 8
    movzx   r10d, byte ptr [rdx+rax]    ; 8 codes in one byte
    vmovd   xmm2, r10d
    vpbroadcastd ymm2, xmm2
    vpsrlvd ymm2, ymm2, ymmword ptr [shift1]
    vpand   ymm2, ymm2, ymmword ptr [mask1]
    vpermps ymm3, ymm2, ymm4
    vmovups ymm2, ymmword ptr [rcx+r9*4]
    vfmadd231ps ymm0, ymm3, ymm2
    add     r9d, 8
    jmp     D1_L
D1_S:
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    vzeroupper
    ret
DecodaV6_Dot1_256 ENDP

END
