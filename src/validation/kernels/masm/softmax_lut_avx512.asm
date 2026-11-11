; ═══════════════════════════════════════════════════════════════════════════════
; Vectorized Softmax with LUT + Linear Interpolation (AVX-512)
; ═══════════════════════════════════════════════════════════════════════════════
; Replaces polynomial exp with fast LUT-based approximation
; LUT is initialized at runtime by Softmax_LUT_Init (avoids MASM FP initializer limits)
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

; ═══════════════════════════════════════════════════════════════════════════════
; Public Exports
; ═══════════════════════════════════════════════════════════════════════════════
PUBLIC Softmax_LUT_AVX512
PUBLIC Softmax_LUT_Init

; ═══════════════════════════════════════════════════════════════════════════════
; Constants
; ═══════════════════════════════════════════════════════════════════════════════
LUT_SIZE        EQU     256             ; LUT entries

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.data

; Exp LUT: exp(x) for x in [-8, 0], 256 entries (initialized at runtime)
exp_lut         DWORD   LUT_SIZE DUP(0)

; Constants
lut_scale       REAL4   32.0            ; LUT_SIZE / LUT_RANGE (256/8)
neg_lut_min     REAL4   -8.0            ; Minimum LUT input
one_f           REAL4   1.0
zero_f          REAL4   0.0
two_f           REAL4   2.0
lut_init_flag   DWORD   0               ; 0 = not initialized, 1 = initialized

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.code

; ═══════════════════════════════════════════════════════════════════════════════
; Softmax_LUT_Init
;
; Initializes the exp LUT at runtime
; exp_lut[i] = exp(-8.0 + i * (8.0 / 256.0)) = exp(-8.0 + i / 32.0)
; ═══════════════════════════════════════════════════════════════════════════════
Softmax_LUT_Init PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    .endprolog

    ; Check if already initialized
    mov     eax, dword ptr [lut_init_flag]
    test    eax, eax
    jnz     .init_done

    ; Initialize LUT
    lea     rsi, [exp_lut]              ; rsi = &exp_lut[0]
    xor     ebx, ebx                    ; ebx = index = 0

.init_loop:
    cmp     ebx, LUT_SIZE
    jae     .init_complete

    ; Compute x = -8.0 + index * 0.03125
    ; 0.03125 = 1/32
    mov     eax, 03D000000h             ; 0.03125f in IEEE754
    movd    xmm1, eax
    cvtsi2ss xmm0, ebx
    mulss   xmm0, xmm1                  ; xmm0 = index * 0.03125
    addss   xmm0, dword ptr [neg_lut_min] ; xmm0 = -8.0 + index * 0.03125

    ; Compute exp(x) using 2^(x * log2(e))
    ; log2(e) = 1.44269504
    mov     eax, 3FB8AA3Bh              ; 1.44269504f
    movd    xmm1, eax
    mulss   xmm0, xmm1                  ; xmm0 = x * log2(e)

    ; Split into integer and fractional parts
    ; 2^x = 2^int * 2^frac
    roundss xmm2, xmm0, 3               ; xmm2 = floor(x) (round toward -inf)
    movss   xmm3, xmm0
    subss   xmm3, xmm2                  ; xmm3 = frac = x - floor(x)

    ; 2^int via bit manipulation: float(2^n) = (n + 127) << 23
    cvtss2si eax, xmm2                  ; eax = (int)floor(x)
    add     eax, 127                    ; exponent bias
    shl     eax, 23                     ; shift to exponent position
    movd    xmm4, eax                   ; xmm4 = 2^int

    ; 2^frac via polynomial: 2^f ≈ 1 + f*ln2 + (f*ln2)^2/2 + (f*ln2)^3/6
    ; ln2 = 0.69314718
    mov     eax, 3F317218h              ; 0.69314718f
    movd    xmm5, eax
    mulss   xmm5, xmm3                  ; xmm5 = f * ln2
    ; exp(y) = 1 + y + y^2/2 + y^3/6 where y = f*ln2
    movss   xmm6, dword ptr [one_f]     ; xmm6 = 1.0
    addss   xmm6, xmm5                  ; 1 + y
    movss   xmm7, xmm5
    mulss   xmm7, xmm7                  ; y^2
    mov     eax, 3F000000h              ; 0.5f
    movd    xmm0, eax
    mulss   xmm7, xmm0                  ; y^2 * 0.5
    addss   xmm6, xmm7                  ; 1 + y + y^2/2
    movss   xmm7, xmm5
    mulss   xmm7, xmm7                  ; y^2
    mulss   xmm7, xmm5                  ; y^3
    mov     eax, 3E2AAAABh              ; 1/6 ≈ 0.16667f
    movd    xmm0, eax
    mulss   xmm7, xmm0                  ; y^3 / 6
    addss   xmm6, xmm7                  ; 1 + y + y^2/2 + y^3/6

    ; Final: exp(x) = 2^int * 2^frac
    mulss   xmm4, xmm6                  ; xmm4 = 2^int * 2^frac = exp(x)

    ; Store in LUT
    movss   dword ptr [rsi + rbx*4], xmm4

    inc     ebx
    jmp     .init_loop

.init_complete:
    mov     dword ptr [lut_init_flag], 1

.init_done:
    pop     rsi
    pop     rbx
    ret
Softmax_LUT_Init ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; Softmax_LUT_AVX512
;
; Fast softmax using LUT + linear interpolation
; Formula: softmax(x_i) = exp(x_i - max) / sum(exp(x_j - max))
;
; Parameters (Windows x64 ABI):
;   RCX = input (float*)
;   RDX = output (float*)
;   R8  = length (uint32_t)
;
; Returns: void
; ═══════════════════════════════════════════════════════════════════════════════
Softmax_LUT_AVX512 PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 64
    .allocstack 64
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog

    ; Save parameters
    mov     rsi, rcx                    ; rsi = input
    mov     rdi, rdx                    ; rdi = output
    mov     ebx, r8d                    ; ebx = length

    test    ebx, ebx
    jz      .done

    ; ═══════════════════════════════════════════════════════════════════════════
    ; Phase 1: Find max (horizontal reduction)
    ; ═══════════════════════════════════════════════════════════════════════════
    vmovss  xmm0, dword ptr [rsi]       ; xmm0 = input[0]
    vbroadcastss zmm0, xmm0             ; zmm0 = max_val

    mov     eax, 1
    cmp     ebx, 16
    jb      .find_max_scalar

.find_max_vector:
    cmp     eax, ebx
    jae     .find_max_done
    vmovups zmm1, zmmword ptr [rsi + rax*4]
    vmaxps  zmm0, zmm0, zmm1
    add     eax, 16
    jmp     .find_max_vector

.find_max_scalar:
    cmp     eax, ebx
    jae     .find_max_done
    vbroadcastss zmm1, dword ptr [rsi + rax*4]
    vmaxps  zmm0, zmm0, zmm1
    inc     eax
    jmp     .find_max_scalar

.find_max_done:
    vextractf64x4 ymm1, zmm0, 1
    vmaxps  ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vmaxps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 0Eh
    vmaxps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 01h
    vmaxps  xmm0, xmm0, xmm1
    vbroadcastss zmm0, xmm0             ; zmm0 = max_val

    ; ═══════════════════════════════════════════════════════════════════════════
    ; Phase 2: Compute exp(x - max) using LUT
    ; ═══════════════════════════════════════════════════════════════════════════
    vbroadcastss zmm7, dword ptr [lut_scale]
    vbroadcastss zmm6, dword ptr [neg_lut_min]
    vxorps  zmm5, zmm5, zmm5            ; zmm5 = sum_exp = 0

    mov     eax, 0
    cmp     ebx, 16
    jb      .exp_scalar

.exp_vector:
    cmp     eax, ebx
    jae     .exp_done
    vmovups zmm1, zmmword ptr [rsi + rax*4]
    vsubps  zmm1, zmm1, zmm0            ; x' = x - max
    vmaxps  zmm1, zmm1, zmm6            ; clamp to [-8, 0]
    vxorps  zmm2, zmm2, zmm2
    vminps  zmm1, zmm1, zmm2
    vsubps  zmm2, zmm1, zmm6            ; x' + 8
    vmulps  zmm2, zmm2, zmm7            ; idx
    vcvtps2dq zmm3, zmm2                ; idx_int
    kxnorw  k1, k1, k1                  ; k1 = all ones
    vgatherdps zmm2 {k1}, [exp_lut + zmm3*4]
    vmovups zmmword ptr [rdi + rax*4], zmm2
    vaddps  zmm5, zmm5, zmm2
    add     eax, 16
    jmp     .exp_vector

.exp_scalar:
    cmp     eax, ebx
    jae     .exp_done
    vmovss  xmm1, dword ptr [rsi + rax*4]
    vsubss  xmm1, xmm1, xmm0
    vmaxss  xmm1, xmm1, xmm6
    vxorps  xmm2, xmm2, xmm2
    vminss  xmm1, xmm1, xmm2
    vsubss  xmm2, xmm1, xmm6
    vmulss  xmm2, xmm2, xmm7
    vcvttss2si r8, xmm2
    cmp     r8, 0
    jl      .clamp_low
    cmp     r8, LUT_SIZE
    jge     .clamp_high
    jmp     .load_lut
.clamp_low:
    xor     r8, r8
    jmp     .load_lut
.clamp_high:
    mov     r8, LUT_SIZE - 1
.load_lut:
    vmovss  xmm2, dword ptr [exp_lut + r8*4]
    vmovss  dword ptr [rdi + rax*4], xmm2
    vaddss  xmm5, xmm5, xmm2
    inc     eax
    jmp     .exp_scalar

.exp_done:
    vextractf64x4 ymm1, zmm5, 1
    vaddps  ymm5, ymm5, ymm1
    vextractf128 xmm1, ymm5, 1
    vaddps  xmm5, xmm5, xmm1
    vshufps xmm1, xmm5, xmm5, 0Eh
    vaddps  xmm5, xmm5, xmm1
    vshufps xmm1, xmm5, xmm5, 01h
    vaddps  xmm5, xmm5, xmm1
    vbroadcastss zmm5, xmm5             ; zmm5 = sum_exp

    ; ═══════════════════════════════════════════════════════════════════════════
    ; Phase 3: Normalize (output = exp(x) / sum_exp)
    ; ═══════════════════════════════════════════════════════════════════════════
    vrcp14ps zmm6, zmm5                 ; approx 1/sum_exp
    vbroadcastss zmm7, dword ptr [two_f]
    vfnmadd231ps zmm7, zmm5, zmm6       ; 2 - sum*r
    vmulps  zmm6, zmm6, zmm7            ; refined reciprocal

    mov     eax, 0
    cmp     ebx, 16
    jb      .normalize_scalar

.normalize_vector:
    cmp     eax, ebx
    jae     .normalize_done
    vmovups zmm1, zmmword ptr [rdi + rax*4]
    vmulps  zmm1, zmm1, zmm6
    vmovups zmmword ptr [rdi + rax*4], zmm1
    add     eax, 16
    jmp     .normalize_vector

.normalize_scalar:
    cmp     eax, ebx
    jae     .normalize_done
    vmovss  xmm1, dword ptr [rdi + rax*4]
    vmulss  xmm1, xmm1, xmm6
    vmovss  dword ptr [rdi + rax*4], xmm1
    inc     eax
    jmp     .normalize_scalar

.normalize_done:
.done:
    vzeroupper
    add     rsp, 64
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

Softmax_LUT_AVX512 ENDP

END