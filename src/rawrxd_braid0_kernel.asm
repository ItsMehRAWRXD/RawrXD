; ============================================================================
; rawrxd_braid0_kernel.asm — Braid-0 Base-Plane GEMM Kernel (MASM x64)
; ============================================================================
; Braid-0 consumes ONLY the base plane (1-bit per weight).
; No residuals. No sparse decode. No bounce logic.
;
; Algorithm:
;   for each 16-element chunk:
;     load 2 bytes of base_plane (16 bits)
;     expand each bit to FP32: 1 -> +scale, 0 -> -scale
;     load 16 FP32 activations
;     FMA: accum += weight * activation
;   horizontal reduce accum
;   convert FP32 -> BF16 (truncate with rounding)
;   store BF16 result
;
; C prototype:
;   extern "C" int Braid0_BasePlaneGEMM_ASM(
;       const uint8_t* base_plane,   // RCX
;       const float*   activations,  // RDX
;       int            tile_size,    // R8
;       float          scale,        // XMM3 (4th arg, float)
;       uint16_t*      out_bf16      // [RSP+0x28] (5th arg)
;   );
;
; Returns: 1 = success, 0 = failure
;
; Preserves all Windows x64 nonvolatile registers:
;   RBX, RBP, RDI, RSI, R12-R15
;   XMM6-XMM15 (none used, so no save needed)
; ============================================================================

        .code

; ----------------------------------------------------------------------------
; Constants
; ----------------------------------------------------------------------------
BRAID0_TILE_CHUNK   EQU     16          ; Process 16 elements at a time (512 bits)
BRAID0_LOCAL_SIZE   EQU     128         ; Stack allocation for temp buffers

; ----------------------------------------------------------------------------
; Braid0_BasePlaneGEMM_ASM
; ----------------------------------------------------------------------------
Braid0_BasePlaneGEMM_ASM PROC FRAME

        ; Save nonvolatile registers
        push    rbx
        .pushreg rbx
        push    rbp
        .pushreg rbp
        push    rdi
        .pushreg rdi
        push    rsi
        .pushreg rsi
        push    r12
        .pushreg r12
        push    r13
        .pushreg r13
        push    r14
        .pushreg r14
        push    r15
        .pushreg r15

        sub     rsp, BRAID0_LOCAL_SIZE
        .allocstack BRAID0_LOCAL_SIZE
        .endprolog

        ; ----------------------------------------------------------------
        ; Parameter unpacking (Windows x64 ABI)
        ; ----------------------------------------------------------------
        mov     r12, rcx                ; r12 = base_plane
        mov     r13, rdx                ; r13 = activations
        mov     r14d, r8d               ; r14 = tile_size
        movss   xmm15, xmm3             ; xmm15 = scale (broadcast later)

        ; 5th parameter: out_bf16 is at [rsp + BRAID0_LOCAL_SIZE + 0x28]
        ; (0x28 = shadow space + alignment)
        mov     r15, [rsp + BRAID0_LOCAL_SIZE + 0x28]

        ; ----------------------------------------------------------------
        ; Validate parameters
        ; ----------------------------------------------------------------
        test    r12, r12
        jz      Braid0_Fail
        test    r13, r13
        jz      Braid0_Fail
        test    r15, r15
        jz      Braid0_Fail
        cmp     r14d, 0
        jle     Braid0_Fail

        ; ----------------------------------------------------------------
        ; Broadcast scale to ZMM15
        ; ----------------------------------------------------------------
        vbroadcastss zmm15, xmm15

        ; ----------------------------------------------------------------
        ; Zero accumulator (ZMM0)
        ; ----------------------------------------------------------------
        vxorps  zmm0, zmm0, zmm0

        ; ----------------------------------------------------------------
        ; Main loop: process tile in chunks of 16
        ; ----------------------------------------------------------------
        xor     ebx, ebx                ; ebx = element index (i)

Braid0_Loop:
        cmp     ebx, r14d
        jge     Braid0_Reduce

        ; Calculate chunk size = min(16, remaining)
        mov     eax, r14d
        sub     eax, ebx
        cmp     eax, BRAID0_TILE_CHUNK
        cmovg   eax, [rel Braid0_Const16]
        mov     r11d, eax               ; r11 = chunk_size

        ; --------------------------------------------------------
        ; Build weight vector in temporary stack buffer
        ; For each bit in base_plane:
        ;   bit = 1 -> +scale
        ;   bit = 0 -> -scale
        ; --------------------------------------------------------
        ; We need to read ceil(chunk_size/8) bytes from base_plane
        ; For chunk_size=16, read 2 bytes
        ; For chunk_size<16, read 1-2 bytes depending

        mov     r8, r12                 ; r8 = current base_plane position
        lea     r9, [rsp + 64]          ; r9 = temp float buffer (64 floats max)

        xor     ecx, ecx                ; ecx = bit index within chunk (0..15)

Braid0_WeightBuild:
        cmp     ecx, r11d
        jge     Braid0_WeightDone

        ; global_element = ebx + ecx
        mov     edx, ebx
        add     edx, ecx                ; edx = global element index

        ; byte_idx = global_element / 8
        mov     eax, edx
        shr     eax, 3

        ; bit_idx = global_element % 8
        mov     edi, edx
        and     edi, 7

        ; bit = (base_plane[byte_idx] >> bit_idx) & 1
        movzx   esi, byte ptr [r12 + rax]
        mov     edx, edi
        shr     esi, cl
        and     esi, 1

        ; weight = bit ? scale : -scale
        ; Store to temp buffer
        test    esi, esi
        jz      Braid0_NegScale

        ; Positive scale
        vmovss  dword ptr [r9 + rcx*4], xmm15
        jmp     Braid0_NextBit

Braid0_NegScale:
        ; Negative scale: -scale
        vxorps  xmm1, xmm1, xmm1
        vsubss  xmm1, xmm1, xmm15
        vmovss  dword ptr [r9 + rcx*4], xmm1

Braid0_NextBit:
        inc     ecx
        jmp     Braid0_WeightBuild

Braid0_WeightDone:
        ; --------------------------------------------------------
        ; Load weights and activations, perform FMA
        ; --------------------------------------------------------
        ; Load 16 weights from temp buffer
        vmovups zmm2, [r9]              ; zmm2 = weights[0..15]

        ; Load 16 activations
        vmovups zmm1, [r13 + rbx*4]     ; zmm1 = activations[i..i+15]

        ; FMA: accum += weight * activation
        vfmadd231ps zmm0, zmm2, zmm1

        ; Advance
        add     ebx, r11d
        jmp     Braid0_Loop

        ; ----------------------------------------------------------------
        ; Horizontal reduction: ZMM0 -> scalar in XMM0
        ; ----------------------------------------------------------------
Braid0_Reduce:
        ; Extract upper 256 bits and add
        vextractf64x4 ymm1, zmm0, 1
        vaddps  ymm0, ymm0, ymm1

        ; Extract upper 128 bits and add
        vextractf128 xmm1, ymm0, 1
        vaddps  xmm0, xmm0, xmm1

        ; Horizontal sum within 128 bits
        vshufps xmm1, xmm0, xmm0, 78h   ; 0x4E = swap high/low 64
        vaddps  xmm0, xmm0, xmm1
        vshufps xmm1, xmm0, xmm0, 01h   ; 0xB1 = swap adjacent pairs
        vaddss  xmm0, xmm0, xmm1

        ; ----------------------------------------------------------------
        ; Convert FP32 accumulator to BF16
        ; BF16 = upper 16 bits of FP32 with round-to-nearest-even
        ; Algorithm: add 0x7FFF + (bit 16), then shift right 16
        ; ----------------------------------------------------------------
        vmovd   eax, xmm0               ; eax = FP32 bits
        mov     edx, eax
        and     edx, 0000FFFFh          ; edx = lower 16 bits (for rounding)
        shr     eax, 16                 ; eax = upper 16 bits
        and     edx, 1                  ; edx = bit 16 (rounding bit)
        add     edx, 7FFFh              ; edx = 0x7FFF + rounding
        add     eax, edx                ; add to upper bits
        shr     eax, 16                 ; eax = BF16 result

        ; Store BF16 result
        mov     word ptr [r15], ax

        ; Return success
        mov     eax, 1
        jmp     Braid0_Exit

        ; ----------------------------------------------------------------
        ; Failure path
        ; ----------------------------------------------------------------
Braid0_Fail:
        xor     eax, eax                ; return 0

        ; ----------------------------------------------------------------
        ; Epilogue
        ; ----------------------------------------------------------------
Braid0_Exit:
        add     rsp, BRAID0_LOCAL_SIZE
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rsi
        pop     rdi
        pop     rbp
        pop     rbx
        ret

Braid0_BasePlaneGEMM_ASM ENDP

; ============================================================================
; Data section
; ============================================================================
        .data

Braid0_Const16    DWORD   16

        END
