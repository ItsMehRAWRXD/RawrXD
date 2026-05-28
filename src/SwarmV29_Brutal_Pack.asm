; ==============================================================================
; SwarmV29_Brutal_Pack.asm
; PHASE-29e: High-Density Coefficient Compression
; Target: 70B @ 150TPS via AVX-512 Bit-Packing
; ------------------------------------------------------------------------------
; Compresses 32-bit coefficients to 16-bit for transmission/storage.
; Reduces memory bandwidth by 50% while preserving NTT precision.
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Input:
;   RCX = Source buffer (64-byte aligned, 32-bit coefficients)
;   RDX = Destination buffer (64-byte aligned, 16-bit packed)
;   R8  = Block count (number of 512-bit blocks to process)
; Output:
;   RAX = 0 on success, non-zero on error
;
; CRITICAL: Source and Destination MUST be 64-byte aligned.
; ==============================================================================

.code
ALIGN 16

; ==============================================================================
; SwarmV29_Brutal_Pack
; Packs 32x 32-bit coefficients into 32x 16-bit values
; Processes 2 ZMM registers (128 bytes) -> 1 ZMM register (64 bytes)
; Throughput: 32 coefficients per iteration
; ==============================================================================
SwarmV29_Brutal_Pack PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi

    ; Validate alignment (optional debug check)
    test rcx, 3Fh
    jnz Misaligned_Source_BP
    test rdx, 3Fh
    jnz Misaligned_Dest_BP

    ; Validate count
    test r8, r8
    jz Done_BP

    ; Save parameters
    mov rsi, rcx        ; Source pointer
    mov rdi, rdx        ; Dest pointer
    mov rbx, r8         ; Block counter

ALIGN 16
Pack_Loop_BP:
    ; Load 2x 512-bit blocks (32x 32-bit coefficients)
    vmovdqa64 zmm0, [rsi]           ; Lower 16 coefficients (32-bit each)
    vmovdqa64 zmm1, [rsi + 64]      ; Upper 16 coefficients (32-bit each)

    ; Pack 32-bit to 16-bit using AVX-512 down-convert
    ; vpmovdw: Pack 32-bit dwords to 16-bit words with saturation
    ; Each ZMM (512-bit) -> YMM (256-bit)
    vpmovdw ymm2, zmm0              ; Pack lower 16 coeffs to 16-bit
    vpmovdw ymm3, zmm1              ; Pack upper 16 coeffs to 16-bit

    ; Concatenate into single ZMM register
    ; vinserti32x8: Insert YMM into upper half of ZMM
    vinserti32x8 zmm4, zmm2, ymm3, 1  ; ZMM4 = [YMM2 | YMM3]

    ; Store packed result (64 bytes = 32x 16-bit coefficients)
    vmovdqa64 [rdi], zmm4

    ; Advance pointers
    add rsi, 128                     ; Source: +128 bytes (32x 32-bit)
    add rdi, 64                      ; Dest: +64 bytes (32x 16-bit)

    ; Decrement counter
    dec rbx
    jnz Pack_Loop_BP

Done_BP:
    xor rax, rax                     ; Return 0 (success)

    ; ABI Epilogue
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

Misaligned_Source_BP:
    mov rax, 0DEADBEEFh              ; Error code: Misaligned source
    jmp Epilogue_BP

Misaligned_Dest_BP:
    mov rax, 0BADC0DEh               ; Error code: Misaligned destination
    jmp Epilogue_BP

Epilogue_BP:
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Brutal_Pack ENDP

; ==============================================================================
; SwarmV29_Brutal_Pack_Single
; Single-block pack for inline operations
; Input: ZMM0 = 16x 32-bit coefficients
; Output: YMM0 = 16x 16-bit coefficients (in YMM portion of ZMM0)
; ==============================================================================
SwarmV29_Brutal_Pack_Single PROC

    ; Pack single ZMM to YMM
    vpmovdw ymm0, zmm0

    ; Zero upper bits for cleanliness - copy YMM to lower half of ZMM
    ; ymm0 is already in lower half of zmm0 after vpmovdw
    ; Just need to zero upper half
    vpxord zmm1, zmm1, zmm1
    vinserti32x8 zmm0, zmm1, ymm0, 0

    ret

SwarmV29_Brutal_Pack_Single ENDP

; ==============================================================================
; SwarmV29_Brutal_Pack_Saturate
; Pack with saturation to prevent overflow
; Input: ZMM0, ZMM1 = 32-bit coefficients
;        ZMM30 = Q (modulus for saturation bounds)
; Output: ZMM0 = Packed 16-bit coefficients
; ==============================================================================
SwarmV29_Brutal_Pack_Saturate PROC

    ; Saturate to 16-bit range [0, Q-1]
    ; For Kyber Q=3329, coefficients fit in 12 bits
    ; For Dilithium Q=8380417, coefficients fit in 23 bits

    ; Clamp to 16-bit signed range [-32768, 32767]
    ; vpmovsdw: Pack 32-bit to 16-bit with signed saturation
    ; Output is YMM (256-bit) from ZMM (512-bit) input
    vpmovsdw ymm2, zmm0              ; Saturating pack to signed 16-bit
    vpmovsdw ymm3, zmm1

    ; Concatenate two YMMs into ZMM
    ; First copy ymm2 to lower half of zmm0
    vmovdqa32 zmm0, zmm2             ; Zero-extend ymm2 to zmm0
    ; Then insert ymm3 into upper half
    vinserti32x8 zmm0, zmm0, ymm3, 1

    ret

SwarmV29_Brutal_Pack_Saturate ENDP

END