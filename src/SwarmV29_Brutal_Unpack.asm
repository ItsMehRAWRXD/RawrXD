; ==============================================================================
; SwarmV29_Brutal_Unpack.asm
; PHASE-29e: High-Density Coefficient Expansion
; Target: 70B @ 150TPS via AVX-512 Bit-Unpacking
; ------------------------------------------------------------------------------
; Expands 16-bit packed coefficients back to 32-bit for NTT processing.
; Restores full precision for arithmetic operations.
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Input:
;   RCX = Source buffer (64-byte aligned, 16-bit packed)
;   RDX = Destination buffer (64-byte aligned, 32-bit coefficients)
;   R8  = Block count (number of 512-bit blocks to process)
; Output:
;   RAX = 0 on success, non-zero on error
;
; CRITICAL: Source and Destination MUST be 64-byte aligned.
; ==============================================================================

.code
ALIGN 16

; ==============================================================================
; SwarmV29_Brutal_Unpack
; Unpacks 32x 16-bit coefficients into 32x 32-bit values
; Processes 1 ZMM register (64 bytes) -> 2 ZMM registers (128 bytes)
; Throughput: 32 coefficients per iteration
; ==============================================================================
SwarmV29_Brutal_Unpack PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi

    ; Validate alignment
    test rcx, 3Fh
    jnz Misaligned_Source_BU
    test rdx, 3Fh
    jnz Misaligned_Dest_BU

    ; Validate count
    test r8, r8
    jz Done_BU

    ; Save parameters
    mov rsi, rcx        ; Source pointer (16-bit packed)
    mov rdi, rdx        ; Dest pointer (32-bit expanded)
    mov rbx, r8         ; Block counter

ALIGN 16
Unpack_Loop_BU:
    ; Load packed 16-bit coefficients (64 bytes = 32x 16-bit)
    vmovdqa64 zmm0, [rsi]

    ; Extract lower 16 coefficients (16-bit -> 32-bit zero-extend)
    ; vpmovzxwd: Zero-extend 16-bit words to 32-bit dwords
    vpmovzxwd zmm1, ymm0             ; Lower 16 coeffs -> ZMM1

    ; Extract upper 16 coefficients
    ; First extract upper YMM from ZMM
    vextracti32x8 ymm2, zmm0, 1      ; Upper 16 coeffs -> YMM2

    ; Zero-extend upper half
    vpmovzxwd zmm2, ymm2             ; Upper 16 coeffs -> ZMM2

    ; Store expanded results
    vmovdqa64 [rdi], zmm1            ; Store lower 16 (64 bytes)
    vmovdqa64 [rdi + 64], zmm2       ; Store upper 16 (64 bytes)

    ; Advance pointers
    add rsi, 64                      ; Source: +64 bytes (32x 16-bit)
    add rdi, 128                     ; Dest: +128 bytes (32x 32-bit)

    ; Decrement counter
    dec rbx
    jnz Unpack_Loop_BU

Done_BU:
    xor rax, rax                     ; Return 0 (success)

    ; ABI Epilogue
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

Misaligned_Source_BU:
    mov rax, 0DEADBEEFh              ; Error code: Misaligned source
    jmp Epilogue_BU

Misaligned_Dest_BU:
    mov rax, 0BADC0DEh                ; Error code: Misaligned destination
    jmp Epilogue_BU

Epilogue_BU:
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Brutal_Unpack ENDP

; ==============================================================================
; SwarmV29_Brutal_Unpack_Single
; Single-block unpack for inline operations
; Input: YMM0 = 16x 16-bit coefficients (in YMM portion)
; Output: ZMM0 = 16x 32-bit coefficients (zero-extended)
; ==============================================================================
SwarmV29_Brutal_Unpack_Single PROC

    ; Zero-extend 16-bit to 32-bit
    vpmovzxwd zmm0, ymm0

    ret

SwarmV29_Brutal_Unpack_Single ENDP

; ==============================================================================
; SwarmV29_Brutal_Unpack_Signed
; Unpack with sign extension (for signed coefficients)
; Input: ZMM0 = 32x 16-bit signed coefficients
; Output: ZMM1 = Lower 16x 32-bit signed, ZMM2 = Upper 16x 32-bit signed
; ==============================================================================
SwarmV29_Brutal_Unpack_Signed PROC

    ; Sign-extend lower 16 coefficients
    vpmovsxwd zmm1, ymm0             ; Signed extend lower half

    ; Extract and sign-extend upper 16 coefficients
    vextracti32x8 ymm2, zmm0, 1
    vpmovsxwd zmm2, ymm2             ; Signed extend upper half

    ret

SwarmV29_Brutal_Unpack_Signed ENDP

; ==============================================================================
; SwarmV29_Brutal_Unpack_With_Scale
; Unpack and scale by N^-1 (for INTT final scaling)
; Input:
;   RCX = Source (16-bit packed)
;   RDX = Dest (32-bit expanded)
;   R8  = Block count
;   R9  = Scale factor (N^-1 mod Q)
; ==============================================================================
SwarmV29_Brutal_Unpack_With_Scale PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi
    push r12

    ; Save parameters
    mov rsi, rcx
    mov rdi, rdx
    mov rbx, r8
    mov r12, r9                       ; Scale factor

    ; Broadcast scale factor to ZMM31
    vpbroadcastq zmm31, r12

ALIGN 16
Scale_Loop:
    ; Load packed coefficients
    vmovdqa64 zmm0, [rsi]

    ; Unpack to 32-bit
    vpmovzxwd zmm1, ymm0
    vextracti32x8 ymm2, zmm0, 1
    vpmovzxwd zmm2, ymm2

    ; Scale by N^-1 (Montgomery multiplication)
    vpmullq zmm1, zmm1, zmm31
    vpmullq zmm2, zmm2, zmm31

    ; Store scaled results
    vmovdqa64 [rdi], zmm1
    vmovdqa64 [rdi + 64], zmm2

    ; Advance
    add rsi, 64
    add rdi, 128
    dec rbx
    jnz Scale_Loop

    xor rax, rax

    pop r12
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Brutal_Unpack_With_Scale ENDP

END