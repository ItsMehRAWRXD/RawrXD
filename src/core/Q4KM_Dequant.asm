; Q4_K_M_Dequant.asm - Q4_K_M Dequantization Kernel
; Implements GGUF Q4_K_M block format decompression in AVX-512
; 
; Q4_K_M Block Format (per 256 weights):
;   - 4-bit quantized weights (128 bytes for 256 weights)
;   - Scale factors (fp16, 8 bytes for 8 groups)
;   - Min values (fp16, 8 bytes for 8 groups)
;   - Total: 144 bytes per 256 weights
;
; This kernel dequantizes 256 weights at a time using AVX-512

option casemap:none

; =============================================================================
; EXTERNAL IMPORTS
; =============================================================================
EXTERNDEF printf:PROC

; =============================================================================
; DATA SECTION
; =============================================================================
.data
    ; Constants for Q4_K_M
    Q4KM_BLOCK_SIZE     EQU 256     ; Weights per block
    Q4KM_GROUPS         EQU 8       ; Scale/min groups
    Q4KM_WEIGHTS_PER_GROUP EQU 32  ; Weights per scale group
    
    ; Debug messages
    msg_init        db "Q4_K_M Dequant Kernel Initialized", 10, 0
    msg_block       db "Processing block %d...", 10, 0
    msg_done        db "Dequantization complete", 10, 0
    
    ; Lookup table for 4-bit to 8-bit expansion
    ; Maps 0-15 to signed values -8 to +7
    nibble_lut      db -8, -7, -6, -5, -4, -3, -2, -1
                    db  0,  1,  2,  3,  4,  5,  6,  7
    
    ; Temporary buffers (aligned for AVX-512)
    align 16
    temp_weights    db 256 dup(0)   ; Expanded 8-bit weights
    align 16
    temp_scales     dd 8 dup(0.0)   ; FP32 scales
    align 16
    temp_mins       dd 8 dup(0.0)   ; FP32 mins

; =============================================================================
; CODE SECTION
; =============================================================================
.code

; =============================================================================
; PUBLIC API
; =============================================================================
PUBLIC Q4KM_Dequant_Block
PUBLIC Q4KM_Init
PUBLIC Q4KM_Process_Layer

; =============================================================================
; Q4KM_Init - Initialize dequantization kernel
; =============================================================================
Q4KM_Init PROC
    push    rbp
    mov     rbp, rsp
    
    ; Print initialization message
    lea     rcx, msg_init
    call    printf
    
    pop     rbp
    ret
Q4KM_Init ENDP

; =============================================================================
; Q4KM_Dequant_Block - Dequantize one Q4_K_M block (256 weights)
; 
; Input:  RCX = pointer to Q4_K_M block data (144 bytes)
;         RDX = pointer to output FP32 buffer (256 floats = 1024 bytes)
; Output: RAX = 0 on success, non-zero on error
; 
; Block layout:
;   [0:127]   - 4-bit weights (256 nibbles packed into 128 bytes)
;   [128:143] - Scale factors (8 x fp16)
;   [144:159] - Min values (8 x fp16)
; =============================================================================
Q4KM_Dequant_Block PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 64
    
    ; Save parameters
    mov     r12, rcx            ; R12 = block data pointer
    mov     r13, rdx            ; R13 = output buffer pointer
    
    ; ============================================================
    ; Step 1: Convert fp16 scales to fp32
    ; ============================================================
    lea     r14, temp_scales    ; R14 = scales buffer
    lea     r15, temp_mins      ; R15 = mins buffer
    
    mov     rcx, 8              ; 8 scale/min pairs
    xor     rbx, rbx            ; RBX = index
    
scale_convert_loop:
    cmp     rbx, 8
    jge     scale_done
    
    ; Load scale (fp16 at offset 128 + rbx*2)
    movzx   eax, word ptr [r12 + 128 + rbx*2]
    
    ; Convert fp16 to fp32
    ; fp16: 1 sign bit, 5 exponent bits, 10 mantissa bits
    ; fp32: 1 sign bit, 8 exponent bits, 23 mantissa bits
    
    ; Extract components
    mov     edx, eax
    and     edx, 8000h          ; Sign bit
    shl     edx, 16             ; Move to fp32 position
    
    mov     ecx, eax
    and     ecx, 7C00h          ; Exponent (5 bits)
    shr     ecx, 10
    sub     ecx, 15             ; Unbias from 15 to 127
    add     ecx, 127
    shl     ecx, 23             ; Move to fp32 position
    
    mov     esi, eax
    and     esi, 03FFh          ; Mantissa (10 bits)
    shl     esi, 13             ; Expand to 23 bits
    
    ; Combine
    or      edx, ecx
    or      edx, esi
    
    mov     dword ptr [r14 + rbx*4], edx
    
    ; Load min (fp16 at offset 144 + rbx*2)
    movzx   eax, word ptr [r12 + 144 + rbx*2]
    
    ; Convert fp16 to fp32 (same logic)
    mov     edx, eax
    and     edx, 8000h
    shl     edx, 16
    
    mov     ecx, eax
    and     ecx, 7C00h
    shr     ecx, 10
    sub     ecx, 15
    add     ecx, 127
    shl     ecx, 23
    
    mov     esi, eax
    and     esi, 03FFh
    shl     esi, 13
    
    or      edx, ecx
    or      edx, esi
    
    mov     dword ptr [r15 + rbx*4], edx
    
    inc     rbx
    jmp     scale_convert_loop
    
scale_done:
    
    ; ============================================================
    ; Step 2: Dequantize weights using AVX-512
    ; Process 64 weights at a time (16 ZMM registers)
    ; ============================================================
    xor     rbx, rbx            ; RBX = weight index (0-255)
    
weight_loop:
    cmp     rbx, 256
    jge     dequant_done
    
    ; Calculate which group this weight belongs to
    mov     rax, rbx
    shr     rax, 5              ; RAX = group index (0-7)
    
    ; Load scale and min for this group
    vmovss  xmm0, dword ptr [r14 + rax*4]   ; Scale
    vmovss  xmm1, dword ptr [r15 + rax*4]   ; Min
    vbroadcastss zmm2, xmm0                  ; ZMM2 = scale (broadcasted)
    vbroadcastss zmm3, xmm1                  ; ZMM3 = min (broadcasted)
    
    ; Process 16 weights at a time
    ; Each byte contains 2 nibbles (2 weights)
    mov     rax, rbx
    shr     rax, 1              ; Byte index
    
    ; Load 8 bytes (16 weights)
    vmovdqu64 zmm4, zmmword ptr [r12 + rax]
    
    ; Extract low nibbles (weights 0, 2, 4, 6, 8, 10, 12, 14)
    vpandd  zmm5, zmm4, zmmword ptr [nibble_mask_low]
    
    ; Extract high nibbles (weights 1, 3, 5, 7, 9, 11, 13, 15)
    vpsrld  zmm6, zmm4, 4
    vpandd  zmm6, zmm6, zmmword ptr [nibble_mask_low]
    
    ; Convert to signed int8 (-8 to +7)
    ; Subtract 8 from each nibble
    vpbroadcastd zmm7, dword ptr [eight_const]
    vpsubd  zmm5, zmm5, zmm7
    vpsubd  zmm6, zmm6, zmm7
    
    ; Convert to FP32
    vcvtdq2ps zmm8, zmm5        ; Low nibbles as FP32
    vcvtdq2ps zmm9, zmm6        ; High nibbles as FP32
    
    ; Apply: dequant = (quant * scale) + min
    vfmadd231ps zmm8, zmm8, zmm2
    vfmadd231ps zmm9, zmm9, zmm2
    vaddps  zmm8, zmm8, zmm3
    vaddps  zmm9, zmm9, zmm3
    
    ; Store results
    vmovups zmmword ptr [r13 + rbx*4], zmm8
    vmovups zmmword ptr [r13 + rbx*4 + 64], zmm9
    
    add     rbx, 16
    jmp     weight_loop
    
dequant_done:
    vzeroupper
    
    ; Return success
    xor     rax, rax
    
    add     rsp, 64
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
Q4KM_Dequant_Block ENDP

; =============================================================================
; Q4KM_Process_Layer - Process an entire layer of Q4_K_M weights
; 
; Input:  RCX = pointer to layer data
;         RDX = number of blocks
;         R8  = output buffer
; Output: RAX = 0 on success
; =============================================================================
Q4KM_Process_Layer PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    
    mov     r12, rcx            ; R12 = layer data
    mov     r13, rdx            ; R13 = block count
    mov     r14, r8             ; R14 = output buffer
    
    xor     rbx, rbx            ; RBX = block index
    
layer_loop:
    cmp     rbx, r13
    jge     layer_done
    
    ; Process one block
    mov     rcx, r12
    mov     rdx, r14
    call    Q4KM_Dequant_Block
    
    ; Advance pointers
    add     r12, 160            ; 160 bytes per block (padded)
    add     r14, 1024           ; 256 floats per block
    
    inc     rbx
    jmp     layer_loop
    
layer_done:
    
    xor     rax, rax
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
Q4KM_Process_Layer ENDP

; =============================================================================
; CONSTANTS (for AVX-512 operations)
; =============================================================================
.data
    align 16
    nibble_mask_low dd 16 dup(0Fh)     ; Mask for low nibble
    eight_const     dd 8                ; Constant 8 for sign conversion

END
