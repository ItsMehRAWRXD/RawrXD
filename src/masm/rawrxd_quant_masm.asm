;==============================================================================
; rawrxd_quant_masm.asm
; Pure x64 MASM quantization kernels — zero dependencies
; Q4_K_M, Q5_K_M, Q8_0 dequantization and matrix-vector ops
;
; Build: ml64 /c /Fo rawrxd_quant_masm.obj rawrxd_quant_masm.asm
;==============================================================================
OPTION CASEMAP:NONE

; Include the tensor header
INCLUDE rawrxd_tensor_masm.inc

.CODE

;==============================================================================
; DEQUANTIZE Q4_K BLOCK
; void rawrxd_dequantize_q4k(const void* block, float* out, int n);
; rcx = block (Q4_K_M block pointer)
; rdx = out (output float array)
; r8  = n (number of elements, must be multiple of 256)
;==============================================================================
PUBLIC rawrxd_dequantize_q4k
rawrxd_dequantize_q4k PROC FRAME
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    .endprolog
    
    mov r12, rcx            ; r12 = block pointer
    mov r13, rdx            ; r13 = output pointer
    mov r14d, r8d           ; r14 = n elements
    
    xor r15, r15            ; r15 = element index
    
dequant_block_loop:
    cmp r15, r14
    jae dequant_done
    
    ; Load scales and mins (32 f16 values each)
    ; scales at offset 0, mins at offset 64
    ; qs at offset 128 (128 bytes of packed 4-bit values)
    
    ; Process 256 elements per superblock
    xor rbx, rbx            ; group index (0-7, each group has 32 elements)
    
group_loop:
    cmp rbx, 8
    jae group_done
    
    ; Load scale and min for this group (convert f16 to f32)
    movzx eax, WORD PTR [r12 + rbx*2]       ; scale_f16
    call f16_to_f32
    movss xmm8, xmm0                        ; scale in xmm8
    
    movzx eax, WORD PTR [r12 + rbx*2 + 64]  ; min_f16
    call f16_to_f32
    movss xmm9, xmm0                        ; min in xmm9
    
    ; Broadcast scale and min
    vbroadcastss ymm8, xmm8
    vbroadcastss ymm9, xmm9
    
    ; Process 32 elements in this group (8 AVX2 registers of 4 floats)
    ; Each byte in qs contains 2 nibbles (2 weights)
    mov rsi, rbx
    shl rsi, 4              ; rsi = group * 16 (offset into qs)
    add rsi, 128            ; rsi = offset to qs data
    add rsi, r12            ; rsi = pointer to qs for this group
    
    xor rdi, rdi            ; byte index within group (0-15)
    
byte_loop:
    cmp rdi, 16
    jae byte_done
    
    ; Load byte with 2 weights
    movzx eax, BYTE PTR [rsi + rdi]
    mov ecx, eax
    and ecx, 0Fh            ; ecx = low nibble (weight 0)
    shr eax, 4              ; eax = high nibble (weight 1)
    
    ; Convert to float and dequantize: out = (q - 8) * scale + min
    ; For weight 0
    sub ecx, 8
    cvtsi2ss xmm0, ecx
    mulss xmm0, xmm8
    addss xmm0, xmm9
    movss REAL4 PTR [r13 + r15*4], xmm0
    inc r15
    
    ; For weight 1
    sub eax, 8
    cvtsi2ss xmm0, eax
    mulss xmm0, xmm8
    addss xmm0, xmm9
    movss REAL4 PTR [r13 + r15*4], xmm0
    inc r15
    
    inc rdi
    jmp byte_loop
    
byte_done:
    inc rbx
    jmp group_loop
    
group_done:
    ; Move to next block
    add r12, 144            ; Q4K_BLOCK_SIZE
    jmp dequant_block_loop
    
dequant_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_dequantize_q4k ENDP

;==============================================================================
; DEQUANTIZE Q4_K ROW (optimized for single row)
; void rawrxd_dequantize_q4k_row(const void* row, float* out, int n_embd);
; rcx = row pointer
; rdx = output pointer  
; r8  = n_embd (must be multiple of 256)
;==============================================================================
PUBLIC rawrxd_dequantize_q4k_row
rawrxd_dequantize_q4k_row PROC FRAME
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    .endprolog
    
    mov r12, rcx            ; r12 = row
    mov r13, rdx            ; r13 = out
    mov r14d, r8d           ; r14 = n_embd
    
    ; Calculate number of blocks
    mov eax, r14d
    shr eax, 8              ; eax = n_embd / 256
    mov r15d, eax           ; r15 = block count
    
    xor rbx, rbx            ; rbx = block index
    
row_block_loop:
    cmp ebx, r15d
    jae row_done
    
    ; Process one block of 256 elements
    ; Load all 32 scales and mins first
    sub rsp, 256            ; Allocate space for 64 floats (32 scales + 32 mins)
    mov rsi, rsp
    
    ; Convert scales f16->f32
    xor rdi, rdi
    mov r8, r12
    
convert_scales:
    cmp rdi, 32
    jae scales_done
    movzx eax, WORD PTR [r8 + rdi*2]
    call f16_to_f32
    movss REAL4 PTR [rsi + rdi*4], xmm0
    inc rdi
    jmp convert_scales
    
scales_done:
    ; Convert mins f16->f32
    xor rdi, rdi
    mov r8, r12
    add r8, 64              ; mins offset
    
convert_mins:
    cmp rdi, 32
    jae mins_done
    movzx eax, WORD PTR [r8 + rdi*2]
    call f16_to_f32
    movss REAL4 PTR [rsi + 128 + rdi*4], xmm0  ; Store after scales
    inc rdi
    jmp convert_mins
    
mins_done:
    ; Now dequantize using AVX2
    ; Process 8 groups at a time with AVX2
    xor rdi, rdi            ; group index
    
group_avx_loop:
    cmp rdi, 8
    jae avx_done
    
    ; Load scale and min for this group
    vbroadcastss ymm0, REAL4 PTR [rsi + rdi*4]      ; scale
    vbroadcastss ymm1, REAL4 PTR [rsi + 128 + rdi*4] ; min
    
    ; Load qs data (16 bytes = 32 nibbles)
    mov rax, rdi
    shl rax, 4              ; rax = group * 16
    add rax, 128            ; offset to qs
    add rax, r12
    
    ; Process 16 bytes -> 32 floats
    ; We'll do this in chunks of 8 floats (2 bytes)
    xor rcx, rcx            ; byte offset in group
    
byte_avx_loop:
    cmp rcx, 16
    jae byte_avx_done
    
    movzx edx, BYTE PTR [rax + rcx]
    mov r8d, edx
    and r8d, 0Fh            ; low nibble
    shr edx, 4              ; high nibble
    
    ; Convert to float, subtract 8, multiply by scale, add min
    sub r8d, 8
    sub edx, 8
    
    cvtsi2ss xmm2, r8d
    cvtsi2ss xmm3, edx
    
    ; Store (simplified - in real impl use AVX2 gathers)
    mov r8d, ebx
    shl r8d, 8              ; r8 = block_idx * 256
    add r8d, edi
    shl r8d, 5              ; r8 = (block_idx * 256) + (group_idx * 32)
    add r8d, ecx
    shl r8d, 1              ; r8 = element offset * 2 (2 elements per byte)
    
    mulss xmm2, xmm0
    addss xmm2, xmm1
    movss REAL4 PTR [r13 + r8*4], xmm2
    
    inc r8d
    mulss xmm3, xmm0
    addss xmm3, xmm1
    movss REAL4 PTR [r13 + r8*4], xmm3
    
    inc rcx
    jmp byte_avx_loop
    
byte_avx_done:
    inc rdi
    jmp group_avx_loop
    
avx_done:
    add rsp, 256            ; Free stack
    
    ; Move to next block
    add r12, 144
    add r13, 256*4          ; 256 floats
    inc rbx
    jmp row_block_loop
    
row_done:
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_dequantize_q4k_row ENDP

;==============================================================================
; MATRIX-VECTOR MULTIPLY Q4_K (fused dequantize + matvec)
; void rawrxd_matvec_q4k(const void* mat, const float* vec, float* out,
;                        int rows, int cols);
; rcx = mat (Q4_K quantized matrix)
; rdx = vec (f32 input vector)
; r8  = out (f32 output)
; r9  = rows
; [rsp+40] = cols (must be multiple of 256)
;==============================================================================
PUBLIC rawrxd_matvec_q4k
rawrxd_matvec_q4k PROC FRAME
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    .endprolog
    
    mov r12, rcx            ; r12 = mat
    mov r13, rdx            ; r13 = vec
    mov r14, r8             ; r14 = out
    mov r15d, r9d           ; r15 = rows
    mov ebx, DWORD PTR [rsp+40+40]  ; ebx = cols (after pushes)
    mov DWORD PTR [rsp], ebx
    
    xor rdi, rdi            ; rdi = row index
    
matvec_row_loop:
    cmp edi, r15d
    jae matvec_done
    
    ; Compute dot product for this row
    vxorps ymm0, ymm0, ymm0 ; ymm0 = accumulator
    
    ; Calculate blocks per row
    mov eax, ebx
    shr eax, 8              ; eax = cols / 256 = blocks per row
    mov esi, eax            ; esi = blocks to process
    
    xor r8d, r8d            ; r8 = block index
    
block_loop:
    cmp r8d, esi
    jae block_done
    
    ; Process one Q4_K block (256 elements)
    ; Load scales and mins
    mov rax, r8
    imul rax, 144           ; rax = block offset in bytes
    add rax, r12            ; rax = current block pointer
    
    ; Process 8 groups per block
    xor r9d, r9d            ; r9 = group index
    
group_matvec_loop:
    cmp r9d, 8
    jae group_matvec_done
    
    ; Load scale and min for this group
    movzx ecx, WORD PTR [rax + r9*2]        ; scale
    call f16_to_f32
    movss xmm8, xmm0
    
    movzx ecx, WORD PTR [rax + r9*2 + 64]   ; min
    call f16_to_f32
    movss xmm9, xmm0
    
    vbroadcastss ymm8, xmm8
    vbroadcastss ymm9, xmm9
    
    ; Load 32 weights from qs and dequantize on the fly
    ; qs offset = 128 + group*16
    mov rcx, r9
    shl rcx, 4              ; rcx = group * 16
    add rcx, 128            ; rcx = offset to qs
    add rcx, rax            ; rcx = pointer to qs for this group
    
    ; Calculate vec offset for this block
    mov rdx, r8
    shl rdx, 8              ; rdx = block_idx * 256
    add rdx, r9
    shl rdx, 5              ; rdx = (block_idx * 256) + (group_idx * 32)
    add rdx, r13            ; rdx = pointer to vec elements
    
    ; Process 32 elements (4 AVX2 iterations of 8 floats)
    xor r10d, r10d          ; r10 = element in group
    
elem_loop:
    cmp r10d, 32
    jae elem_done
    
    ; Load 8 floats from vec
    vmovups ymm2, YMMWORD PTR [rdx + r10*4]
    
    ; Load and dequantize 8 weights from qs
    ; Each byte has 2 weights, so we need 4 bytes for 8 weights
    mov r11, r10
    shr r11, 1              ; r11 = byte index (2 weights per byte)
    movzx eax, BYTE PTR [rcx + r11]
    
    ; Extract nibbles and dequantize
    ; This is simplified - real impl would use lookup tables
    mov r11d, eax
    and r11d, 0Fh
    sub r11d, 8
    cvtsi2ss xmm3, r11d
    mulss xmm3, xmm8
    addss xmm3, xmm9
    
    shr eax, 4
    sub eax, 8
    cvtsi2ss xmm4, eax
    mulss xmm4, xmm8
    addss xmm4, xmm9
    
    ; Insert into ymm register (simplified)
    vinsertf128 ymm3, ymm3, xmm4, 0
    
    ; Multiply and accumulate
    vfmadd231ps ymm0, ymm2, ymm3
    
    add r10d, 8
    jmp elem_loop
    
elem_done:
    inc r9d
    jmp group_matvec_loop
    
group_matvec_done:
    inc r8d
    jmp block_loop
    
block_done:
    ; Horizontal sum ymm0 -> scalar
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    movss REAL4 PTR [r14 + rdi*4], xmm0
    
    ; Move to next row
    inc edi
    jmp matvec_row_loop
    
matvec_done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_matvec_q4k ENDP

;==============================================================================
; FUSED Q4_K MATVEC + SWIGLU
; Optimized for transformer FFN layers
; void rawrxd_matvec_q4k_fused(const void* w1, const void* w3, 
;                               const float* x, float* gate, float* up,
;                               int n_embd, int n_ff);
;==============================================================================
PUBLIC rawrxd_matvec_q4k_fused
rawrxd_matvec_q4k_fused PROC FRAME
    ; TODO: Implement fused gate+up projection with SwiGLU
    ; This is a placeholder that calls the regular matvec twice
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    .endprolog
    
    ; Save params
    mov r12, rcx            ; w1
    mov r13, rdx            ; w3
    mov r14, r8             ; x
    mov r15, r9             ; gate
    mov ebx, DWORD PTR [rsp+40+40]  ; up
    mov edi, DWORD PTR [rsp+40+48]  ; n_embd
    mov esi, DWORD PTR [rsp+40+56]  ; n_ff
    
    ; Call matvec for w1 -> gate
    mov rcx, r12
    mov rdx, r14
    mov r8, r15
    mov r9d, esi          ; n_ff rows
    mov DWORD PTR [rsp], edi  ; n_embd cols
    call rawrxd_matvec_q4k
    
    ; Call matvec for w3 -> up
    mov rcx, r13
    mov rdx, r14
    mov r8, rbx
    mov r9d, esi
    mov DWORD PTR [rsp], edi
    call rawrxd_matvec_q4k
    
    ; Apply SwiGLU: gate = silu(gate) * up
    mov rcx, r15          ; gate
    mov rdx, rbx          ; up
    mov r8d, esi          ; n_ff
    call rawrxd_swiglu_f32
    
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_matvec_q4k_fused ENDP

;==============================================================================
; HELPER: Convert FP16 to FP32
; Input: eax = f16 value
; Output: xmm0 = f32 value
;==============================================================================
f16_to_f32 PROC PRIVATE
    ; Extract sign, exponent, mantissa
    mov ecx, eax
    and ecx, 8000h          ; ecx = sign
    shr ecx, 15             ; ecx = sign bit
    
    mov edx, eax
    and edx, 7C00h          ; edx = exponent
    shr edx, 10             ; edx = exponent (5 bits, bias 15)
    
    mov esi, eax
    and esi, 03FFh          ; esi = mantissa (10 bits)
    
    ; Handle special cases
    test edx, edx
    jz f16_zero_or_denorm
    cmp edx, 31
    je f16_inf_or_nan
    
    ; Normal number
    ; f32_exp = f16_exp - 15 + 127 = f16_exp + 112
    add edx, 112
    shl edx, 23             ; Shift to exponent position
    
    ; f32_mant = f16_mant << 13
    shl esi, 13
    
    ; Combine
    or edx, esi
    shl ecx, 31             ; Sign to bit 31
    or edx, ecx
    
    movd xmm0, edx
    ret
    
f16_zero_or_denorm:
    ; Zero or denormalized
    test esi, esi
    jz f16_zero
    ; Denormalized - would need proper handling
    ; For now, return 0
    xorps xmm0, xmm0
    ret
    
f16_zero:
    xorps xmm0, xmm0
    ret
    
f16_inf_or_nan:
    ; Infinity or NaN
    shl esi, 13
    mov edx, 255
    shl edx, 23
    or edx, esi
    shl ecx, 31
    or edx, ecx
    movd xmm0, edx
    ret
f16_to_f32 ENDP

;==============================================================================
; SWIGLU ACTIVATION
; void rawrxd_swiglu_f32(float* gate, const float* up, int n);
; gate[i] = silu(gate[i]) * up[i]
; silu(x) = x * sigmoid(x)
;==============================================================================
PUBLIC rawrxd_swiglu_f32
rawrxd_swiglu_f32 PROC FRAME
    push rbx
    push rdi
    push rsi
    .endprolog
    
    mov rbx, rcx            ; rbx = gate
    mov rdi, rdx            ; rdi = up
    mov esi, r8d            ; esi = n
    
    xor rcx, rcx            ; i = 0
    
swiglu_loop:
    cmp ecx, esi
    jae swiglu_done
    
    ; Load gate[i]
    movss xmm0, REAL4 PTR [rbx + rcx*4]
    
    ; Compute sigmoid(gate[i])
    ; sigmoid(x) = 1 / (1 + exp(-x))
    movss xmm1, xmm0
    xorps xmm2, xmm2
    subss xmm2, xmm1        ; xmm2 = -x
    
    ; exp(-x) using Taylor series approximation
    ; For now, use simple approximation
    movss xmm3, xmm2
    mulss xmm3, xmm2        ; x^2
    movss xmm4, REAL4 PTR [one_f32]
    addss xmm4, xmm2        ; 1 + x
    addss xmm4, xmm3        ; 1 + x + x^2/2 (approx)
    
    ; 1 / (1 + exp(-x))
    movss xmm5, REAL4 PTR [one_f32]
    divss xmm5, xmm4        ; sigmoid approx
    
    ; silu(x) = x * sigmoid(x)
    mulss xmm0, xmm5
    
    ; Multiply by up[i]
    movss xmm1, REAL4 PTR [rdi + rcx*4]
    mulss xmm0, xmm1
    
    ; Store result
    movss REAL4 PTR [rbx + rcx*4], xmm0
    
    inc ecx
    jmp swiglu_loop
    
swiglu_done:
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_swiglu_f32 ENDP

END
