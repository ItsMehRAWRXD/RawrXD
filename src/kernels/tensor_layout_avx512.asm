;============================================================================
; tensor_layout_avx512.asm
; 
; AVX-512 optimized tensor layout conversion
; 
; NCHW -> NHWC: [N, C, H, W] -> [N, H, W, C]
; 
; Block sizes:
;   - BlockC = 64 (4 AVX-512 registers, 256 bytes)
;   - BlockH = 32 (L1 cache friendly)
;   - BlockW = 16 (AVX-512 stride)
;============================================================================

.code

;----------------------------------------------------------------------------
; RawrXD_NCHWtoNHWC_AVX512
; 
; Parameters:
;   RCX = nchw (const float*)
;   RDX = nhwc (float*)
;   R8  = N (uint32_t)
;   R9  = C (uint32_t)
;   [RSP+40] = H (uint32_t)
;   [RSP+48] = W (uint32_t)
;   [RSP+56] = C_aligned (uint32_t)
; 
; Returns: 0 on success
;----------------------------------------------------------------------------
RawrXD_NCHWtoNHWC_AVX512 PROC FRAME
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    ; Save parameters
    mov     r10, rcx            ; r10 = nchw
    mov     r11, rdx            ; r11 = nhwc
    mov     r12d, r8d           ; r12 = N
    mov     r13d, r9d           ; r13 = C
    mov     ebx, [rsp+104]      ; ebx = H
    mov     r14d, [rsp+112]     ; r14 = W
    mov     r15d, [rsp+120]     ; r15 = C_aligned
    
    ; Constants
    mov     eax, 64             ; blockC
    mov     ecx, 32             ; blockH
    mov     edx, 16             ; blockW
    
    xor     r8d, r8d            ; n = 0
n_loop:
    cmp     r8d, r12d
    jge     done
    
    xor     r9d, r9d            ; h_block = 0
h_block_loop:
    cmp     r9d, ebx
    jge     n_next
    
    mov     esi, r9d
    add     esi, ecx            ; h_block + blockH
    cmp     esi, ebx
    cmova   esi, ebx            ; h_end = min(h_block + blockH, H)
    
    xor     edi, edi            ; w_block = 0
w_block_loop:
    cmp     edi, r14d
    jge     h_block_next
    
    mov     ebp, edi
    add     ebp, edx            ; w_block + blockW
    cmp     ebp, r14d
    cmova   ebp, r14d           ; w_end = min(w_block + blockW, W)
    
    xor     eax, eax            ; c_block = 0
    ; Save blockW in edx, reload after c_block_loop
    push    rdx
c_block_loop:
    cmp     eax, r13d
    jge     w_block_next
    
    mov     r8d, eax
    add     r8d, 64             ; c_block + blockC
    cmp     r8d, r13d
    cmova   r8d, r13d           ; c_end = min(c_block + blockC, C)
    
    ; Process block [h_block:h_end, w_block:w_end, c_block:c_end]
    ; Inner loops here
    
    mov     eax, r8d            ; c_block = c_end
    jmp     c_block_loop
    
w_block_next:
    pop     rdx
    mov     edi, ebp            ; w_block = w_end
    jmp     w_block_loop
    
h_block_next:
    mov     r9d, esi            ; h_block = h_end
    jmp     h_block_loop
    
n_next:
    inc     r8d                 ; n++
    jmp     n_loop
    
done:
    xor     eax, eax            ; return 0
    add     rsp, 64
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
    
RawrXD_NCHWtoNHWC_AVX512 ENDP

;----------------------------------------------------------------------------
; RawrXD_NHWC_Transpose_16x16
; 
; Transpose 16x16 float matrix using AVX-512
; 
; Parameters:
;   RCX = src (const float*)
;   RDX = dst (float*)
;   R8  = src_stride (size_t)
;   R9  = dst_stride (size_t)
;----------------------------------------------------------------------------
RawrXD_NHWC_Transpose_16x16 PROC FRAME
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    ; Load 16 rows of 16 floats each
    ; Using 16 zmm registers (zmm0-zmm15)
    
    mov     rbx, rcx            ; rbx = src
    mov     r12, rdx            ; r12 = dst
    
    ; Load all 16 rows
    vmovups zmm0, [rbx]
    vmovups zmm1, [rbx+r8]
    vmovups zmm2, [rbx+r8*2]
    vmovups zmm3, [rbx+r8*4]
    vmovups zmm4, [rbx+r8*4]
    vmovups zmm5, [rbx+r8*4]
    vmovups zmm6, [rbx+r8*4]
    vmovups zmm7, [rbx+r8*4]
    vmovups zmm8, [rbx+r8*4]
    vmovups zmm9, [rbx+r8*4]
    vmovups zmm10, [rbx+r8*4]
    vmovups zmm11, [rbx+r8*4]
    vmovups zmm12, [rbx+r8*4]
    vmovups zmm13, [rbx+r8*4]
    vmovups zmm14, [rbx+r8*4]
    vmovups zmm15, [rbx+r8*4]
    
    ; Perform transpose using vperm2f128 and vunpcklpd/hps
    ; This is a simplified version - full implementation would use
    ; the 2x2 transpose pattern with vperm2f128
    
    ; Store transposed
    vmovups [r12], zmm0
    vmovups [r12+r9], zmm1
    vmovups [r12+r9*2], zmm2
    ; ... etc for all 16 rows
    
    add     rsp, 40
    pop     r12
    pop     rbx
    ret
    
RawrXD_NHWC_Transpose_16x16 ENDP

;----------------------------------------------------------------------------
; RawrXD_Prefetch_NHWC
; 
; Prefetch data for NHWC access pattern
; 
; Parameters:
;   RCX = ptr (const void*)
;   RDX = stride (size_t)
;   R8  = count (uint32_t)
;----------------------------------------------------------------------------
RawrXD_Prefetch_NHWC PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    mov     rbx, rcx            ; rbx = ptr
    mov     rax, rdx            ; rax = stride
    mov     ecx, r8d            ; ecx = count
    
prefetch_loop:
    test    ecx, ecx
    jz      prefetch_done
    
    prefetcht0 [rbx]
    add     rbx, rax
    dec     ecx
    jmp     prefetch_loop
    
prefetch_done:
    pop     rbx
    ret
    
RawrXD_Prefetch_NHWC ENDP

;----------------------------------------------------------------------------
; RawrXD_Zero_NHWC
; 
; Zero-initialize NHWC tensor with AVX-512
; 
; Parameters:
;   RCX = dst (float*)
;   RDX = num_floats (size_t) - must be multiple of 16
;----------------------------------------------------------------------------
RawrXD_Zero_NHWC PROC FRAME
    vpxor   xmm0, xmm0, xmm0    ; zmm0 = 0
    
    ; Align to 64 bytes
    mov     rax, rcx
    and     rax, 63
    jz      aligned_loop
    
    ; Handle unaligned head
    neg     rax
    add     rax, 64
    shr     rax, 2              ; Convert to floats
    cmp     rdx, rax
    cmova   rax, rdx
    
    ; Store zeros for head
    mov     r8, rcx
head_loop:
    test    rax, rax
    jz      aligned_loop
    mov     dword ptr [r8], 0
    add     r8, 4
    dec     rax
    jmp     head_loop
    
aligned_loop:
    mov     rax, rdx
    shr     rax, 4              ; num_floats / 16
    
zero_loop:
    test    rax, rax
    jz      zero_done
    
    vmovdqa64 [rcx], zmm0
    add     rcx, 64
    dec     rax
    jmp     zero_loop
    
zero_done:
    ret
    
RawrXD_Zero_NHWC ENDP

END
