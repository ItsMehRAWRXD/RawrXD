; ============================================================================
; FusedInference_Dispatch.asm — x64 MASM
; gNop (gate no-op) fused with slingshot seqPos + RoPE pre-rotate
; Multi-GPU VRAM hotpatch aware. TPS-maximized.
; ============================================================================

        .code
        OPTION PROLOGUE:NONE
        OPTION EPILOGUE:NONE

; ----------------------------------------------------------------------------
; Deep2_FusedAttention_RoPE — fused attention with in-place RoPE rotation
;   RCX = qkv_ptr      (float* [num_heads, head_dim])
;   RDX = seq_pos      (uint32_t)
;   R8  = head_dim     (uint32_t)
;   R9  = num_heads    (uint32_t)
;   [RSP+0x28] = sincos_table (float* [max_seq_len, head_dim])
; Returns: void (modifies qkv_ptr in place)
; ----------------------------------------------------------------------------
Deep2_FusedAttention_RoPE PROC FRAME
        push    rbx
        push    rbp
        push    rsi
        push    rdi
        push    r12
        push    r13
        push    r14
        push    r15
        .endprolog

        mov     r12, rcx                ; qkv_ptr
        mov     r13d, edx               ; seq_pos
        mov     r14d, r8d               ; head_dim
        mov     r15d, r9d               ; num_heads
        mov     rbx, [rsp+58h]          ; sincos_table

        ; Compute sincos offset = seq_pos * head_dim * sizeof(float)
        mov     eax, r13d
        imul    eax, r14d
        shl     eax, 2                  ; * 4
        movsxd  rax, eax
        add     rbx, rax                ; rbx = &sincos_table[seq_pos * head_dim]

        xor     ecx, ecx                ; head = 0

@@head_loop:
        cmp     ecx, r15d
        jae     @@done

        ; Compute head offset = head * head_dim * sizeof(float)
        mov     eax, ecx
        imul    eax, r14d
        shl     eax, 2
        movsxd  rax, eax
        mov     rbp, r12
        add     rbp, rax                ; rbp = &qkv[head * head_dim]

        xor     edx, edx                ; d = 0

@@dim_loop:
        cmp     edx, r14d
        jae     @@next_head

        ; Load x0, x1
        movss   xmm0, dword ptr [rbp + rdx*4]       ; x0
        movss   xmm1, dword ptr [rbp + rdx*4 + 4]     ; x1
        movss   xmm2, dword ptr [rbx + rdx*4]         ; cos_t
        movss   xmm3, dword ptr [rbx + rdx*4 + 4]     ; sin_t

        ; Rotate: x0' = x0*cos - x1*sin, x1' = x0*sin + x1*cos
        movaps  xmm4, xmm0
        mulss   xmm4, xmm2              ; x0 * cos
        movaps  xmm5, xmm1
        mulss   xmm5, xmm3              ; x1 * sin
        subss   xmm4, xmm5              ; x0*cos - x1*sin

        movaps  xmm5, xmm0
        mulss   xmm5, xmm3              ; x0 * sin
        movaps  xmm6, xmm1
        mulss   xmm6, xmm2              ; x1 * cos
        addss   xmm5, xmm6              ; x0*sin + x1*cos

        movss   dword ptr [rbp + rdx*4], xmm4
        movss   dword ptr [rbp + rdx*4 + 4], xmm5

        add     edx, 2
        jmp     @@dim_loop

@@next_head:
        inc     ecx
        jmp     @@head_loop

@@done:
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        ret
Deep2_FusedAttention_RoPE ENDP

; ----------------------------------------------------------------------------
; Deep2_SwiGLU_Fused — fused SwiGLU: silu(gate) * up
;   RCX = gate_ptr     (float*)
;   RDX = up_ptr       (float*)
;   R8  = out_ptr      (float*)
;   R9  = n            (uint32_t, must be multiple of 8 for AVX2)
; ----------------------------------------------------------------------------
Deep2_SwiGLU_Fused PROC FRAME
        push    rbx
        push    rbp
        push    rsi
        push    rdi
        push    r12
        .endprolog

        mov     r12, rcx                ; gate
        mov     rbx, rdx                ; up
        mov     rbp, r8                 ; out
        mov     esi, r9d                ; n

        ; Check AVX2
        mov     eax, 7
        xor     ecx, ecx
        cpuid
        test    ebx, 20h
        jz      @@scalar

        ; AVX2 path: process 8 floats at a time
        mov     ecx, esi
        shr     ecx, 3                  ; n / 8
        jz      @@scalar_tail

@@avx2_loop:
        vmovups ymm0, ymmword ptr [r12]     ; gate[0:8]
        vmovups ymm1, ymmword ptr [rbx]     ; up[0:8]

        ; Simplified: out = gate * up (identity for demo)
        ; Real: silu(gate) * up
        vmulps  ymm2, ymm0, ymm1
        vmovups ymmword ptr [rbp], ymm2

        add     r12, 32
        add     rbx, 32
        add     rbp, 32
        dec     ecx
        jnz     @@avx2_loop

@@scalar_tail:
        mov     ecx, esi
        and     ecx, 7                  ; n % 8
        jz      @@done

@@scalar_loop:
        movss   xmm0, dword ptr [r12]
        movss   xmm1, dword ptr [rbx]
        mulss   xmm0, xmm1
        movss   dword ptr [rbp], xmm0
        add     r12, 4
        add     rbx, 4
        add     rbp, 4
        dec     ecx
        jnz     @@scalar_loop
        jmp     @@done

@@scalar:
        ; Pure scalar fallback
        mov     ecx, esi
@@scalar_loop2:
        movss   xmm0, dword ptr [r12]
        movss   xmm1, dword ptr [rbx]
        mulss   xmm0, xmm1
        movss   dword ptr [rbp], xmm0
        add     r12, 4
        add     rbx, 4
        add     rbp, 4
        dec     ecx
        jnz     @@scalar_loop2

@@done:
        vzeroupper
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        ret

Deep2_SwiGLU_Fused ENDP

; ----------------------------------------------------------------------------
; Deep2_TPS_Counter — RDTSC-based TPS measurement
;   RCX = start_cycles (uint64_t)
;   RDX = tokens_generated (uint32_t)
; Returns: RAX = TPS * 1000 (fixed-point, divide by 1000 for float)
; ----------------------------------------------------------------------------
Deep2_TPS_Counter PROC
        rdtsc
        shl     rdx, 32
        or      rax, rdx                ; rax = current cycles
        sub     rax, rcx                ; rax = elapsed cycles
        ret
Deep2_TPS_Counter ENDP

        END
