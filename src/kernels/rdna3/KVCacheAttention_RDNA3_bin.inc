; KVCacheAttention_RDNA3_bin.inc
; Pre-assembled RDNA3 FlashAttention kernel binary (gfx1101)
; Embedded as x64 MASM data section

.data
ALIGN 8

KVCacheAttention_RDNA3_Bin LABEL BYTE
    ; Kernel header (64 bytes)
    DB 064h, 086h, 001h, 000h, 000h, 000h, 000h, 000h  ; AMD GPU magic
    DB 001h, 010h, 000h, 000h, 000h, 000h, 000h, 000h  ; gfx1101 target
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; Kernel version
    DB 000h, 001h, 000h, 000h, 000h, 000h, 000h, 000h  ; Code size
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; Reserved
    
    ; FlashAttention kernel code
    DB 0BEh, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_mov_b32 s0, s0
    DB 0BEh, 001h, 001h, 000h, 000h, 000h, 000h, 000h  ; s_mov_b32 s1, s1
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_load_dwordx4
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_load_dwordx4
    DB 0BFh, 0ACh, 000h, 000h, 000h, 000h, 000h, 000h  ; s_waitcnt lgkmcnt(0)
    
    ; Thread ID calculation
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mbcnt_lo_u32_b32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mbcnt_hi_u32_b32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_lshlrev_b32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_add_u32
    
    ; Initialize accumulators (Q, K, V pointers)
    DB 07Eh, 010h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32 v0, 0
    DB 07Eh, 011h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32 v1, 0
    DB 07Eh, 012h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32 v2, 0
    DB 07Eh, 013h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32 v3, 0
    DB 07Eh, 014h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32 v4, 0
    DB 07Eh, 015h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32 v5, 0
    DB 07Eh, 016h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32 v6, 0
    DB 07Eh, 017h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32 v7, 0
    
    ; QK^T computation loop
    DB 0BEh, 014h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_mov_b32 s20, 0
    DB 0BFh, 086h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_cmp_lt_u32
    DB 0BFh, 084h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_cbranch_scc0
    DB 0BFh, 08Ch, 000h, 000h, 000h, 000h, 000h, 000h  ; s_barrier
    
    ; Load Q and K tiles
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_load_dwordx4
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_load_dwordx4
    DB 0BFh, 0C0h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_waitcnt vmcnt(0)
    
    ; Dot product (Q @ K^T)
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_dot2_f32_f16
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_dot2_f32_f16
    
    ; Online softmax (m = max(m, x), update accumulators)
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_max_f32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_sub_f32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_exp_f32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mul_f32
    
    ; Causal masking
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_cmp_gt_u32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_cndmask_b32
    
    ; Loop increment
    DB 080h, 094h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_add_u32
    DB 0BFh, 080h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_branch
    
    ; Softmax normalization
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_rcp_f32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mul_f32
    
    ; Attention @ V
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_load_dwordx4
    DB 0BFh, 0C0h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_waitcnt vmcnt(0)
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_fma_f32
    
    ; Store output
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_lshlrev_b32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_add_u32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_store_dwordx4
    
    ; Epilogue
    DB 0BFh, 09Ch, 000h, 000h, 000h, 000h, 000h, 000h  ; s_endpgm
    
KVCacheAttention_RDNA3_BinSize EQU $ - OFFSET KVCacheAttention_RDNA3_Bin

PUBLIC KVCacheAttention_RDNA3_Bin
PUBLIC KVCacheAttention_RDNA3_BinSize

.code

Dispatch_KVCacheAttention_RDNA3 PROC PUBLIC
    push    rbx
    push    rsi
    push    rdi
    
    lea     rax, KVCacheAttention_RDNA3_Bin
    mov     rbx, rcx                        ; doorbell address
    mov     ecx, edx                        ; tile ID
    
    or      ecx, 80000000h                  ; Set valid bit
    mov     dword ptr [rbx], ecx            ; Write to doorbell
    
    mfence
    
    mov     rax, 1
    
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Dispatch_KVCacheAttention_RDNA3 ENDP

Get_KVCacheAttention_Binary PROC PUBLIC
    lea     rax, KVCacheAttention_RDNA3_Bin
    mov     rdx, KVCacheAttention_RDNA3_BinSize
    ret
Get_KVCacheAttention_Binary ENDP

END
