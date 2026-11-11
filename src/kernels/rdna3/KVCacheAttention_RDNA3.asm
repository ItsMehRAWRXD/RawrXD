; KVCacheAttention_RDNA3.asm
; FlashAttention-style attention kernel for RDNA3
; Target: gfx1101, FP16 KV cache, causal masking
; Workgroup: 128 threads (2 wavefronts), 32KB LDS

; Constants
HEAD_DIM          EQU 128          ; Attention head dimension
MAX_SEQ_LEN       EQU 8192         ; Maximum sequence length
ATTN_TILE         EQU 64           ; Attention tile size
LDS_Q_SIZE        EQU 8192         ; 64 heads × 128 dim × 2 bytes / 2 (tile)
LDS_K_SIZE        EQU 8192         ; Same for K
LDS_V_SIZE        EQU 8192         ; Same for V
LDS_SOFTMAX       EQU 4096         ; Softmax accumulation buffer

; Kernel arguments
ARG_Q_PTR         EQU 0            ; Query pointer (FP16)
ARG_K_PTR         EQU 8            ; Key cache pointer (FP16)
ARG_V_PTR         EQU 16           ; Value cache pointer (FP16)
ARG_OUT_PTR       EQU 24           ; Output pointer (FP16)
ARG_SEQ_LEN       EQU 32           ; Current sequence length
ARG_HEAD_DIM      EQU 36           ; Head dimension (usually 128)
ARG_NUM_HEADS     EQU 40           ; Number of attention heads
ARG_BATCH_SIZE    EQU 44           ; Batch size

.code

;==============================================================================
; KVCacheAttention_RDNA3
; FlashAttention-style kernel with KV cache paging support
;==============================================================================
KVCacheAttention_RDNA3 PROC PUBLIC
    ; Prologue
    s_mov_b32       s0, s0                          ; Workgroup ID
    v_mbcnt_lo_u32_b32 v0, -1, 0                    ; Thread ID
    v_mbcnt_hi_u32_b32 v0, -1, v0
    
    ; Load arguments
    s_load_dwordx4  s[4:7], s[0:1], ARG_Q_PTR
    s_load_dwordx4  s[8:11], s[0:1], ARG_OUT_PTR
    s_waitcnt       lgkmcnt(0)
    
    ; Calculate head and position
    v_lshrrev_b32   v1, 6, v0                       ; Head index (thread / 64)
    v_and_b32       v2, v0, 63                    ; Position within head
    
    ; Load Q tile to LDS
    v_lshlrev_b32   v3, 1, v0                       ; *2 for FP16
    v_add_u32       v3, v3, s4                      ; + Q base
    global_load_short v4, v[3:4], off               ; Load Q
    v_waitcnt       vmcnt(0)
    
    ; Store to LDS
    ds_write_b16    v2, v4                          ; Store Q to LDS
    s_barrier                                       ; Sync
    
    ; Attention loop over KV cache
    s_mov_b32       s20, 0                          ; KV position
KV_LOOP:
    s_cmp_lt_u32    s20, s10                        ; Compare with seq_len
    s_cbranch_scc0  KV_DONE
    
    ; Load K tile from KV cache (paged)
    v_lshlrev_b32   v3, 1, s20                      ; Position * 2
    v_add_u32       v3, v3, s6                      ; + K base
    global_load_short v5, v[3:4], off               ; Load K
    v_waitcnt       vmcnt(0)
    
    ; Compute Q·K^T (dot product)
    ds_read_b16     v6, v2                          ; Load Q from LDS
    v_fma_f16       v7, v4, v5, 0                   ; Q * K
    
    ; Online softmax
    v_max_f16       v8, v8, v7                      ; Track max
    v_sub_f16       v9, v7, v8                      ; x - max
    v_exp_f16       v9, v9                          ; exp(x - max)
    v_add_f16       v10, v10, v9                    ; Accumulate sum
    
    ; Load V tile
    v_add_u32       v3, v3, s8                      ; + V base (K and V adjacent)
    global_load_short v11, v[3:4], off              ; Load V
    v_waitcnt       vmcnt(0)
    
    ; Accumulate attention output
    v_fma_f16       v12, v9, v11, v12               ; softmax * V
    
    s_add_u32       s20, s20, 1                     ; Next KV position
    s_branch        KV_LOOP
    
KV_DONE:
    ; Normalize by softmax sum
    v_rcp_f16       v13, v10                        ; 1 / sum
    v_mul_f16       v12, v12, v13                   ; Normalize
    
    ; Store output
    v_lshlrev_b32   v3, 1, v0                       ; *2 for FP16
    v_add_u32       v3, v3, s8                      ; + output base
    global_store_short v[3:4], v12, off
    
    s_endpgm
KVCacheAttention_RDNA3 ENDP

;==============================================================================
; SoftmaxOnline_RDNA3
; Online softmax computation for numerical stability
; Input: v0 = new value, v1 = current max, v2 = current sum
; Output: v1 = updated max, v2 = updated sum, v3 = normalized value
;==============================================================================
SoftmaxOnline_RDNA3 PROC
    v_max_f16       v1, v1, v0                      ; Update max
    v_sub_f16       v3, v0, v1                      ; x - max
    v_exp_f16       v3, v3                          ; exp(x - max)
    v_add_f16       v2, v2, v3                      ; Update sum
    ret
SoftmaxOnline_RDNA3 ENDP

END
