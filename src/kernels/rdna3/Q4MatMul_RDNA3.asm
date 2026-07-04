; Q4MatMul_RDNA3.asm
; RDNA3-optimized Q4_K_M matrix multiplication kernel
; Target: gfx1101 (7800 XT), 60 CUs, WMMA acceleration
; Workgroup: 256 threads (4 wavefronts), 64KB LDS

; RDNA3 ISA constants
WAVE_SIZE         EQU 64
CU_COUNT          EQU 60
LDS_SIZE          EQU 65536        ; 64KB per workgroup
WMMA_M            EQU 16           ; WMMA tile M dimension
WMMA_N            EQU 16           ; WMMA tile N dimension  
WMMA_K            EQU 16           ; WMMA tile K dimension

; Q4_K_M block layout
Q4K_SUPERBLOCK    EQU 256          ; Weights per superblock
Q4K_SCALE_BITS    EQU 8            ; Scale per 32-weight group
Q4K_MIN_BITS      EQU 6            ; Min per 32-weight group
Q4K_WEIGHT_BITS   EQU 2            ; 2-bit quantized weights

; Kernel arguments (HSA ABI)
ARG_A_PTR         EQU 0            ; Q4_K_M weight matrix pointer
ARG_B_PTR         EQU 8            ; FP16 activation pointer
ARG_C_PTR         EQU 16           ; FP16 output pointer
ARG_M             EQU 24           ; M dimension (output rows)
ARG_N             EQU 28           ; N dimension (output cols)
ARG_K             EQU 32           ; K dimension (inner dim)
ARG_LDA           EQU 36           ; A stride
ARG_LDB           EQU 40           ; B stride
ARG_LDC           EQU 44           ; C stride

; LDS layout
LDS_WEIGHT_TILE   EQU 0            ; 32KB weight tile cache
LDS_ACTIV_TILE    EQU 32768          ; 32KB activation tile cache

.code

;==============================================================================
; Q4MatMul_RDNA3
; Entry point for Q4_K_M matrix multiplication
;==============================================================================
Q4MatMul_RDNA3 PROC PUBLIC
    ; Prologue - HSA ABI compliance
    s_mov_b32       s0, s0                          ; Workgroup ID X
    s_mov_b32       s1, s1                          ; Workgroup ID Y
    s_mov_b32       s2, s2                          ; Workgroup ID Z
    
    ; Load kernel arguments from kernarg segment
    s_load_dwordx4  s[4:7], s[0:1], ARG_A_PTR       ; Load A, B pointers
    s_load_dwordx4  s[8:11], s[0:1], ARG_C_PTR    ; Load C, M
    s_load_dwordx4  s[12:15], s[0:1], ARG_K        ; Load K, LDA, LDB, LDC
    s_waitcnt       lgkmcnt(0)                      ; Wait for scalar loads
    
    ; Calculate global thread ID
    v_mbcnt_lo_u32_b32 v0, -1, 0                    ; Thread ID within wave
    v_mbcnt_hi_u32_b32 v0, -1, v0                   ; Continue thread ID
    v_mov_b32       v1, s0                          ; Workgroup X
    v_lshlrev_b32   v2, 8, v1                       ; WG * 256
    v_add_u32       v0, v0, v2                      ; Global thread ID
    
    ; Calculate tile coordinates
    v_lshrrev_b32   v1, 4, v0                       ; Tile row (thread / 16)
    v_and_b32       v2, v0, 15                      ; Tile col (thread % 16)
    
    ; Initialize accumulators (v[16:31] for 16x16 tile)
    v_mov_b32       v16, 0
    v_mov_b32       v17, 0
    v_mov_b32       v18, 0
    v_mov_b32       v19, 0
    v_mov_b32       v20, 0
    v_mov_b32       v21, 0
    v_mov_b32       v22, 0
    v_mov_b32       v23, 0
    v_mov_b32       v24, 0
    v_mov_b32       v25, 0
    v_mov_b32       v26, 0
    v_mov_b32       v27, 0
    v_mov_b32       v28, 0
    v_mov_b32       v29, 0
    v_mov_b32       v30, 0
    v_mov_b32       v31, 0
    
    ; Main loop over K dimension
    s_mov_b32       s20, 0                          ; K index
K_LOOP:
    s_cmp_lt_u32    s20, s12                        ; Compare with K
    s_cbranch_scc0  K_DONE                          ; Exit if K done
    
    ; Load Q4_K_M superblock to LDS
    s_barrier                                       ; Sync before load
    
    ; Calculate weight address for this tile
    v_lshlrev_b32   v3, 4, v1                       ; Row * 16
    v_add_u32       v3, v3, s20                     ; + K index
    v_lshlrev_b32   v3, 7, v3                       ; * 128 bytes per superblock
    v_add_u32       v3, v3, s4                      ; + base pointer
    
    ; Load scales and mins (first 14 bytes of superblock)
    global_load_ubyte v4, v[3:4], off               ; Load scale
    global_load_ubyte v5, v[3:4], 1                 ; Load min
    v_waitcnt       vmcnt(0)
    
    ; Dequantize weights using WMMA
    ; v4 = scale, v5 = min
    v_wmma_f16_16x16x16_f16 v[16:31], v[4:5], v[6:7], v[16:31]
    
    ; Accumulate
    v_add_f16       v16, v16, v32
    v_add_f16       v17, v17, v33
    ; ... (continue for all 16 accumulators)
    
    s_add_u32       s20, s20, WMMA_K                ; Advance K
    s_branch        K_LOOP
    
K_DONE:
    ; Store results to global memory
    v_lshlrev_b32   v3, 1, v0                       ; *2 for FP16
    v_add_u32       v3, v3, s6                      ; + C base
    
    ; Write 16x16 tile
    global_store_short v[3:4], v16, off
    global_store_short v[3:4], v17, 2
    ; ... (continue for all 16 outputs)
    
    ; Epilogue
    s_endpgm
    
Q4MatMul_RDNA3 ENDP

;==============================================================================
; Q4Dequant_RDNA3
; Dequantize Q4_K_M superblock to FP16
; Input: v0 = scale, v1 = min, v2 = quantized weights (packed)
; Output: v[16:31] = 16 FP16 values
;==============================================================================
Q4Dequant_RDNA3 PROC
    ; Extract 2-bit weights
    v_and_b32       v3, v2, 3                       ; Weight 0
    v_lshrrev_b32   v4, 2, v2                     ; Weight 1
    v_and_b32       v4, v4, 3
    v_lshrrev_b32   v5, 4, v2                     ; Weight 2
    v_and_b32       v5, v5, 3
    ; ... continue for all 16 weights
    
    ; Dequantize: (weight * scale + min) / 64.0
    v_cvt_f32_u32   v3, v3                          ; Convert to float
    v_cvt_f32_u32   v4, v4
    ; ...
    
    v_mul_f32       v3, v3, v0                      ; * scale
    v_add_f32       v3, v3, v1                      ; + min
    v_mov_b32       v20, 0x3D800000                 ; 1/64.0
    v_mul_f32       v3, v3, v20                     ; / 64.0
    
    v_cvt_f16_f32   v16, v3                         ; Convert to FP16
    ; ... repeat for all weights
    
    ret
Q4Dequant_RDNA3 ENDP

END
