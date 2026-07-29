;==============================================================================
; rawrxd_tensor_masm.inc - MASM x64 Tensor Operations Header
; Pure x64 MASM - Zero dependencies on GGML or external libraries
;==============================================================================

;==============================================================================
; CONSTANTS
;==============================================================================
RAWRXD_TYPE_F32     EQU 0
RAWRXD_TYPE_F16     EQU 1
RAWRXD_TYPE_Q4_0    EQU 2
RAWRXD_TYPE_Q4_1    EQU 3
RAWRXD_TYPE_Q5_0    EQU 6
RAWRXD_TYPE_Q5_1    EQU 7
RAWRXD_TYPE_Q8_0    EQU 8
RAWRXD_TYPE_Q2_K    EQU 14
RAWRXD_TYPE_Q3_K    EQU 15
RAWRXD_TYPE_Q4_K    EQU 16
RAWRXD_TYPE_Q5_K    EQU 17
RAWRXD_TYPE_Q6_K    EQU 18

; Q4_K_M block structure
Q4K_BLOCK_SIZE      EQU 144
Q4K_SUPERBLOCK_SIZE EQU 256

;==============================================================================
; STRUCTURES
;==============================================================================

; Q4_K_M block: 256 weights in 144 bytes
; scales[32] (f16), mins[32] (f16), qs[128] (4-bit packed)
Q4K_BLOCK STRUCT
    scales  DW 32 DUP(?)    ; 64 bytes - f16 scales
    mins    DW 32 DUP(?)    ; 64 bytes - f16 mins  
    qs      DB 128 DUP(?)   ; 16 bytes - packed 4-bit weights
Q4K_BLOCK ENDS

; Tensor descriptor
TENSOR STRUCT
    data        DQ ?        ; Pointer to data
    type_       DD ?        ; RAWRXD_TYPE_*
    num_elems   DQ 4 DUP(?) ; Dimensions [ne0, ne1, ne2, ne3]
    byte_strides DQ 4 DUP(?); Byte strides [nb0, nb1, nb2, nb3]
    name        DB 64 DUP(?); Tensor name
TENSOR ENDS

; Context for tensor operations
TENSOR_CTX STRUCT
    scratch     DQ ?        ; Scratch buffer pointer
    scratch_size DQ ?      ; Scratch buffer size
    n_threads   DD ?        ; Number of threads to use
    flags       DD ?        ; Context flags
TENSOR_CTX ENDS

; KV Cache entry
KV_CACHE_ENTRY STRUCT
    k_ptr       DQ ?        ; Key cache pointer
    v_ptr       DQ ?        ; Value cache pointer
    seq_len     DD ?        ; Current sequence length
    max_len     DD ?        ; Maximum sequence length
KV_CACHE_ENTRY ENDS

;==============================================================================
; MACROS
;==============================================================================

; Horizontal sum of ymm register into xmm0
HSUM_YMM MACRO reg
    vextractf128 xmm1, reg, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
ENDM

; Horizontal sum of zmm register into xmm0  
HSUM_ZMM MACRO reg
    vextractf32x8 ymm1, reg, 1
    vaddps ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
ENDM

; Load aligned or unaligned based on flag
VMOVAPS_OR_U MACRO dst, src, aligned
    IF aligned
        vmovaps dst, src
    ELSE
        vmovups dst, src
    ENDIF
ENDM

;==============================================================================
; EXTERNS - Windows API
;==============================================================================
EXTERNDEF VirtualAlloc:PROC
EXTERNDEF VirtualFree:PROC
EXTERNDEF VirtualProtect:PROC
EXTERNDEF GetCurrentThread:PROC
EXTERNDEF SetThreadAffinityMask:PROC
EXTERNDEF QueryPerformanceCounter:PROC
EXTERNDEF QueryPerformanceFrequency:PROC

;==============================================================================
; FUNCTION PROTOTYPES
;==============================================================================

;------------------------------------------------------------------------------
; MATH OPERATIONS (rawrxd_math_masm.asm)
;------------------------------------------------------------------------------
EXTERNDEF rawrxd_dot_f32:PROC
EXTERNDEF rawrxd_matvec_f32:PROC
EXTERNDEF rawrxd_matmul_f32:PROC
EXTERNDEF rawrxd_rms_norm_f32:PROC
EXTERNDEF rawrxd_layer_norm_f32:PROC
EXTERNDEF rawrxd_softmax_f32:PROC
EXTERNDEF rawrxd_silu_f32:PROC
EXTERNDEF rawrxd_gelu_f32:PROC
EXTERNDEF rawrxd_add_f32:PROC
EXTERNDEF rawrxd_mul_f32:PROC
EXTERNDEF rawrxd_scale_f32:PROC

;------------------------------------------------------------------------------
; QUANTIZATION OPERATIONS (rawrxd_quant_masm.asm)
;------------------------------------------------------------------------------
EXTERNDEF rawrxd_dequantize_q4k:PROC
EXTERNDEF rawrxd_dequantize_q4k_row:PROC
EXTERNDEF rawrxd_matvec_q4k:PROC
EXTERNDEF rawrxd_matvec_q4k_fused:PROC

;------------------------------------------------------------------------------
; TRANSFORMER OPERATIONS (rawrxd_transformer_masm.asm)
;------------------------------------------------------------------------------
EXTERNDEF rawrxd_transformer_layer:PROC
EXTERNDEF rawrxd_rope_f32:PROC
EXTERNDEF rawrxd_attention_fwd:PROC
EXTERNDEF rawrxd_ffn_swiglu:PROC
EXTERNDEF rawrxd_kv_cache_update:PROC
EXTERNDEF rawrxd_kv_cache_retrieve:PROC

;------------------------------------------------------------------------------
; SAMPLING OPERATIONS (rawrxd_sampler_masm.asm)
;------------------------------------------------------------------------------
EXTERNDEF rawrxd_sample_argmax:PROC
EXTERNDEF rawrxd_sample_topk:PROC
EXTERNDEF rawrxd_sample_topp:PROC
EXTERNDEF rawrxd_sample_temperature:PROC

;==============================================================================
; DATA SECTION
;==============================================================================
.DATA

; Constants for math operations
ALIGN 4
rms_norm_eps_f      REAL4 1.0e-6
layer_norm_eps_f    REAL4 1.0e-5
sqrt_2_over_pi      REAL4 0.7978845608    ; For GELU

; RoPE frequency constants
ALIGN 4
rope_theta_f        REAL4 10000.0
rope_inv_theta_f    REAL4 0.0001

; Lookup tables
ALIGN 16
exp_lut             REAL4 256 DUP(0.0)    ; Exponential lookup (initialized at runtime)

; AVX2/AVX-512 constants
ALIGN 16
sign_mask_f32       DD 8 DUP(7FFFFFFFh)   ; Abs value mask
one_f32             DD 8 DUP(3F800000h)    ; 1.0f
half_f32            DD 8 DUP(3F000000h)    ; 0.5f

; Q4_K dequantization tables
ALIGN 16
q4k_nibble_mask     DB 16 DUP(0Fh)         ; Low nibble mask
q4k_sign_extend     DB 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15

; Thread-local storage for scratch buffers
ALIGN 8
tls_scratch_ptr     DQ 0
tls_scratch_size    DQ 0

.CODE
