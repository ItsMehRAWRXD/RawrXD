; =============================================================================
; masm_kernel_api.inc - Unified Kernel API for RawrXD MASM Runtime
; =============================================================================
; This include file defines the public API surface for all MASM acceleration
; kernels. Every kernel follows the Microsoft x64 calling convention:
;   RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
;   RAX = return value (0 = success, non-zero = error code)
;
; Non-volatile registers (RBX, RBP, RDI, RSI, R12-R15) MUST be preserved.
; Volatile registers (RAX, RCX, RDX, R8-R11, XMM0-XMM5) may be clobbered.
; =============================================================================

IFNDEF MASM_KERNEL_API_INC
MASM_KERNEL_API_INC EQU 1

; =============================================================================
; Error Codes
; =============================================================================
KERNEL_SUCCESS          EQU 0
KERNEL_ERR_NULL_PTR     EQU 1
KERNEL_ERR_ZERO_SIZE    EQU 2
KERNEL_ERR_MISALIGN     EQU 3
KERNEL_ERR_BAD_SIZE     EQU 4
KERNEL_ERR_UNSUPPORTED  EQU 5
KERNEL_ERR_OOM          EQU 6

; =============================================================================
; Quantization Types
; =============================================================================
QUANT_F32               EQU 0
QUANT_F16               EQU 1
QUANT_Q4_0              EQU 2
QUANT_Q4_1              EQU 3
QUANT_Q5_0              EQU 4
QUANT_Q5_1              EQU 5
QUANT_Q8_0              EQU 6
QUANT_Q8_1              EQU 7

; =============================================================================
; Tensor Dtypes
; =============================================================================
DTYPE_F32               EQU 0
DTYPE_F16               EQU 1
DTYPE_I32               EQU 2
DTYPE_I16               EQU 3
DTYPE_I8                EQU 4
DTYPE_Q4_0              EQU 10
DTYPE_Q4_1              EQU 11
DTYPE_Q5_0              EQU 12
DTYPE_Q5_1              EQU 13
DTYPE_Q8_0              EQU 14

; =============================================================================
; Kernel Dispatch IDs
; =============================================================================
KERNEL_ID_RMSNORM       EQU 1
KERNEL_ID_SOFTMAX       EQU 2
KERNEL_ID_SILU          EQU 3
KERNEL_ID_Q4_DEQUANT    EQU 4
KERNEL_ID_Q4_MATMUL     EQU 5
KERNEL_ID_F32_MATMUL    EQU 6
KERNEL_ID_F16_MATMUL    EQU 7
KERNEL_ID_ROPE          EQU 8
KERNEL_ID_ATTENTION     EQU 9
KERNEL_ID_LAYERNORM     EQU 10

; =============================================================================
; CPU Feature Flags
; =============================================================================
CPU_FEATURE_SSE         EQU 00000001h
CPU_FEATURE_SSE2        EQU 00000002h
CPU_FEATURE_SSE3        EQU 00000004h
CPU_FEATURE_AVX         EQU 00000008h
CPU_FEATURE_AVX2        EQU 00000010h
CPU_FEATURE_AVX512      EQU 00000020h
CPU_FEATURE_FMA         EQU 00000040h
CPU_FEATURE_AMX         EQU 00000080h

; =============================================================================
; Kernel Dispatch Table Entry Structure
; =============================================================================
; Each entry is 32 bytes:
;   +0: QWORD kernel_id
;   +8: QWORD function_ptr (AVX512 variant)
;  +16: QWORD function_ptr (AVX2 variant)
;  +24: QWORD function_ptr (scalar fallback)
KERNEL_ENTRY_STRUCT     STRUC
    kernel_id           DQ ?
    fn_avx512           DQ ?
    fn_avx2             DQ ?
    fn_scalar           DQ ?
KERNEL_ENTRY_STRUCT     ENDS

; =============================================================================
; Public API Declarations
; =============================================================================

; --- Kernel Dispatch ---
EXTERNDEF RawrXD_InitKernelRegistry:PROC
EXTERNDEF RawrXD_DispatchKernel:PROC
EXTERNDEF RawrXD_GetCPUFeatures:PROC
EXTERNDEF RawrXD_GetActiveKernelSet:PROC

; --- Normalization ---
EXTERNDEF RawrXD_RMSNorm:PROC
EXTERNDEF RawrXD_Softmax:PROC
EXTERNDEF RawrXD_LayerNorm:PROC

; --- Activations ---
EXTERNDEF RawrXD_SiLU:PROC
EXTERNDEF RawrXD_GELU:PROC
EXTERNDEF RawrXD_ReLU:PROC

; --- Quantization ---
EXTERNDEF RawrXD_Q4_Dequant:PROC
EXTERNDEF RawrXD_Q4_Quant:PROC
EXTERNDEF RawrXD_Q8_Dequant:PROC

; --- Matrix Operations ---
EXTERNDEF RawrXD_MatMul_F32:PROC
EXTERNDEF RawrXD_MatMul_Q4:PROC
EXTERNDEF RawrXD_MatMul_F16:PROC

; --- Tensor Operations ---
EXTERNDEF RawrXD_TensorCreate:PROC
EXTERNDEF RawrXD_TensorFree:PROC
EXTERNDEF RawrXD_TensorCopy:PROC
EXTERNDEF RawrXD_TensorReshape:PROC
EXTERNDEF RawrXD_TensorView:PROC

; --- Transformer ---
EXTERNDEF RawrXD_RoPE:PROC
EXTERNDEF RawrXD_Attention:PROC
EXTERNDEF RawrXD_TransformerBlock:PROC
EXTERNDEF RawrXD_SwiGLU:PROC

; --- KV Cache ---
EXTERNDEF RawrXD_KVCacheCreate:PROC
EXTERNDEF RawrXD_KVCacheAppend:PROC
EXTERNDEF RawrXD_KVCacheRead:PROC
EXTERNDEF RawrXD_KVCacheEvict:PROC

; --- Sampling ---
EXTERNDEF RawrXD_SampleTopK:PROC
EXTERNDEF RawrXD_SampleTopP:PROC
EXTERNDEF RawrXD_SampleTemperature:PROC
EXTERNDEF RawrXD_SampleToken:PROC

; --- Inference ---
EXTERNDEF RawrXD_LoadModel:PROC
EXTERNDEF RawrXD_RunInference:PROC
EXTERNDEF RawrXD_StreamTokens:PROC
EXTERNDEF RawrXD_Generate:PROC

; --- GGUF ---
EXTERNDEF GGUF_Load:PROC
EXTERNDEF GGUF_GetTensor:PROC
EXTERNDEF GGUF_GetMetadata:PROC
EXTERNDEF GGUF_MapWeights:PROC

; --- Tokenizer ---
EXTERNDEF Tokenizer_Encode:PROC
EXTERNDEF Tokenizer_Decode:PROC
EXTERNDEF Tokenizer_LookupToken:PROC

; --- Agent ---
EXTERNDEF Agent_Planner:PROC
EXTERNDEF Agent_Coder:PROC
EXTERNDEF Agent_Reflector:PROC

; --- GPU ---
EXTERNDEF GPU_OffloadTensor:PROC
EXTERNDEF GPU_SyncTensor:PROC
EXTERNDEF GPU_ExecuteKernel:PROC

; --- Memory Management ---
EXTERNDEF RawrXD_AlignedAlloc:PROC
EXTERNDEF RawrXD_AlignedFree:PROC
EXTERNDEF RawrXD_MemCopy:PROC
EXTERNDEF RawrXD_ZeroMemory:PROC

; --- String Utilities (defined in gguf_reader.asm, agent_runtime.asm) ---
EXTERNDEF RawrXD_StrCmp:PROC
EXTERNDEF RawrXD_StrCopy:PROC

; --- Sampling Parameters (defined in sampler.asm) ---

; =============================================================================
; Tensor Struct Field Offsets (shared across all runtime files)
; =============================================================================
TENSOR_OFF_DATA_PTR     EQU 0
TENSOR_OFF_NDIM         EQU 8
TENSOR_OFF_DTYPE        EQU 12
TENSOR_OFF_NUMEL        EQU 16
TENSOR_OFF_SHAPE        EQU 24
TENSOR_OFF_STRIDE       EQU 88
TENSOR_OFF_OFFSET       EQU 152
TENSOR_OFF_QUANT_TYPE   EQU 160
TENSOR_OFF_DEVICE       EQU 168

ENDIF ; MASM_KERNEL_API_INC
