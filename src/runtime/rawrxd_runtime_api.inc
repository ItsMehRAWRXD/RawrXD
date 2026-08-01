; =============================================================================
; rawrxd_runtime_api.inc - RawrXD Runtime C ABI Public API
; =============================================================================
; This is the single public header for all C-callable runtime functions.
; Every function uses the Microsoft x64 calling convention:
;   RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4, stack for 5+
;   RAX = return value (0 = success, non-zero = error code)
;
; All functions are exported as PUBLIC symbols for linking with
; sovereign_main.asm and any C/C++ wrapper code.
; =============================================================================

IFNDEF RAWRXD_RUNTIME_API_INC
RAWRXD_RUNTIME_API_INC EQU 1

; =============================================================================
; Error Codes
; =============================================================================
RAWRXD_SUCCESS              EQU 0
RAWRXD_ERR_NULL_PTR        EQU 1
RAWRXD_ERR_INVALID_PARAM   EQU 2
RAWRXD_ERR_OUT_OF_MEMORY   EQU 3
RAWRXD_ERR_FILE_NOT_FOUND  EQU 4
RAWRXD_ERR_BAD_MAGIC       EQU 5
RAWRXD_ERR_UNSUPPORTED     EQU 6
RAWRXD_ERR_DEVICE_LOST     EQU 7
RAWRXD_ERR_TIMEOUT         EQU 8
RAWRXD_ERR_ABI_VIOLATION   EQU 9

; =============================================================================
; Runtime States
; =============================================================================
RAWRXD_STATE_UNINIT        EQU 0
RAWRXD_STATE_INIT          EQU 1
RAWRXD_STATE_MODEL_LOADED  EQU 2
RAWRXD_STATE_INFERRING     EQU 3
RAWRXD_STATE_ERROR         EQU 4

; =============================================================================
; Public API — Lifecycle
; =============================================================================
; RawrXD_InitRuntime - Initialize the entire runtime
;   RCX = void* config (optional config struct, NULL = defaults)
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_InitRuntime:PROC

; RawrXD_Shutdown - Shut down the runtime, free all resources
;   No parameters
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_Shutdown:PROC

; RawrXD_GetRuntimeState - Get current runtime state
;   Returns: RAX = RAWRXD_STATE_* value
EXTERNDEF RawrXD_GetRuntimeState:PROC

; RawrXD_GetLastError - Get last error message
;   Returns: RAX = pointer to null-terminated error string
EXTERNDEF RawrXD_GetLastError:PROC

; =============================================================================
; Public API — Model Loading
; =============================================================================
; RawrXD_LoadModel - Load a GGUF model file
;   RCX = char* model_path
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_LoadModel:PROC

; RawrXD_UnloadModel - Unload the current model
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_UnloadModel:PROC

; RawrXD_GetModelInfo - Get model metadata
;   RCX = void* out_buffer
;   RDX = QWORD buffer_size
;   Returns: RAX = bytes written, or 0 on error
EXTERNDEF RawrXD_GetModelInfo:PROC

; =============================================================================
; Public API — Inference
; =============================================================================
; RawrXD_RunInference - Run a single forward pass
;   RCX = QWORD input_token
;   RDX = QWORD* out_token (output token ID)
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_RunInference:PROC

; RawrXD_Generate - Generate tokens from a prompt
;   RCX = QWORD* prompt_tokens
;   RDX = QWORD prompt_len
;   R8  = QWORD max_tokens
;   R9  = QWORD* output_tokens
;   Returns: RAX = number of tokens generated
EXTERNDEF RawrXD_Generate:PROC

; RawrXD_StreamTokens - Generate with callback
;   RCX = QWORD* prompt_tokens
;   RDX = QWORD prompt_len
;   R8  = QWORD max_tokens
;   R9  = void* callback(token_id)
;   Returns: RAX = number of tokens generated
EXTERNDEF RawrXD_StreamTokens:PROC

; RawrXD_StopGeneration - Stop an in-progress generation
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_StopGeneration:PROC

; =============================================================================
; Public API — Sampling Parameters
; =============================================================================
; RawrXD_SetTemperature - Set sampling temperature
;   RCX = float temperature
EXTERNDEF RawrXD_SetTemperature:PROC

; RawrXD_SetTopK - Set top-K sampling parameter
;   RCX = QWORD k
EXTERNDEF RawrXD_SetTopK:PROC

; RawrXD_SetTopP - Set top-P (nucleus) sampling parameter
;   RCX = float p
EXTERNDEF RawrXD_SetTopP:PROC

; =============================================================================
; Public API — Tokenizer
; =============================================================================
; RawrXD_Encode - Encode text to token IDs
;   RCX = char* text
;   RDX = QWORD* out_tokens
;   R8  = QWORD max_tokens
;   Returns: RAX = number of tokens
EXTERNDEF RawrXD_Encode:PROC

; RawrXD_Decode - Decode token IDs to text
;   RCX = QWORD* tokens
;   RDX = QWORD num_tokens
;   R8  = char* out_text
;   R9  = QWORD max_len
;   Returns: RAX = length of decoded text
EXTERNDEF RawrXD_Decode:PROC

; =============================================================================
; Public API — GPU
; =============================================================================
; RawrXD_GPU_Init - Initialize GPU backend
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_GPU_Init:PROC

; RawrXD_GPU_Offload - Offload a tensor to GPU
;   RCX = QWORD tensor_ptr
;   RDX = QWORD device_id
;   Returns: RAX = device pointer
EXTERNDEF RawrXD_GPU_Offload:PROC

; RawrXD_GPU_Sync - Synchronize GPU
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_GPU_Sync:PROC

; =============================================================================
; Public API — Agent
; =============================================================================
; RawrXD_Agent_RunPipeline - Run the agent pipeline
;   RCX = char* task
;   RDX = void* output
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_Agent_RunPipeline:PROC

; =============================================================================
; Public API — Benchmark
; =============================================================================
; RawrXD_Benchmark - Run performance benchmark
;   RCX = QWORD num_iterations
;   RDX = void* out_results
;   Returns: RAX = 0 on success
EXTERNDEF RawrXD_Benchmark:PROC

ENDIF ; RAWRXD_RUNTIME_API_INC
