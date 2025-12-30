; ============================================================================
; INFERENCE_MANAGER.INC - Model Inference Header
; ============================================================================

EXTERN inference_manager_init:PROC
EXTERN inference_manager_shutdown:PROC
EXTERN load_model:PROC
EXTERN unload_model:PROC
EXTERN tokenize_input:PROC
EXTERN prepare_batch:PROC
EXTERN run_inference:PROC
EXTERN get_logits:PROC
EXTERN sample_token:PROC
EXTERN manage_kv_cache:PROC
EXTERN set_sampling_params:PROC
EXTERN get_inference_stats:PROC
EXTERN cache_embeddings:PROC
EXTERN optimize_memory:PROC

INFERENCE_REQUEST STRUCT
    input_tokens QWORD ?
    input_length DWORD ?
    max_gen_tokens DWORD ?
    output_buffer QWORD ?
    request_id DWORD ?
    status DWORD ?
INFERENCE_REQUEST ENDS

KV_CACHE STRUCT
    key_tensors QWORD ?
    value_tensors QWORD ?
    seq_position DWORD ?
    max_seq_len DWORD ?
KV_CACHE ENDS
