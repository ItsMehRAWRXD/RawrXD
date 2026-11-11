// ABI Verifier for llama.cpp Python ctypes bridge
// Compiles against the exact llama.h used to build the loaded DLL
// Prints sizeof and offsetof for all critical structures

#include "tmp_llama-clone/include/llama.h"
#include <stdio.h>
#include <stddef.h>

#define PRINT_SIZE(type) printf("sizeof(%s) = %zu\n", #type, sizeof(type))
#define PRINT_OFFSET(struct_type, field) printf("offsetof(%s, %s) = %zu\n", #struct_type, #field, offsetof(struct_type, field))

int main() {
    printf("=== LLAMA STRUCT ABI VERIFICATION ===\n\n");

    // llama_model_params
    printf("--- llama_model_params ---\n");
    PRINT_SIZE(llama_model_params);
    PRINT_OFFSET(llama_model_params, devices);
    PRINT_OFFSET(llama_model_params, tensor_buft_overrides);
    PRINT_OFFSET(llama_model_params, n_gpu_layers);
    PRINT_OFFSET(llama_model_params, split_mode);
    PRINT_OFFSET(llama_model_params, load_mode);
    PRINT_OFFSET(llama_model_params, lazy_mode);
    PRINT_OFFSET(llama_model_params, main_gpu);
    PRINT_OFFSET(llama_model_params, tensor_split);
    PRINT_OFFSET(llama_model_params, progress_callback);
    PRINT_OFFSET(llama_model_params, progress_callback_user_data);
    PRINT_OFFSET(llama_model_params, kv_overrides);
    PRINT_OFFSET(llama_model_params, vocab_only);
    PRINT_OFFSET(llama_model_params, check_tensors);
    PRINT_OFFSET(llama_model_params, use_extra_bufts);
    PRINT_OFFSET(llama_model_params, no_host);
    PRINT_OFFSET(llama_model_params, no_alloc);
    PRINT_OFFSET(llama_model_params, load_mtp);

    printf("\n--- llama_context_params ---\n");
    PRINT_SIZE(llama_context_params);
    PRINT_OFFSET(llama_context_params, n_ctx);
    PRINT_OFFSET(llama_context_params, n_batch);
    PRINT_OFFSET(llama_context_params, n_ubatch);
    PRINT_OFFSET(llama_context_params, n_seq_max);
    PRINT_OFFSET(llama_context_params, n_rs_seq);
    PRINT_OFFSET(llama_context_params, n_outputs_max);
    PRINT_OFFSET(llama_context_params, n_outputs_max_per_seq);
    PRINT_OFFSET(llama_context_params, n_threads);
    PRINT_OFFSET(llama_context_params, n_threads_batch);
    PRINT_OFFSET(llama_context_params, ctx_type);
    PRINT_OFFSET(llama_context_params, rope_scaling_type);
    PRINT_OFFSET(llama_context_params, pooling_type);
    PRINT_OFFSET(llama_context_params, attention_type);
    PRINT_OFFSET(llama_context_params, flash_attn_type);
    PRINT_OFFSET(llama_context_params, rope_freq_base);
    PRINT_OFFSET(llama_context_params, rope_freq_scale);
    PRINT_OFFSET(llama_context_params, yarn_ext_factor);
    PRINT_OFFSET(llama_context_params, yarn_attn_factor);
    PRINT_OFFSET(llama_context_params, yarn_beta_fast);
    PRINT_OFFSET(llama_context_params, yarn_beta_slow);
    PRINT_OFFSET(llama_context_params, yarn_orig_ctx);
    PRINT_OFFSET(llama_context_params, defrag_thold);
    PRINT_OFFSET(llama_context_params, cb_eval);
    PRINT_OFFSET(llama_context_params, cb_eval_user_data);
    PRINT_OFFSET(llama_context_params, type_k);
    PRINT_OFFSET(llama_context_params, type_v);
    PRINT_OFFSET(llama_context_params, abort_callback);
    PRINT_OFFSET(llama_context_params, abort_callback_data);
    PRINT_OFFSET(llama_context_params, embeddings);
    PRINT_OFFSET(llama_context_params, offload_kqv);
    PRINT_OFFSET(llama_context_params, no_perf);
    PRINT_OFFSET(llama_context_params, op_offload);
    PRINT_OFFSET(llama_context_params, swa_full);
    PRINT_OFFSET(llama_context_params, kv_unified);
    PRINT_OFFSET(llama_context_params, samplers);
    PRINT_OFFSET(llama_context_params, n_samplers);
    PRINT_OFFSET(llama_context_params, ctx_other);

    printf("\n--- llama_batch ---\n");
    PRINT_SIZE(llama_batch);
    PRINT_OFFSET(llama_batch, n_tokens);
    PRINT_OFFSET(llama_batch, token);
    PRINT_OFFSET(llama_batch, embd);
    PRINT_OFFSET(llama_batch, pos);
    PRINT_OFFSET(llama_batch, n_seq_id);
    PRINT_OFFSET(llama_batch, seq_id);
    PRINT_OFFSET(llama_batch, logits);

    printf("\n--- Enum sizes ---\n");
    PRINT_SIZE(enum llama_split_mode);
    PRINT_SIZE(enum llama_load_mode);
    PRINT_SIZE(enum llama_lazy_mode);
    PRINT_SIZE(enum llama_context_type);
    PRINT_SIZE(enum llama_rope_scaling_type);
    PRINT_SIZE(enum llama_pooling_type);
    PRINT_SIZE(enum llama_attention_type);
    PRINT_SIZE(enum llama_flash_attn_type);
    PRINT_SIZE(enum ggml_type);

    printf("\n--- Pointer sizes ---\n");
    printf("sizeof(void*) = %zu\n", sizeof(void*));
    printf("sizeof(llama_model*) = %zu\n", sizeof(struct llama_model*));
    printf("sizeof(llama_context*) = %zu\n", sizeof(struct llama_context*));
    printf("sizeof(llama_sampler*) = %zu\n", sizeof(struct llama_sampler*));
    printf("sizeof(ggml_backend_dev_t*) = %zu\n", sizeof(ggml_backend_dev_t*));

    return 0;
}