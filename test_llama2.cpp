#include <llama.h>
#include <cstdio>

int main(int argc, char** argv) {
    std::fprintf(stderr, "TEST: Before llama_backend_init\n");
    std::fflush(stderr);
    
    llama_backend_init();
    
    std::fprintf(stderr, "TEST: After llama_backend_init\n");
    std::fflush(stderr);
    
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    
    std::fprintf(stderr, "TEST: Loading model\n");
    std::fflush(stderr);
    
    llama_model* model = llama_model_load_from_file("F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf", model_params);
    if (!model) {
        std::fprintf(stderr, "TEST: Failed to load model\n");
        return 1;
    }
    
    std::fprintf(stderr, "TEST: Model loaded\n");
    std::fflush(stderr);
    
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 16384;
    ctx_params.n_batch = 2048;
    ctx_params.n_ubatch = 512;
    ctx_params.flash_attn_type = LLAMA_FLASH_ATTN_TYPE_DISABLED;
    ctx_params.offload_kqv = false;
    ctx_params.embeddings = true;
    
    std::fprintf(stderr, "TEST: Creating context\n");
    std::fflush(stderr);
    
    llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::fprintf(stderr, "TEST: Failed to create context\n");
        llama_model_free(model);
        return 1;
    }
    
    std::fprintf(stderr, "TEST: Context created\n");
    std::fflush(stderr);
    
    std::fprintf(stderr, "TEST: Calling llama_set_capture\n");
    std::fflush(stderr);
    
    llama_set_capture(ctx, "F:\\rawrxd\\test_capture", true);
    
    std::fprintf(stderr, "TEST: llama_set_capture returned\n");
    std::fflush(stderr);
    
    llama_batch batch = llama_batch_init(1, 0, 1);
    batch.n_tokens = 1;
    batch.token[0] = 1;
    batch.pos[0] = 0;
    batch.n_seq_id[0] = 1;
    batch.seq_id[0][0] = 0;
    batch.logits[0] = 1;
    
    std::fprintf(stderr, "TEST: Calling llama_decode\n");
    std::fflush(stderr);
    
    int ret = llama_decode(ctx, batch);
    std::fprintf(stderr, "TEST: llama_decode returned %d\n", ret);
    std::fflush(stderr);
    
    llama_set_capture(ctx, "", false);
    llama_batch_free(batch);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    
    std::fprintf(stderr, "TEST: Done\n");
    std::fflush(stderr);
    return 0;
}