#include <llama.h>
#include <cstdio>

int main() {
    std::fprintf(stderr, "STEP 1\n");
    std::fflush(stderr);
    
    llama_backend_init();
    std::fprintf(stderr, "STEP 2\n");
    std::fflush(stderr);
    
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    
    std::fprintf(stderr, "STEP 3\n");
    std::fflush(stderr);
    
    llama_model* model = llama_model_load_from_file("F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf", model_params);
    if (!model) {
        std::fprintf(stderr, "FAIL: model load\n");
        return 1;
    }
    std::fprintf(stderr, "STEP 4\n");
    std::fflush(stderr);
    
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 16384;
    ctx_params.n_batch = 2048;
    ctx_params.n_ubatch = 512;
    ctx_params.flash_attn_type = LLAMA_FLASH_ATTN_TYPE_DISABLED;
    ctx_params.offload_kqv = false;
    ctx_params.embeddings = true;
    
    std::fprintf(stderr, "STEP 5\n");
    std::fflush(stderr);
    
    llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::fprintf(stderr, "FAIL: context init\n");
        llama_model_free(model);
        return 1;
    }
    std::fprintf(stderr, "STEP 6\n");
    std::fflush(stderr);
    
    std::fprintf(stderr, "STEP 7: llama_set_capture\n");
    std::fflush(stderr);
    
    llama_set_capture(ctx, "F:\\rawrxd\\test_capture", true);
    
    std::fprintf(stderr, "STEP 8: llama_set_capture done\n");
    std::fflush(stderr);
    
    llama_set_capture(ctx, "", false);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    
    std::fprintf(stderr, "STEP 9: Done\n");
    std::fflush(stderr);
    return 0;
}