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
    
    llama_model_free(model);
    llama_backend_free();
    
    std::fprintf(stderr, "TEST: Done\n");
    std::fflush(stderr);
    return 0;
}