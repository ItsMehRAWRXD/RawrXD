#include <llama.h>
#include <iostream>
#include <vector>
#include <cstdint>
#include <cstdio>

int main() {
    llama_backend_init();
    
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    
    llama_model* model = llama_model_load_from_file("F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf", model_params);
    if (!model) {
        std::fprintf(stderr, "Failed to load model\n");
        return 1;
    }
    
    // Try to get the token embedding tensor
    // The tensor name might be "token_embd.weight" or "model.embed_tokens.weight"
    const char* embd_names[] = {
        "token_embd.weight",
        "model.embed_tokens.weight",
        "tok_embeddings.weight",
        "embd.weight",
        "token_embd",
        "model.embed_tokens"
    };
    
    for (int i = 0; i < 6; ++i) {
        ggml_tensor* tensor = llama_get_model_tensor(model, embd_names[i]);
        if (tensor) {
            std::printf("Found tensor: %s\n", embd_names[i]);
            std::printf("  type: %d\n", tensor->type);
            std::printf("  ne: [%lld, %lld, %lld, %lld]\n", tensor->ne[0], tensor->ne[1], tensor->ne[2], tensor->ne[3]);
            
            // Get the tensor data for token 1
            // For Q4_K, we need to dequantize
            // The embedding for token 1 is at row 1 (or column 1 depending on layout)
            // ne[0] = embedding_dim, ne[1] = vocab_size typically
            
            // Just print the tensor info for now
            break;
        }
    }
    
    llama_model_free(model);
    llama_backend_free();
    
    return 0;
}