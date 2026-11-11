#include <llama.h>
#include <iostream>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <fstream>

int main() {
    llama_backend_init();
    
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    
    llama_model* model = llama_model_load_from_file("F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf", model_params);
    if (!model) {
        std::fprintf(stderr, "Failed to load model\n");
        return 1;
    }
    
    // Get vocabulary
    const llama_vocab* vocab = llama_model_get_vocab(model);
    int32_t n_vocab = llama_vocab_n_tokens(vocab);
    std::printf("Vocab size: %d\n", n_vocab);
    
    // Get embedding tensor
    // The embedding is the output of the first layer (token embedding lookup)
    // We can get it by running a single token through the model
    
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 16384;
    ctx_params.n_batch = 1;
    ctx_params.n_ubatch = 1;
    ctx_params.flash_attn_type = LLAMA_FLASH_ATTN_TYPE_DISABLED;
    ctx_params.offload_kqv = false;
    ctx_params.embeddings = true;
    
    llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::fprintf(stderr, "Failed to create context\n");
        llama_model_free(model);
        return 1;
    }
    
    // Run token 1
    llama_batch batch = llama_batch_init(1, 0, 1);
    batch.n_tokens = 1;
    batch.token[0] = 1;
    batch.pos[0] = 0;
    batch.n_seq_id[0] = 1;
    batch.seq_id[0][0] = 0;
    batch.logits[0] = 1;
    
    if (llama_decode(ctx, batch) != 0) {
        std::fprintf(stderr, "Decode failed\n");
    }
    
    // Get embeddings
    float* embeddings = llama_get_embeddings(ctx);
    if (embeddings) {
        std::printf("Embedding dimension: %d\n", llama_model_n_embd(model));
        int n_embd = llama_model_n_embd(model);
        
        // Print first 32 values
        std::printf("First 32 embedding values for token 1:\n");
        for (int i = 0; i < std::min(32, n_embd); ++i) {
            std::printf("  [%d] = %.6f\n", i, embeddings[i]);
        }
        
        // Find max and argmax
        float max_val = embeddings[0];
        int argmax = 0;
        for (int i = 1; i < n_embd; ++i) {
            if (embeddings[i] > max_val) {
                max_val = embeddings[i];
                argmax = i;
            }
        }
        std::printf("Argmax: %d (%.6f)\n", argmax, max_val);
        
        // Save to file for comparison
        std::ofstream f("F:\\rawrxd\\direct_embd_token1.bin", std::ios::binary);
        f.write(reinterpret_cast<char*>(embeddings), n_embd * sizeof(float));
        f.close();
    } else {
        std::fprintf(stderr, "No embeddings available\n");
    }
    
    llama_batch_free(batch);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    
    return 0;
}