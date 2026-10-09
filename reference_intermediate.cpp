#include <llama.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>

void write_binary(const char* path, const float* data, size_t count) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data), count * sizeof(float));
    f.close();
}

int main() {
    std::cerr << "Starting reference intermediate dump..." << std::endl;
    std::cerr.flush();
    
    // Token sequence: positions 0 and 1
    std::vector<uint32_t> tokens = {1, 185};
    
    llama_backend_init();
    std::cerr << "Backend init done" << std::endl;
    std::cerr.flush();
    
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    
    const char* model_path = "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    llama_model* model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    std::cerr << "Model loaded" << std::endl;
    std::cerr.flush();
    
    const llama_vocab* vocab = llama_model_get_vocab(model);
    int n_vocab = llama_vocab_n_tokens(vocab);
    std::cerr << "Vocab size: " << n_vocab << std::endl;
    std::cerr.flush();
    
    // Create context with KV cache
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 256;
    ctx_params.n_batch = 1;
    ctx_params.n_ubatch = 1;
    ctx_params.n_threads = 1;
    ctx_params.n_threads_batch = 1;
    ctx_params.flash_attn_type = static_cast<llama_flash_attn_type>(0);
    ctx_params.type_k = static_cast<ggml_type>(0);
    ctx_params.type_v = static_cast<ggml_type>(0);
    
    llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::cerr << "Failed to create context\n";
        return 1;
    }
    std::cerr << "Context created" << std::endl;
    std::cerr.flush();
    
    // Process each position with same context (preserving KV cache)
    for (size_t i = 0; i < tokens.size(); ++i) {
        uint32_t token = tokens[i];
        size_t position = i;
        
        std::cerr << "Processing pos " << position << " token " << token << std::endl;
        std::cerr.flush();
        
        llama_token llama_tokens[] = {static_cast<llama_token>(token)};
        llama_batch batch = llama_batch_get_one(llama_tokens, 1);
        
        // Allocate batch arrays if needed
        if (!batch.pos) batch.pos = new llama_pos[batch.n_tokens];
        if (!batch.n_seq_id) batch.n_seq_id = new int32_t[batch.n_tokens];
        if (!batch.seq_id) {
            batch.seq_id = new int32_t*[batch.n_tokens];
            for (size_t j = 0; j < batch.n_tokens; ++j) {
                batch.seq_id[j] = new int32_t[1];
            }
        }
        if (!batch.logits) batch.logits = new int8_t[batch.n_tokens];
        
        batch.pos[0] = static_cast<llama_pos>(position);
        batch.n_seq_id[0] = 1;
        batch.seq_id[0][0] = 0;
        batch.logits[0] = 1;
        
        if (llama_decode(ctx, batch)) {
            std::cerr << "Failed to decode at position " << position << "\n";
            return 1;
        }
        
        float* logits = llama_get_logits_ith(ctx, 0);
        if (!logits) {
            std::cerr << "Failed to get logits at position " << position << "\n";
            return 1;
        }
        
        // Save logits
        char fname[512];
        sprintf_s(fname, "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\ref_logits_pos%zu.bin", position);
        write_binary(fname, logits, n_vocab);
        
        // Find argmax
        int argmax_token = 0;
        float max_logit = logits[0];
        for (int j = 1; j < n_vocab; ++j) {
            if (logits[j] > max_logit) {
                max_logit = logits[j];
                argmax_token = j;
            }
        }
        
        char token_text[32];
        llama_token_to_piece(vocab, argmax_token, token_text, sizeof(token_text), 0, false);
        std::cerr << "Pos " << position << ": token=" << token 
                  << " argmax=" << argmax_token << " (" << token_text << ") logit=" << max_logit << std::endl;
        std::cerr.flush();
    }
    
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    
    std::cerr << "Done!" << std::endl;
    return 0;
}