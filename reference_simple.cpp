#include <llama.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

void write_binary(const char* path, const float* data, size_t count) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data), count * sizeof(float));
    f.close();
}

int main() {
    llama_backend_init();
    
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    
    const char* model_path = "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    llama_model* model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    const llama_vocab* vocab = llama_model_get_vocab(model);
    int n_vocab = llama_vocab_n_tokens(vocab);
    std::cout << "Vocab size: " << n_vocab << std::endl;
    
    // Test just the first 3 positions
    std::vector<uint32_t> test_tokens = {1, 185, 16};
    
    for (size_t pos = 0; pos < test_tokens.size(); ++pos) {
        std::cout << "\n=== Position " << pos << " ===" << std::endl;
        
        llama_context_params ctx_params = llama_context_default_params();
        ctx_params.n_ctx = 512;
        ctx_params.n_batch = 256;
        ctx_params.n_ubatch = 256;
        ctx_params.n_threads = 1;
        ctx_params.n_threads_batch = 1;
        
        llama_context* ctx = llama_init_from_model(model, ctx_params);
        if (!ctx) {
            std::cerr << "Failed to create context at position " << pos << std::endl;
            continue;
        }
        
        uint32_t input_token = test_tokens[pos];
        std::cout << "Input token: " << input_token << std::endl;
        
        llama_token tokens[] = {static_cast<llama_token>(input_token)};
        llama_batch batch = llama_batch_get_one(tokens, 1);
        batch.pos[0] = static_cast<llama_pos>(pos);
        
        std::cout << "Decoding..." << std::endl;
        if (llama_decode(ctx, batch)) {
            std::cerr << "Failed to decode at position " << pos << std::endl;
            llama_free(ctx);
            continue;
        }
        std::cout << "Decode done" << std::endl;
        
        float* logits = llama_get_logits_ith(ctx, 0);
        if (!logits) {
            std::cerr << "Failed to get logits at position " << pos << std::endl;
            llama_free(ctx);
            continue;
        }
        std::cout << "Got logits" << std::endl;
        
        // Find argmax
        int argmax_token = 0;
        float max_logit = logits[0];
        for (int i = 1; i < n_vocab; ++i) {
            if (logits[i] > max_logit) {
                max_logit = logits[i];
                argmax_token = i;
            }
        }
        
        // Save logits
        char fname[256];
        sprintf_s(fname, "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\ref_logits_pos%zu.bin", pos);
        write_binary(fname, logits, n_vocab);
        std::cout << "Saved logits to " << fname << std::endl;
        
        char token_text[32];
        llama_token_to_piece(vocab, argmax_token, token_text, sizeof(token_text), 0, false);
        std::cout << "Pos " << pos << ": input=" << input_token 
                  << " ref_argmax=" << argmax_token 
                  << " (" << token_text << ") logit=" << max_logit << std::endl;
        
        llama_free(ctx);
        std::cout << "Context freed" << std::endl;
    }
    
    llama_model_free(model);
    llama_backend_free();
    
    std::cout << "\nDone!" << std::endl;
    return 0;
}