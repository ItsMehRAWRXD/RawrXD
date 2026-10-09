#include <llama.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "Usage: reference_runner <model.gguf> <output_dir> <token1> [token2] ...\n";
        return 1;
    }

    const char* model_path = argv[1];
    const char* output_dir = argv[2];
    
    // Parse forced tokens
    std::vector<int32_t> forced_tokens;
    for (int i = 3; i < argc; ++i) {
        forced_tokens.push_back(std::atoi(argv[i]));
    }
    
    if (forced_tokens.empty()) {
        std::cerr << "ERROR: No forced tokens provided\n";
        return 1;
    }

    // Initialize llama
    llama_backend_init();
    
    // Model params
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0; // CPU only
    
    // Load model
    llama_model* model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        std::cerr << "ERROR: Failed to load model\n";
        return 1;
    }
    
    // Get vocab size
    const llama_vocab* vocab = llama_model_get_vocab(model);
    int32_t n_vocab = llama_vocab_n_tokens(vocab);
    std::cout << "Model vocab size: " << n_vocab << std::endl;
    std::cout << "Forced tokens: " << forced_tokens.size() << std::endl;
    
    // Context params
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 16384; // Large enough for DeepSeek-V2
    ctx_params.n_batch = 2048;
    ctx_params.n_ubatch = 512;
    ctx_params.flash_attn_type = LLAMA_FLASH_ATTN_TYPE_DISABLED;
    ctx_params.offload_kqv = false;
    
    // Create context
    llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::cerr << "ERROR: Failed to create context\n";
        llama_model_free(model);
        return 1;
    }
    
    // Create batch
    llama_batch batch = llama_batch_init(1, 0, 1);
    int32_t position = 0;
    
    // Process each forced token
    for (size_t step = 0; step < forced_tokens.size(); ++step) {
        int32_t token = forced_tokens[step];
        
        // Reset batch
        batch.n_tokens = 1;
        batch.token[0] = token;
        batch.pos[0] = position;
        batch.n_seq_id[0] = 1;
        batch.seq_id[0][0] = 0;
        batch.logits[0] = 1; // Request logits for this token
        
        // Decode
        if (llama_decode(ctx, batch) != 0) {
            std::cerr << "ERROR: llama_decode failed at step " << step << std::endl;
            break;
        }
        
        // Get logits for the last token (index 0 since batch size is 1)
        float* logits = llama_get_logits_ith(ctx, 0);
        if (!logits) {
            std::cerr << "ERROR: Failed to get logits at step " << step << std::endl;
            break;
        }
        
        // Save logits
        char fname[512];
        sprintf_s(fname, "%s\\ref_logits_pos%zu.bin", output_dir, step);
        
        std::ofstream f(fname, std::ios::binary);
        if (!f) {
            std::cerr << "ERROR: Cannot open " << fname << std::endl;
            break;
        }
        f.write(reinterpret_cast<const char*>(logits), n_vocab * sizeof(float));
        f.close();
        
        // Print argmax for verification
        float max_val = logits[0];
        int32_t argmax = 0;
        for (int32_t i = 1; i < n_vocab; ++i) {
            if (logits[i] > max_val) {
                max_val = logits[i];
                argmax = i;
            }
        }
        std::cout << "Position " << step << ": forced_token=" << token 
                  << ", argmax=" << argmax << ", max_val=" << max_val << std::endl;
        
        position++;
    }
    
    // Cleanup
    llama_batch_free(batch);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    
    std::cout << "Done. Saved " << forced_tokens.size() << " logit files.\n";
    return 0;
}