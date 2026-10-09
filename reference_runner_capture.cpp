#include <llama.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <direct.h>  // for _mkdir

int main(int argc, char** argv) {
    std::fprintf(stderr, "DEBUG: Starting reference_runner_capture\n");
    std::fflush(stderr);
    
    if (argc < 4) {
        std::fprintf(stderr, "Usage: reference_runner_capture <model.gguf> <output_dir> <token1> [token2] ...\n");
        return 1;
    }

    std::fprintf(stderr, "DEBUG: Args parsed\n");
    std::fflush(stderr);

    const char* model_path = argv[1];
    const char* output_dir = argv[2];
    
    // Parse forced tokens
    std::vector<int32_t> forced_tokens;
    for (int i = 3; i < argc; ++i) {
        forced_tokens.push_back(std::atoi(argv[i]));
    }
    
    if (forced_tokens.empty()) {
        std::fprintf(stderr, "ERROR: No forced tokens provided\n");
        return 1;
    }

    std::fprintf(stderr, "DEBUG: Creating output dir: %s\n", output_dir);
    std::fflush(stderr);
    _mkdir(output_dir);

    std::fprintf(stderr, "DEBUG: Initializing llama backend\n");
    std::fflush(stderr);
    // Initialize llama
    llama_backend_init();
    
    // Model params
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    
    std::fprintf(stderr, "DEBUG: Loading model: %s\n", model_path);
    std::fflush(stderr);
    // Load model
    llama_model* model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        std::fprintf(stderr, "ERROR: Failed to load model\n");
        return 1;
    }
    
    std::fprintf(stderr, "DEBUG: Model loaded\n");
    std::fflush(stderr);
    
    const llama_vocab* vocab = llama_model_get_vocab(model);
    int32_t n_vocab = llama_vocab_n_tokens(vocab);
    std::printf("Model vocab size: %d\n", n_vocab);
    std::printf("Forced tokens: %zu\n", forced_tokens.size());
    std::fflush(stdout);
    
    // Context params
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 16384;
    ctx_params.n_batch = 2048;
    ctx_params.n_ubatch = 512;
    ctx_params.flash_attn_type = LLAMA_FLASH_ATTN_TYPE_DISABLED;
    ctx_params.offload_kqv = false;
    ctx_params.embeddings = true;
    
    std::fprintf(stderr, "DEBUG: Creating context\n");
    std::fflush(stderr);
    // Create context
    llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::fprintf(stderr, "ERROR: Failed to create context\n");
        llama_model_free(model);
        return 1;
    }
    
    std::fprintf(stderr, "DEBUG: Context created, enabling capture\n");
    std::fflush(stderr);
    // Enable tensor capture
    llama_set_capture(ctx, output_dir, true);
    std::printf("Tensor capture enabled: %s\n", output_dir);
    std::fflush(stdout);
    
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
        batch.logits[0] = 1;
        
        std::fprintf(stderr, "DEBUG: Decoding step %zu token %d pos %d\n", step, token, position);
        std::fflush(stderr);
        
        // Decode
        if (llama_decode(ctx, batch) != 0) {
            std::fprintf(stderr, "ERROR: llama_decode failed at step %zu\n", step);
            break;
        }
        
        std::fprintf(stderr, "DEBUG: Decode done, getting logits\n");
        std::fflush(stderr);
        
        // Get logits
        float* logits = llama_get_logits_ith(ctx, 0);
        if (logits) {
            char fname[512];
            sprintf_s(fname, "%s/ref_logits_pos%zu.bin", output_dir, step);
            std::ofstream f(fname, std::ios::binary);
            if (f) {
                f.write(reinterpret_cast<const char*>(logits), n_vocab * sizeof(float));
                f.close();
            }
            
            // Print argmax for verification
            float max_val = logits[0];
            int32_t argmax = 0;
            for (int32_t i = 1; i < n_vocab; ++i) {
                if (logits[i] > max_val) {
                    max_val = logits[i];
                    argmax = i;
                }
            }
            std::printf("Position %zu: forced_token=%d, argmax=%d, max_val=%.6f\n", step, token, argmax, max_val);
            std::fflush(stdout);
        }
        
        position++;
    }
    
    std::fprintf(stderr, "DEBUG: Disabling capture\n");
    std::fflush(stderr);
    // Disable capture
    llama_set_capture(ctx, "", false);
    
    // Cleanup
    llama_batch_free(batch);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    
    std::printf("Done. Captured tensors saved to %s\n", output_dir);
    std::fflush(stdout);
    return 0;
}