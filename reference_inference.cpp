#include <llama.h>
#include <iostream>
#include <vector>
#include <algorithm>

int main() {
    // Initialize
    llama_backend_init();
    
    // Model parameters
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;  // CPU only
    
    // Load model
    const char* model_path = "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    std::cout << "Loading model from: " << model_path << std::endl;
    llama_model* model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    std::cout << "Model loaded successfully" << std::endl;
    
    // Context parameters
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 512;
    ctx_params.n_batch = 512;
    ctx_params.n_ubatch = 512;
    ctx_params.n_threads = 1;
    ctx_params.n_threads_batch = 1;
    
    llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::cerr << "Failed to create context\n";
        return 1;
    }
    
    // Get vocab
    const llama_vocab* vocab = llama_model_get_vocab(model);
    int n_vocab = llama_vocab_n_tokens(vocab);
    std::cout << "Vocab size: " << n_vocab << std::endl;
    
    // Get token 1 text
    char token_text[32];
    llama_token_to_piece(vocab, 1, token_text, (int32_t)sizeof(token_text), 0, false);
    std::cout << "Token 1: '" << token_text << "'" << std::endl;
    
    // Prepare input: token 1 at position 0
    llama_token tokens[] = {1};
    llama_batch batch = llama_batch_get_one(tokens, 1);
    
    // Decode
    if (llama_decode(ctx, batch)) {
        std::cerr << "Failed to decode\n";
        return 1;
    }
    
    // Get logits
    float* logits = llama_get_logits_ith(ctx, 0);
    if (!logits) {
        std::cerr << "Failed to get logits\n";
        return 1;
    }
    
    // Find argmax
    int argmax_token = 0;
    float max_logit = logits[0];
    float logit_185 = logits[185];
    float logit_93633 = logits[93633];
    
    for (int i = 1; i < n_vocab; ++i) {
        if (logits[i] > max_logit) {
            max_logit = logits[i];
            argmax_token = i;
        }
    }
    
    std::cout << "Argmax token: " << argmax_token << " (logit: " << max_logit << ")" << std::endl;
    std::cout << "Logit at 185: " << logit_185 << std::endl;
    std::cout << "Logit at 93633: " << logit_93633 << std::endl;
    
    // Get token text for argmax
    char argmax_text[32];
    llama_token_to_piece(vocab, argmax_token, argmax_text, (int32_t)sizeof(argmax_text), 0, false);
    std::cout << "Argmax token text: '" << argmax_text << "'" << std::endl;
    
    // Get embeddings for token 1
    float* embeddings = llama_get_embeddings_ith(ctx, 0);
    if (embeddings) {
        int n_embd = llama_model_n_embd(model);
        std::cout << "Embedding dim: " << n_embd << std::endl;
        // Print first few values
        std::cout << "Embedding[0..7]: ";
        for (int i = 0; i < std::min(8, n_embd); ++i) {
            std::cout << embeddings[i] << " ";
        }
        std::cout << std::endl;
    }
    
    // Cleanup
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    
    return 0;
}