#include <llama.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>

void write_binary(const char* path, const float* data, size_t count) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data), count * sizeof(float));
    f.close();
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <token> <position> [output_file]\n";
        return 1;
    }
    
    uint32_t token = static_cast<uint32_t>(std::stoul(argv[1]));
    size_t position = static_cast<size_t>(std::stoul(argv[2]));
    std::string output_file = (argc >= 4) ? argv[3] : "";
    
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
    
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 256;
    ctx_params.n_batch = 1;
    ctx_params.n_ubatch = 1;
    ctx_params.n_threads = 1;
    ctx_params.n_threads_batch = 1;
    
    // Disable flash attention to avoid massive graph allocation
    ctx_params.flash_attn_type = static_cast<llama_flash_attn_type>(0);  // LLAMA_FLASH_ATTN_TYPE_DISABLED
    
    // Force F32 for K/V to avoid flash attention paths
    ctx_params.type_k = static_cast<ggml_type>(0);  // GGML_TYPE_F32
    ctx_params.type_v = static_cast<ggml_type>(0);  // GGML_TYPE_F32
    
    llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::cerr << "Failed to create context\n";
        return 1;
    }
    std::cerr << "Context created successfully" << std::endl;
    std::cerr.flush();
    
    llama_token tokens[] = {static_cast<llama_token>(token)};
    std::cerr << "Tokens array created" << std::endl;
    std::cerr.flush();
    
    llama_batch batch = llama_batch_get_one(tokens, 1);
    std::cerr << "Batch get one returned" << std::endl;
    std::cerr << "  batch.n_tokens=" << batch.n_tokens << std::endl;
    std::cerr << "  batch.token=" << (batch.token ? "valid" : "null") << std::endl;
    std::cerr << "  batch.pos=" << (batch.pos ? "valid" : "null") << std::endl;
    std::cerr << "  batch.n_seq_id=" << (batch.n_seq_id ? "valid" : "null") << std::endl;
    std::cerr << "  batch.seq_id=" << (batch.seq_id ? "valid" : "null") << std::endl;
    std::cerr << "  batch.logits=" << (batch.logits ? "valid" : "null") << std::endl;
    std::cerr.flush();
    
    // llama_batch_get_one doesn't allocate all arrays, need to allocate manually
    if (!batch.pos) {
        batch.pos = new llama_pos[batch.n_tokens];
    }
    if (!batch.n_seq_id) {
        batch.n_seq_id = new int32_t[batch.n_tokens];
    }
    if (!batch.seq_id) {
        batch.seq_id = new int32_t*[batch.n_tokens];
        for (size_t i = 0; i < batch.n_tokens; ++i) {
            batch.seq_id[i] = new int32_t[1];
        }
    }
    if (!batch.logits) {
        batch.logits = new int8_t[batch.n_tokens];
    }
    
    batch.pos[0] = static_cast<llama_pos>(position);
    batch.n_seq_id[0] = 1;
    batch.seq_id[0][0] = 0;
    batch.logits[0] = true;
    
    std::cerr << "Batch fields initialized" << std::endl;
    std::cerr << "  pos[0]=" << batch.pos[0] << std::endl;
    std::cerr.flush();
    
    std::cerr << "Starting llama_decode..." << std::endl;
    std::cerr.flush();
    if (llama_decode(ctx, batch)) {
        std::cerr << "Failed to decode\n";
        return 1;
    }
    std::cerr << "Decode completed successfully" << std::endl;
    
    float* logits = llama_get_logits_ith(ctx, 0);
    if (!logits) {
        std::cerr << "Failed to get logits\n";
        return 1;
    }
    
    // Find argmax
    int argmax_token = 0;
    float max_logit = logits[0];
    for (int i = 1; i < n_vocab; ++i) {
        if (logits[i] > max_logit) {
            max_logit = logits[i];
            argmax_token = i;
        }
    }
    
    // Save logits if output file specified
    if (!output_file.empty()) {
        write_binary(output_file.c_str(), logits, n_vocab);
    }
    
    // Print result
    char token_text[32];
    llama_token_to_piece(vocab, argmax_token, token_text, sizeof(token_text), 0, false);
    std::cout << "token=" << token << " pos=" << position 
              << " argmax=" << argmax_token << " (" << token_text << ") logit=" << max_logit << std::endl;
    
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    
    return 0;
}