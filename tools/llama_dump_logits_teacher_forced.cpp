// llama_dump_logits_teacher_forced.cpp
// Extended version that accepts token IDs directly for teacher-forced mode
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <filesystem>
#include "llama.h"

void print_usage(const char* argv0) {
    std::fprintf(stderr, "Usage: %s <model.gguf> <tokens_file> <output_dir> [n_vocab]\n", argv0);
    std::fprintf(stderr, "  tokens_file: text file with space-separated token IDs\n");
    std::fprintf(stderr, "  output_dir: directory to write ref_logits_pos*.bin and ref_hidden_pos*.bin\n");
}

int main(int argc, char* argv[])
{
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char* model_path = argv[1];
    const char* tokens_file = argv[2];
    const char* out_dir = argv[3];
    const int n_vocab = argc > 4 ? std::atoi(argv[4]) : 102400;

    // Read token IDs from file
    FILE* tf = std::fopen(tokens_file, "r");
    if (!tf) {
        std::fprintf(stderr, "Failed to open tokens file: %s\n", tokens_file);
        return 1;
    }
    
    std::vector<llama_token> tokens;
    llama_token tok;
    while (std::fscanf(tf, "%d", &tok) == 1) {
        tokens.push_back(tok);
    }
    std::fclose(tf);
    
    if (tokens.empty()) {
        std::fprintf(stderr, "No tokens found in file\n");
        return 1;
    }
    
    std::printf("Loaded %zu tokens from %s\n", tokens.size(), tokens_file);

    // Initialize llama.cpp
    llama_backend_init();

    // Load model
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0; // CPU only
    struct llama_model* model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        std::fprintf(stderr, "Failed to load model: %s\n", model_path);
        return 1;
    }

    // Create context
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 1024;
    ctx_params.n_batch = 1024;
    ctx_params.embeddings = false;
    struct llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::fprintf(stderr, "Failed to create context\n");
        llama_model_free(model);
        return 2;
    }

    // Create output directory
    std::filesystem::create_directories(out_dir);

    // Process each position: feed tokens one by one, capture logits and hidden state at each step
    for (size_t pos = 0; pos < tokens.size(); ++pos) {
        // Create batch with single token at correct position
        llama_batch batch = llama_batch_init(1, 0, 1);
        if (!batch.token) {
            std::fprintf(stderr, "llama_batch_init failed at pos %zu\n", pos);
            return 4;
        }
        batch.n_tokens = 1;

        batch.token[0] = tokens[pos];
        batch.pos[0] = pos;
        batch.n_seq_id[0] = 1;
        batch.seq_id[0][0] = 0; // sequence 0
        batch.logits[0] = 1;    // we want logits for this token

        // Decode
        if (llama_decode(ctx, batch) != 0) {
            std::fprintf(stderr, "llama_decode failed at pos %zu\n", pos);
            llama_batch_free(batch);
            return 5;
        }

        // Get logits for this position (sequence 0, index 0)
        float* logits = llama_get_logits_ith(ctx, 0);
        if (!logits) {
            std::fprintf(stderr, "llama_get_logits_ith returned null at pos %zu\n", pos);
            llama_batch_free(batch);
            return 6;
        }

        // Get embeddings (final hidden state before LM-head)
        const float* embeddings = llama_get_embeddings_ith(ctx, 0);
        
        // Save logits to binary file
        char path[512];
        std::snprintf(path, sizeof(path), "%s/ref_logits_pos%zu.bin", out_dir, pos);
        FILE* f = std::fopen(path, "wb");
        if (!f) {
            std::fprintf(stderr, "Failed to open %s\n", path);
            llama_batch_free(batch);
            return 6;
        }
        size_t written = std::fwrite(logits, sizeof(float), n_vocab, f);
        std::fclose(f);
        if (written != (size_t)n_vocab) {
            std::fprintf(stderr, "Incomplete write: %zu/%d\n", written, n_vocab);
            return 7;
        }
        std::printf("Wrote ref_logits_pos%zu.bin (%d floats)\n", pos, n_vocab);

        // Save hidden state to binary file
        if (embeddings) {
            std::snprintf(path, sizeof(path), "%s/ref_hidden_pos%zu.bin", out_dir, pos);
            f = std::fopen(path, "wb");
            if (f) {
                size_t hidden_written = std::fwrite(embeddings, sizeof(float), 2048, f);
                std::fclose(f);
                if (hidden_written == 2048) {
                    std::printf("Wrote ref_hidden_pos%zu.bin (%zu floats)\n", pos, hidden_written);
                } else {
                    std::fprintf(stderr, "Incomplete hidden write: %zu/2048\n", hidden_written);
                }
            }
        } else {
            std::fprintf(stderr, "llama_get_embeddings_ith returned null at pos %zu\n", pos);
        }

        llama_batch_free(batch);
    }

    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}