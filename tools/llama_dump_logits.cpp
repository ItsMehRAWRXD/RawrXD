#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <filesystem>
#include "llama.h"

int main(int argc, char* argv[])
{
    if (argc < 4) {
        std::fprintf(stderr, "Usage: %s <model.gguf> <prompt_text> <output_dir> [n_vocab]\n", argv[0]);
        return 1;
    }

    const char* model_path = argv[1];
    const char* prompt_text = argv[2];
    const char* out_dir = argv[3];
    const int n_vocab = argc > 4 ? std::atoi(argv[4]) : 102400;

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

    // Tokenize prompt
    const struct llama_vocab* vocab = llama_model_get_vocab(model);
    std::vector<llama_token> tokens(1024);
    int n_tokens = llama_tokenize(vocab, prompt_text, std::strlen(prompt_text), tokens.data(), tokens.size(), true, false);
    if (n_tokens < 0) {
        std::fprintf(stderr, "Tokenize failed\n");
        return 3;
    }
    tokens.resize(n_tokens);
    std::printf("Prompt tokenized to %d tokens\n", n_tokens);

    // Create output directory
    std::filesystem::create_directories(out_dir);

    // Process each position: feed tokens one by one, capture logits at each step
    for (int pos = 0; pos < n_tokens; ++pos) {
        // Create batch with single token at correct position
        llama_batch batch = llama_batch_init(1, 0, 1);
        if (!batch.token) {
            std::fprintf(stderr, "llama_batch_init failed at pos %d\n", pos);
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
            std::fprintf(stderr, "llama_decode failed at pos %d\n", pos);
            llama_batch_free(batch);
            return 5;
        }

        // Get logits for this position (sequence 0, index 0)
        float* logits = llama_get_logits_ith(ctx, 0);
        if (!logits) {
            std::fprintf(stderr, "llama_get_logits_ith returned null at pos %d\n", pos);
            llama_batch_free(batch);
            return 6;
        }

        // Save logits to binary file
        char path[512];
        std::snprintf(path, sizeof(path), "%s/ref_logits_pos%d.bin", out_dir, pos);
        FILE* f = std::fopen(path, "wb");
        if (!f) {
            std::fprintf(stderr, "Failed to open %s\n", path);
            llama_batch_free(batch);
            return 6;
        }
        size_t written = std::fwrite(llama_get_logits_ith(ctx, 0), sizeof(float), n_vocab, f);
        std::fclose(f);
        llama_batch_free(batch);
        if (written != (size_t)n_vocab) {
            std::fprintf(stderr, "Incomplete write: %zu/%d\n", written, n_vocab);
            return 7;
        }
        std::printf("Wrote ref_logits_pos%d.bin (%d floats)\n", pos, n_vocab);
    }

    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}