#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include "llama.h"

// Helper to dump raw tensor elements to disk
static void dump_tensor_binary(const std::string& filename, const float* data, size_t count) {
    if (!data || count == 0) return;
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(data), count * sizeof(float));
        file.close();
        std::fprintf(stderr, "[DUMP] Wrote %zu floats to %s\n", count, filename.c_str());
    } else {
        std::fprintf(stderr, "[DUMP ERROR] Failed to open %s\n", filename.c_str());
    }
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::fprintf(stderr, "Usage: %s <model.gguf> <output_dir>\n", argv[0]);
        return 1;
    }

    const char* model_path = argv[1];
    const char* out_dir = argv[2];

    // Initialize llama.cpp
    llama_backend_init();

    // Load model
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    struct llama_model* model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        std::fprintf(stderr, "Failed to load model\n");
        return 1;
    }

    // Create context with small batch for teacher forcing
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 1024;
    ctx_params.n_batch = 2;
    ctx_params.embeddings = false;
    struct llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::fprintf(stderr, "Failed to create context\n");
        llama_model_free(model);
        return 2;
    }

    // Enable tensor capture for numerical parity
    // llama_set_capture(ctx, out_dir, true);

    // Tokenize the 2-token prompt: position 0 = BOS (1), position 1 = 185
    llama_token tokens[] = {1, 185};
    const int n_tokens = 2;

    // Create output directory
    std::filesystem::create_directories(out_dir);

    // Process tokens in a single batch to trigger graph building and capture
    llama_batch batch = llama_batch_init(2, 0, 1);
    if (!batch.token) {
        std::fprintf(stderr, "llama_batch_init failed\n");
        return 3;
    }
    batch.n_tokens = 2;
    batch.token[0] = tokens[0];
    batch.token[1] = tokens[1];
    batch.pos[0] = 0;
    batch.pos[1] = 1;
    batch.n_seq_id[0] = 1;
    batch.n_seq_id[1] = 1;
    batch.seq_id[0][0] = 0;
    batch.seq_id[1][0] = 0;
    batch.logits[0] = 1;
    batch.logits[1] = 1;

    if (llama_decode(ctx, batch) != 0) {
        std::fprintf(stderr, "llama_decode failed\n");
        llama_batch_free(batch);
        return 4;
    }

    // Get logits for both positions
    const int n_vocab = 102400;
    for (int pos = 0; pos < 2; ++pos) {
        float* logits = llama_get_logits_ith(ctx, pos);
        if (!logits) {
            std::fprintf(stderr, "llama_get_logits_ith returned null at pos %d\n", pos);
            llama_batch_free(batch);
            return 5;
        }

        char path[512];
        std::snprintf(path, sizeof(path), "%s/ref_logits_pos%d.bin", out_dir, pos);
        FILE* f = std::fopen(path, "wb");
        if (!f) {
            std::fprintf(stderr, "Failed to open %s\n", path);
            llama_batch_free(batch);
            return 6;
        }
        size_t written = std::fwrite(logits, sizeof(float), n_vocab, f);
        std::fclose(f);
        llama_batch_free(batch);
        if (written != (size_t)n_vocab) {
            std::fprintf(stderr, "Incomplete write: %zu/%d\n", written, n_vocab);
            return 7;
        }
        std::printf("Wrote ref_logits_pos%d.bin (%d floats)\n", pos, n_vocab);
    }

    llama_batch_free(batch);

    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}