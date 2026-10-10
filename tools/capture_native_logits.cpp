#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <filesystem>
#include "ModelGenieRuntime.h"

int main(int argc, char* argv[])
{
    const char* gguf = argc > 1 ? argv[1] : "F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    const char* prompt = argc > 2 ? argv[2] : "<｜begin▁of▁sentence｜>User: Hello, world!\n\nAssistant:";
    const char* outdir = argc > 3 ? argv[3] : "F:\\rawrxd\\evidence\\RAWRXD_CORE_DLL_NATIVE_E2E_001";

    mg_model_t* m = nullptr;
    mg_model_config_t cfg{};
    cfg.max_seq_len = 1024;
    cfg.use_kv_cache = true;
    if (mg_model_load(gguf, &cfg, &m) != MG_SUCCESS || !m) {
        std::fprintf(stderr, "mg_model_load failed\n");
        return 1;
    }

    mg_context_t* ctx = nullptr;
    if (mg_context_create(m, &ctx) != MG_SUCCESS || !ctx) {
        std::fprintf(stderr, "mg_context_create failed\n");
        mg_model_free(m);
        return 2;
    }

    // Tokenize prompt
    size_t n = 0;
    mg_error_t rc = mg_model_tokenize(m, prompt, nullptr, &n);
    if ((rc != MG_SUCCESS && rc != MG_ERROR_INVALID_ARGUMENT) || n == 0) {
        std::fprintf(stderr, "tokenize capacity failed\n");
        mg_context_destroy(ctx);
        mg_model_free(m);
        return 3;
    }
    std::vector<uint32_t> tokens(n);
    size_t fill = n;
    rc = mg_model_tokenize(m, prompt, tokens.data(), &fill);
    if (rc != MG_SUCCESS || fill != n) {
        std::fprintf(stderr, "tokenize fill failed\n");
        mg_context_destroy(ctx);
        mg_model_free(m);
        return 4;
    }
    std::printf("Prompt tokens: %zu\n", n);
    for (size_t i = 0; i < n; ++i) {
        std::printf("%zu: %u\n", i, tokens[i]);
    }

    // Prefill all tokens and capture logits at each position
    mg_generation_config_t genCfg{};
    genCfg.max_tokens = 0; // Only prefill
    genCfg.temperature = 0.0f;

    for (size_t pos = 0; pos < tokens.size(); ++pos) {
        std::vector<uint32_t> prefix(tokens.begin(), tokens.begin() + pos + 1);
        std::vector<uint32_t> produced = mg_context_generate_with_logits(ctx, prefix.data(), prefix.size(), &genCfg);
        
        // Get logits from the context
        const std::vector<float>* logits = mg_context_get_logits(ctx);
        if (logits && !logits->empty()) {
            char path[512];
            std::snprintf(path, sizeof(path), "%s\\native_tf_logits_pos%zu.bin", outdir, pos);
            FILE* f = std::fopen(path, "wb");
            if (f) {
                std::fwrite(logits->data(), sizeof(float), logits->size(), f);
                std::fclose(f);
                std::printf("Wrote %s (%zu floats)\n", path, logits->size());
            }
        }
    }

    mg_context_destroy(ctx);
    mg_model_free(m);
    return 0;
}