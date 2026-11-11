#include <windows.h>
#include <filesystem>
#include <cstdio>
#include <cstring>
#include <vector>

#include "ModelGenieRuntime.h"

int main()
{
    setvbuf(stderr, nullptr, _IONBF, 0);
    const char* path = "F:/rawrxd/DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    mg_model_config_t cfg{};
    cfg.max_seq_len = 2048;
    cfg.use_kv_cache = true;
    mg_model_t* mg = nullptr;
    if (mg_model_load(path, &cfg, &mg) != MG_SUCCESS) {
        fprintf(stderr, "load failed\n");
        return 1;
    }
    fprintf(stderr, "loaded, vocab=%zu layers=%zu bytes=%llu\n",
            mg_model_vocab_size(mg), mg_model_layer_count(mg),
            (unsigned long long) mg_model_file_bytes(mg));

    // tokenize via authority two-phase
    const char* text = "User: Hello, world!\n\nAssistant:";
    size_t cap = 0;
    mg_model_tokenize(mg, text, nullptr, &cap);
    fprintf(stderr, "needed=%zu\n", cap);
    std::vector<uint32_t> ids(cap ? cap : 1);
    mg_model_tokenize(mg, text, ids.data(), &cap);
    fprintf(stderr, "tokens:");
    for (size_t i = 0; i < cap && i < 12; ++i) fprintf(stderr, " %u", ids[i]);
    fprintf(stderr, "\n");

    mg_context_t* ctx = nullptr;
    if (mg_context_create(mg, &ctx) != MG_SUCCESS) {
        fprintf(stderr, "ctx failed\n");
        return 1;
    }
    const size_t vocab = mg_model_vocab_size(mg);
    std::vector<float> logits(vocab, 0.0f);
    size_t n = vocab;
    fprintf(stderr, "calling eval_buffer...\n");
    mg_error_t rc = mg_context_eval_buffer(ctx, ids.data(), cap, logits.data(), &n);
    fprintf(stderr, "  rc=%d n=%zu logits[0..3]=%.4f %.4f %.4f %.4f\n",
            (int) rc, n, logits[0], logits[1], logits[2], logits[3]);

    fprintf(stderr, "calling eval...\n");
    uint32_t tok = 0;
    mg_context_last_tokens(ctx, &tok, 1, nullptr);
    std::vector<float> step(vocab, 0.0f);
    size_t n2 = vocab;
    rc = mg_context_eval(ctx, tok, step.data(), &n2);
    fprintf(stderr, "  rc=%d tok=%u pos=%zu step[0..3]=%.4f %.4f %.4f %.4f\n",
            (int) rc, tok, mg_context_position(ctx),
            step[0], step[1], step[2], step[3]);
    mg_context_free(ctx);
    mg_model_free(mg);
    fprintf(stderr, "ALL DONE\n");
    return 0;
}
