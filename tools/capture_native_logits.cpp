// Regenerate the native teacher-forced logits with the CURRENT runtime.
//
// The prompt is the reference generator's: "User: Hello, world!\n\nAssistant:"
// fed one token at a time through the same mg_context_generate prefill the
// production DLL uses, capturing mg_context_logits after every position. Writes
// native_tf_logits_pos%d.bin into the directory given by argv[2] so the
// existing evidence artifacts are never overwritten.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ModelGenieRuntime.h"

int main(int argc, char* argv[])
{
    const char* gguf = argc > 1 ? argv[1] : "F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    const char* outdir = argc > 2 ? argv[2]
        : "F:\\rawrxd\\evidence\\RAWRXD_CORE_DLL_NATIVE_E2E_001\\native_tf_current";
    // argv[3] is either the token list "1,185,16,..." or a prompt string.
    // A prompt string is tokenized (BOS is prepended when the vocab does not
    // emit it, matching the production DLL), while a comma/space separated list
    // of ids is used verbatim so a reference's forced sequence can be replayed
    // exactly.

    mg_model_config_t cfg{};
    cfg.max_seq_len = 1024;
    cfg.use_kv_cache = true;

    mg_model_t* m = nullptr;
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

    std::vector<uint32_t> tokens;
    bool tokenList = false;
    for (const char* p = (argc > 3 ? argv[3] : ""); p && *p; ) {
        if ((*p >= '0' && *p <= '9') || *p == ',' || *p == ' ') {
            tokenList = true;
            break;
        }
        ++p;
    }

    if (tokenList) {
        const char* p = argv[3];
        while (*p) {
            char* endp = nullptr;
            const unsigned long v = std::strtoul(p, &endp, 10);
            if (endp == p) { ++p; continue; }
            tokens.push_back(static_cast<uint32_t>(v));
            p = endp;
            while (*p == ',' || *p == ' ') ++p;
        }
    } else {
        const char* prompt = argc > 3 ? argv[3] : "User: Hello, world!\n\nAssistant:";
        size_t n = 0;
        if (mg_model_tokenize(m, prompt, nullptr, &n) != MG_SUCCESS || n == 0) {
            std::fprintf(stderr, "tokenize capacity failed\n");
            mg_context_free(ctx);
            mg_model_free(m);
            return 3;
        }
        tokens.resize(n);
        size_t fill = n;
        if (mg_model_tokenize(m, prompt, tokens.data(), &fill) != MG_SUCCESS) {
            std::fprintf(stderr, "tokenize fill failed\n");
            mg_context_free(ctx);
            mg_model_free(m);
            return 4;
        }
        tokens.resize(fill);
        if (tokens.empty() ||
            tokens[0] != mg_model_bos_token_id(m)) {
            tokens.insert(tokens.begin(), mg_model_bos_token_id(m));
        }
    }
    const size_t fill = tokens.size();
    std::printf("tokens (%zu):", fill);
    for (size_t i = 0; i < fill; ++i) std::printf(" %u", tokens[i]);
    std::printf("\n");
    std::fflush(stdout);

    mg_generation_config_t genCfg{};
    genCfg.max_tokens = 1;   // prefill prefix, then read that position's logits
    genCfg.temperature = 0.0f;

    size_t captured = 0;
    for (size_t prefix = 1; prefix <= fill; ++prefix) {
        mg_context_reset(ctx);
        const mg_error_t rc = mg_context_generate(ctx, tokens.data(), prefix, &genCfg,
                                                 nullptr, nullptr);
        if (rc != MG_SUCCESS) {
            std::fprintf(stderr, "generate failed at prefix %zu (rc=%d)\n", prefix, (int)rc);
            break;
        }
        if (mg_context_position(ctx) != prefix) {
            std::fprintf(stderr, "unexpected position %zu (wanted %zu)\n",
                         mg_context_position(ctx), prefix);
            break;
        }
        size_t count = 0;
        const float* logits = mg_context_logits(ctx, &count);
        if (!logits || count == 0) {
            std::fprintf(stderr, "no logits at prefix %zu\n", prefix);
            break;
        }
        char path[512];
        std::snprintf(path, sizeof(path), "%s\\native_tf_logits_pos%zu.bin", outdir,
                      prefix - 1);
        FILE* f = std::fopen(path, "wb");
        if (!f) {
            std::fprintf(stderr, "open failed: %s\n", path);
            break;
        }
        std::fwrite(logits, sizeof(float), count, f);
        std::fclose(f);
        ++captured;
    }
    std::fprintf(stderr, "captured %zu positions into %s\n", captured, outdir);
    mg_context_free(ctx);
    mg_model_free(m);
    return captured ? 0 : 5;
}
