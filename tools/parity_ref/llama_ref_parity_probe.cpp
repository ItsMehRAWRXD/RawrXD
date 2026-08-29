/*
 * llama_ref_parity_probe.cpp — EXTERNAL measuring stick for PARITY-CERT-001
 *
 * NOT a Deep2 dependency. Separate process only.
 * Deep2 remains deep2_inference_deps=NONE (no Ollama / no llama link into Deep2).
 *
 * Build: tools/parity_ref/build_llama_ref_probe.ps1
 * Usage: llama_ref_parity_probe.exe [model.gguf] [prompt] [n_predict]
 */
#include "llama.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
static void load_ggml_backends() {
    // Prebuilt llama-direct packages require explicit backend load.
    // Resolve from ggml-base.dll so we do not link ggml into Deep2 (this
    // probe is an EXTERNAL measuring stick only).
    const char* candidates[] = {
        R"(F:\~dev\llama-direct\vulkan\ggml.dll)",
        "ggml.dll",
        R"(F:\~dev\llama-direct\vulkan\ggml-base.dll)",
        "ggml-base.dll",
        nullptr
    };
    HMODULE h = nullptr;
    for (int i = 0; candidates[i]; ++i) {
        h = LoadLibraryA(candidates[i]);
        if (h) {
            std::fprintf(stderr, "REF_BACKEND_DLL=%s\n", candidates[i]);
            break;
        }
    }
    if (!h) {
        std::fprintf(stderr, "REF_BACKEND=FAIL cannot LoadLibrary ggml-base.dll\n");
        return;
    }
    using load_all_fn = void (*)(void);
    using load_all_path_fn = void (*)(const char*);
    auto fn = reinterpret_cast<load_all_fn>(GetProcAddress(h, "ggml_backend_load_all"));
    auto fnPath = reinterpret_cast<load_all_path_fn>(
        GetProcAddress(h, "ggml_backend_load_all_from_path"));
    if (fnPath) {
        fnPath(R"(F:\~dev\llama-direct\vulkan)");
    } else if (fn) {
        fn();
    } else {
        std::fprintf(stderr, "REF_BACKEND=FAIL ggml_backend_load_all missing\n");
    }
}
#else
static void load_ggml_backends() {}
#endif

static void printIds(const char* key, const std::vector<llama_token>& ids) {
    std::printf("%s=", key);
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i) std::printf(",");
        std::printf("%d", static_cast<int>(ids[i]));
    }
    std::printf("\n");
}

static void dumpTop10(const char* key, float* logits, int n_vocab, const llama_vocab* vocab) {
    std::vector<std::pair<float, int>> scored;
    scored.reserve(static_cast<size_t>(n_vocab));
    for (int i = 0; i < n_vocab; ++i) scored.push_back({logits[i], i});
    const int k = std::min(10, n_vocab);
    std::partial_sort(scored.begin(), scored.begin() + k, scored.end(),
                      [](const auto& a, const auto& b) { return a.first > b.first; });
    std::printf("%s=", key);
    for (int i = 0; i < k; ++i) {
        if (i) std::printf(",");
        char buf[256];
        const int n = llama_token_to_piece(vocab, scored[i].second, buf, (int)sizeof(buf), 0, true);
        std::string piece = (n > 0) ? std::string(buf, buf + n) : std::string();
        for (char& c : piece) {
            if (c == ',' || c == '\n' || c == '\r' || c == '\'') c = ' ';
        }
        std::printf("%d:%.6f:'%s'", scored[i].second, scored[i].first, piece.c_str());
    }
    std::printf("\n");
    if (k > 0) {
        std::printf("REF_SELECTED_ID=%d\n", scored[0].second);
        std::printf("REF_SELECTED_LOGIT=%.6f\n", scored[0].first);
    }
}

int main(int argc, char** argv) {
    const char* modelPath = R"(F:\~dev\tinyllama_fresh.gguf)";
    const char* prompt = "hello";
    int nPredict = 15;
    if (argc >= 2) modelPath = argv[1];
    if (argc >= 3) prompt = argv[2];
    if (argc >= 4) nPredict = std::atoi(argv[3]);

    std::printf("PARITY-CERT-001\n");
    std::printf("side=reference\n");
    std::printf("reference_backend=llama.cpp\n");
    std::printf("note=external_measuring_stick_only_not_a_deep2_dependency\n");
    std::printf("model=%s\n", modelPath);
    std::printf("prompt=%s\n", prompt);
    std::printf("max_new_tokens=%d\n", nPredict);
    std::printf("temperature=0\n");
    std::printf("top_k=1\n");
    fflush(stdout);

    llama_backend_init();
    load_ggml_backends();

    llama_model_params mparams = llama_model_default_params();
    mparams.n_gpu_layers = 0; // CPU: deterministic measuring stick
    llama_model* model = llama_model_load_from_file(modelPath, mparams);
    if (!model) {
        std::fprintf(stderr, "REF_LOAD=FAIL\n");
        return 2;
    }
    const llama_vocab* vocab = llama_model_get_vocab(model);

    llama_context_params cparams = llama_context_default_params();
    cparams.n_ctx = 2048;
    cparams.n_batch = 512;
    llama_context* ctx = llama_init_from_model(model, cparams);
    if (!ctx) {
        std::fprintf(stderr, "REF_CTX=FAIL\n");
        llama_model_free(model);
        return 2;
    }
    std::printf("REF_LOAD=PASS\n");

    std::vector<llama_token> promptTokens(64);
    int n = llama_tokenize(vocab, prompt, (int32_t)std::strlen(prompt),
                           promptTokens.data(), (int32_t)promptTokens.size(),
                           /*add_special*/ true, /*parse_special*/ true);
    if (n < 0) {
        promptTokens.resize((size_t)(-n));
        n = llama_tokenize(vocab, prompt, (int32_t)std::strlen(prompt),
                           promptTokens.data(), (int32_t)promptTokens.size(),
                           true, true);
    }
    if (n < 0) {
        std::fprintf(stderr, "REF_TOKENIZE=FAIL\n");
        return 2;
    }
    promptTokens.resize((size_t)n);
    printIds("REF_PROMPT_IDS", promptTokens);

    // Prefill prompt
    llama_batch batch = llama_batch_get_one(promptTokens.data(), n);
    if (llama_decode(ctx, batch) != 0) {
        std::fprintf(stderr, "REF_PREFILL=FAIL\n");
        return 2;
    }

    float* logits = llama_get_logits_ith(ctx, n - 1);
    if (!logits) logits = llama_get_logits(ctx);
    const int n_vocab = llama_vocab_n_tokens(vocab);
    dumpTop10("REF_TOP10", logits, n_vocab, vocab);

    llama_sampler* sampler = llama_sampler_chain_init(llama_sampler_chain_default_params());
    llama_sampler_chain_add(sampler, llama_sampler_init_greedy());

    std::vector<llama_token> gen;
    gen.reserve((size_t)nPredict);
    for (int t = 0; t < nPredict; ++t) {
        const llama_token id = llama_sampler_sample(sampler, ctx, -1);
        llama_sampler_accept(sampler, id);
        gen.push_back(id);
        if (llama_vocab_is_eog(vocab, id)) break;

        llama_batch step = llama_batch_get_one(const_cast<llama_token*>(&gen.back()), 1);
        if (llama_decode(ctx, step) != 0) {
            std::fprintf(stderr, "REF_DECODE=FAIL at %d\n", t);
            break;
        }
    }

    printIds("REF_GEN_IDS", gen);
    std::printf("REF_GEN_COUNT=%zu\n", gen.size());
    std::printf("REF_SIDE=DONE\n");
    fflush(stdout);

    llama_sampler_free(sampler);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return gen.empty() ? 1 : 0;
}
