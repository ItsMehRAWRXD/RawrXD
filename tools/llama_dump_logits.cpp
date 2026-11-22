// Minimal llama.cpp reference logit dumper (public C API only).
// Loads a GGUF, runs a single prompt, prints argmax + top-5 per position.
// Build: link against wp01_reference build libllama.a (+ ggml, pthread).
#include "llama.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <model.gguf> <prompt> [n_predict]\n", argv[0]);
        return 2;
    }
    const char* modelPath = argv[1];
    const std::string prompt = argv[2];
    const int nPredict = (argc > 3) ? std::atoi(argv[3]) : 1;

    llama_backend_init();
    llama_model_params mp = llama_model_default_params();
    llama_model* model = llama_model_load_from_file(modelPath, mp);
    if (!model) { std::fprintf(stderr, "LOAD_FAIL\n"); return 1; }

    llama_context_params cp = llama_context_default_params();
    cp.n_ctx = 2048;
    cp.n_threads = 8;
    cp.n_batch = 512;
    cp.embeddings = true;   // expose final hidden state for the Deep2 differential
    llama_context* ctx = llama_init_from_model(model, cp);
    if (!ctx) { std::fprintf(stderr, "CTX_FAIL\n"); return 1; }

    const llama_vocab* vocab = llama_model_get_vocab(model);
    const int nVocab = llama_vocab_n_tokens(vocab);
    const bool addBos = llama_vocab_get_add_bos(vocab);
    const bool addSpecial = llama_vocab_get_add_sep(vocab);

    // Tokenize prompt.
    std::vector<llama_token> tokens(1 + prompt.size() + 8);
    int nTokens = llama_tokenize(vocab, prompt.data(), (int)prompt.size(),
                                 tokens.data(), (int)tokens.size(), addBos, addSpecial);
    if (nTokens < 0) { std::fprintf(stderr, "TOKENIZE_FAIL\n"); return 1; }
    tokens.resize(nTokens);
    std::fprintf(stderr, "PROMPT_TOKENS=%d\n", nTokens);

    llama_batch batch = llama_batch_get_one(tokens.data(), nTokens);
    if (llama_decode(ctx, batch) != 0) { std::fprintf(stderr, "DECODE_FAIL\n"); return 1; }

    const float* logits = llama_get_logits_ith(ctx, nTokens - 1);
    if (!logits) { std::fprintf(stderr, "NO_LOGITS\n"); return 1; }

    // Argmax.
    int best = 0;
    for (int i = 1; i < nVocab; ++i) if (logits[i] > logits[best]) best = i;
    std::fprintf(stderr, "ARGMAX=%d\n", best);

    // Top-5.
    std::vector<int> idx(nVocab);
    for (int i = 0; i < nVocab; ++i) idx[i] = i;
    std::partial_sort(idx.begin(), idx.begin() + std::min(5, nVocab), idx.end(),
                      [&](int a, int b){ return logits[a] > logits[b]; });
    for (int i = 0; i < 5 && i < nVocab; ++i)
        std::fprintf(stderr, "top%d=%d:%.6f\n", i, idx[i], logits[idx[i]]);

    // Optionally generate.
    for (int step = 0; step < nPredict; ++step) {
        const float* lg = llama_get_logits_ith(ctx, (llama_decode(ctx, batch) == 0) ? 0 : 0);
        (void)lg;
        break;
    }

    // Dump final hidden state (pre-head) to a file for Deep2 differential.
    if (const char* out = std::getenv("LLAMA_DUMP_HIDDEN")) {
        const int nEmbd = llama_model_n_embd(model);
        const float* embd = llama_get_embeddings_ith(ctx, nTokens - 1);
        if (embd && nEmbd > 0) {
            std::FILE* f = std::fopen(out, "wb");
            if (f) {
                std::fwrite(embd, sizeof(float), (size_t)nEmbd, f);
                std::fclose(f);
                std::fprintf(stderr, "HIDDEN_DUMP n=%d rms=%.6f e0=%.6f e1=%.6f\n",
                             nEmbd,
                             [&]{ double s=0; for(int i=0;i<nEmbd;++i) s+=(double)embd[i]*embd[i]; return std::sqrt(s/nEmbd); }(),
                             embd[0], embd[1]);
            }
        }
    }

    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}