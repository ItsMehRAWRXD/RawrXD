// Prefill prompt batch, then TF-decode gen tokens; dump tip14 logits (pos22).
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <filesystem>
#include "llama.h"
#include "ggml-backend.h"

int main(int argc, char** argv) {
    if (argc < 5) {
        std::fprintf(stderr, "Usage: %s <gguf> <tokens.txt> <outdir> <n_prompt>\n", argv[0]);
        return 1;
    }
    FILE* tf = std::fopen(argv[2], "r");
    if (!tf) return 2;
    std::vector<llama_token> tok;
    for (llama_token t; std::fscanf(tf, "%d", &t) == 1;) tok.push_back(t);
    std::fclose(tf);
    const int n_prompt = std::atoi(argv[4]);
    if ((int)tok.size() < n_prompt + 1) return 3;
    std::filesystem::create_directories(argv[3]);

    ggml_backend_load_all();
    llama_backend_init();
    auto mp = llama_model_default_params();
    mp.n_gpu_layers = 0;
    llama_model* model = llama_model_load_from_file(argv[1], mp);
    if (!model) return 4;
    auto cp = llama_context_default_params();
    cp.n_ctx = 2048;
    cp.n_batch = 512;
    llama_context* ctx = llama_init_from_model(model, cp);
    if (!ctx) return 5;

    auto dump = [&](int pos) {
        float* logits = llama_get_logits_ith(ctx, 0);
        if (!logits) return;
        const int nv = llama_vocab_n_tokens(llama_model_get_vocab(model));
        char path[512];
        std::snprintf(path, sizeof(path), "%s/cont_logits_pos%d.bin", argv[3], pos);
        FILE* f = std::fopen(path, "wb");
        if (!f) return;
        std::fwrite(logits, sizeof(float), nv, f);
        std::fclose(f);
        int a15233 = 15233, a29213 = 29213, arg = 0;
        float mx = logits[0];
        for (int i = 1; i < nv; ++i) if (logits[i] > mx) { mx = logits[i]; arg = i; }
        std::printf("pos=%d arg=%d max=%.6f 15233=%.6f 29213=%.6f m=%.6f\n",
            pos, arg, mx, logits[a15233], logits[a29213],
            logits[a15233] - logits[a29213]);
    };

    // Prefill prompt as one batch (mirrors llama-cli).
    llama_batch b = llama_batch_init(n_prompt, 0, 1);
    b.n_tokens = n_prompt;
    for (int i = 0; i < n_prompt; ++i) {
        b.token[i] = tok[i];
        b.pos[i] = i;
        b.n_seq_id[i] = 1;
        b.seq_id[i][0] = 0;
        b.logits[i] = (i == n_prompt - 1);
    }
    if (llama_decode(ctx, b) != 0) return 6;
    llama_batch_free(b);
    dump(n_prompt - 1);

    // Teacher-force remaining tokens one-by-one.
    for (int pos = n_prompt; pos < (int)tok.size(); ++pos) {
        llama_batch s = llama_batch_init(1, 0, 1);
        s.n_tokens = 1;
        s.token[0] = tok[pos];
        s.pos[0] = pos;
        s.n_seq_id[0] = 1;
        s.seq_id[0][0] = 0;
        s.logits[0] = 1;
        if (llama_decode(ctx, s) != 0) return 7;
        llama_batch_free(s);
        dump(pos);
    }
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}
