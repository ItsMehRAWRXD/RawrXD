/* R105 Ornith hybrid load probe — llama.cpp API only; no tensor fabricate. */
#include "llama.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char ** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <gguf> [n_gpu_layers]\n", argv[0]);
        return 2;
    }
    const char * path = argv[1];
    int ngl = (argc >= 3) ? atoi(argv[2]) : 99;

    llama_backend_init();
    llama_model_params mp = llama_model_default_params();
    mp.n_gpu_layers = ngl;

    std::fprintf(stderr, "ORNITH_HYBRID_LOAD_PROBE begin path=%s n_gpu_layers=%d\n", path, ngl);
    llama_model * model = llama_model_load_from_file(path, mp);
    if (!model) {
        std::fprintf(stderr, "ORNITH_HYBRID_LOAD=FAIL\n");
        llama_backend_free();
        return 1;
    }

    const int n_layer = llama_model_n_layer(model);
    const int n_embd  = llama_model_n_embd(model);
    std::fprintf(stderr, "ORNITH_HYBRID_LOAD=PASS n_layer=%d n_embd=%d\n", n_layer, n_embd);

    llama_context_params cp = llama_context_default_params();
    cp.n_ctx = 256;
    cp.n_batch = 64;
    llama_context * ctx = llama_init_from_model(model, cp);
    if (!ctx) {
        std::fprintf(stderr, "ORNITH_HYBRID_CTX=FAIL\n");
        llama_model_free(model);
        llama_backend_free();
        return 1;
    }
    std::fprintf(stderr, "ORNITH_HYBRID_CTX=PASS\n");

    /* First real op beyond load: tokenize + decode one prompt token batch. */
    const char * prompt = "ping";
    const llama_vocab * vocab = llama_model_get_vocab(model);
    llama_token tokens[32];
    int n = llama_tokenize(vocab, prompt, (int) std::strlen(prompt), tokens, 32, true, true);
    if (n <= 0) {
        std::fprintf(stderr, "ORNITH_HYBRID_TOKENIZE=FAIL n=%d\n", n);
        llama_free(ctx);
        llama_model_free(model);
        llama_backend_free();
        return 1;
    }
    std::fprintf(stderr, "ORNITH_HYBRID_TOKENIZE=PASS n=%d\n", n);

    llama_batch batch = llama_batch_get_one(tokens, n);
    int32_t drc = llama_decode(ctx, batch);
    if (drc != 0) {
        std::fprintf(stderr, "ORNITH_HYBRID_DECODE=FAIL rc=%d\n", (int) drc);
        llama_free(ctx);
        llama_model_free(model);
        llama_backend_free();
        return 1;
    }
    std::fprintf(stderr, "ORNITH_HYBRID_DECODE=PASS n_tokens=%d\n", n);

    /* Multi-token sample loop (coherent path smoke; not semantic CERT). */
    llama_token cur = tokens[n - 1];
    int gen = 0;
    const int want = 8;
    for (; gen < want; ++gen) {
        float * logits = llama_get_logits_ith(ctx, -1);
        if (!logits) {
            std::fprintf(stderr, "ORNITH_HYBRID_LOGITS=FAIL at gen=%d\n", gen);
            break;
        }
        const int n_vocab = llama_vocab_n_tokens(vocab);
        int best = 0;
        float bestv = logits[0];
        for (int i = 1; i < n_vocab; ++i) {
            if (logits[i] > bestv) {
                bestv = logits[i];
                best = i;
            }
        }
        cur = (llama_token) best;
        if (llama_vocab_is_eog(vocab, cur)) {
            std::fprintf(stderr, "ORNITH_HYBRID_EOG at gen=%d\n", gen);
            break;
        }
        batch = llama_batch_get_one(&cur, 1);
        drc = llama_decode(ctx, batch);
        if (drc != 0) {
            std::fprintf(stderr, "ORNITH_HYBRID_GEN_DECODE=FAIL rc=%d gen=%d\n", (int) drc, gen);
            llama_free(ctx);
            llama_model_free(model);
            llama_backend_free();
            return 1;
        }
    }
    std::fprintf(stderr, "ORNITH_HYBRID_GEN=PASS gen_tokens=%d want=%d\n", gen, want);
    std::fprintf(stderr, "ORNITH_HYBRID_FIRST_OP=DECODE_OK\n");

    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}
