// llama_logits.c — A02/A03 independent full-logit capture via the llama.cpp API.
// Usage: llama_logits.exe <model.gguf> <out.bin> <tok_id> [<tok_id> ...] [--ngl N]
// Writes: uint32 n_vocab, uint32 pos, then n_vocab float32 logits for the last position.
#include "llama.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s <model> <out.bin> <tok...> [--ngl N]\n", argv[0]); return 2; }
    const char* model = argv[1];
    const char* outp = argv[2];
    int ngl = 99;
    int toks[256]; int nt = 0;
    for (int i = 3; i < argc; ++i) {
        if (!strcmp(argv[i], "--ngl") && i + 1 < argc) { ngl = atoi(argv[++i]); continue; }
        if (nt < 256) toks[nt++] = atoi(argv[i]);
    }
    if (nt == 0) { fprintf(stderr, "no tokens\n"); return 2; }

    llama_backend_init();
    llama_model_params mp = llama_model_default_params();
    mp.n_gpu_layers = ngl;
    llama_model* m = llama_model_load_from_file(model, mp);
    if (!m) { fprintf(stderr, "load failed\n"); return 1; }
    llama_context_params cp = llama_context_default_params();
    cp.n_ctx = 2048; cp.n_threads = 8; cp.n_threads_batch = 8;
    llama_context* c = llama_init_from_model(m, cp);
    if (!c) { fprintf(stderr, "ctx failed\n"); return 1; }

    llama_batch batch = llama_batch_get_one(toks, nt);
    if (llama_decode(c, batch) != 0) { fprintf(stderr, "decode failed\n"); return 1; }
    float* logits = llama_get_logits_ith(c, nt - 1);
    int nv = (int)llama_vocab_n_tokens(llama_model_get_vocab(m));

    FILE* f = fopen(outp, "wb");
    if (!f) { fprintf(stderr, "open out failed\n"); return 1; }
    unsigned int hdr[2] = { (unsigned int)nv, (unsigned int)(nt - 1) };
    fwrite(hdr, sizeof(unsigned int), 2, f);
    fwrite(logits, sizeof(float), (size_t)nv, f);
    fclose(f);
    fprintf(stderr, "OK nv=%d pos=%d -> %s\n", nv, nt - 1, outp);
    llama_free(c);
    llama_model_free(m);
    llama_backend_free();
    return 0;
}