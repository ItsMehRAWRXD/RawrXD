// RAW-XD diagnostic runner: replay the reference token sequence and dump the
// llama.cpp attention scores (kq), softmax (kq_soft_max) and weighted V (kqv)
// per layer via the llama-kq-probe instrumentation.
#include <llama.h>

#include <cstdio>
#include <cstdlib>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 5) {
        std::fprintf(stderr, "usage: %s <model> <n_tokens> <tok0> <tok1> ...\n", argv[0]);
        return 1;
    }
    const char* model_path = argv[1];
    int32_t n_tokens = std::atoi(argv[2]);
    std::vector<int32_t> tokens;
    for (int i = 0; i < n_tokens; ++i) tokens.push_back(std::atoi(argv[3 + i]));

    llama_backend_init();

    llama_model_params mp = llama_model_default_params();
    mp.n_gpu_layers = 0;
    llama_model* model = llama_model_load_from_file(model_path, mp);
    if (!model) { std::fprintf(stderr, "model load failed\n"); return 1; }

    llama_context_params cp = llama_context_default_params();
    // replicate the reference run that produced the certified logits:
    // single-threaded, F32 KV cache, flash attention disabled, 1-token ubatch
    cp.n_ctx = 256;
    cp.n_batch = 1;
    cp.n_ubatch = 1;
    cp.n_threads = 1;
    cp.n_threads_batch = 1;
    cp.flash_attn_type = LLAMA_FLASH_ATTN_TYPE_DISABLED;
    cp.type_k = GGML_TYPE_F32;
    cp.type_v = GGML_TYPE_F32;
    cp.offload_kqv = false;
    cp.embeddings = true;
    llama_context* ctx = llama_init_from_model(model, cp);
    if (!ctx) { std::fprintf(stderr, "ctx failed\n"); return 1; }

    llama_batch batch = llama_batch_init(1, 0, 1);
    int32_t pos = 0;
    for (int step = 0; step < (int) tokens.size(); ++step) {
        batch.n_tokens = 1;
        batch.token[0] = tokens[step];
        batch.pos[0] = pos;
        batch.n_seq_id[0] = 1;
        batch.seq_id[0][0] = 0;
        batch.logits[0] = 1;
        if (llama_decode(ctx, batch) != 0) {
            std::fprintf(stderr, "decode failed at step %d\n", step);
            break;
        }
        float* logits = llama_get_logits_ith(ctx, 0);
        if (logits) {
            float mx = logits[0];
            int32_t am = 0;
            for (int32_t i = 1; i < llama_vocab_n_tokens(llama_model_get_vocab(model)); ++i) {
                if (logits[i] > mx) { mx = logits[i]; am = i; }
            }
            std::printf("step %d pos %d argmax %d max %.6f\n", step, pos, am, mx);
            char fn[1024];
            std::sprintf(fn, "%s/ref_logits_pos%d.bin", getenv("RAWRXD_PROBE_DIR"), step);
            FILE* f = fopen(fn, "wb");
            if (f) { fwrite(logits, sizeof(float), llama_vocab_n_tokens(llama_model_get_vocab(model)), f); fclose(f); }
        }
        pos++;
    }

    llama_batch_free(batch);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}
