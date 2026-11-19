/**
 * llama_logits_ref.cpp - RAWRXD_DEEP2_REFERENCE_ORACLE_001
 *
 * Independent numerical oracle for Deep2 CPU/GPU parity.
 *
 * Loads the exact same reduced GGUF that Deep2 benchmarks, feeds the SAME RAW TOKEN
 * IDS rather than text, disables the chat template and sampling entirely, and writes
 * raw float32 logits per position.
 *
 * llama.cpp is loaded DYNAMICALLY by absolute path. A static import of llama.lib made
 * the process bind to whichever llama.dll the Windows loader found first, which in this
 * tree is a stale F:\rawrxd\llama.dll from 2026-10-08; that produced
 * 0xC0000139 before main() ran. LoadLibraryExW with LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
 * makes the DLL's own dependencies resolve relative to its own directory, which the
 * loader probe proved works.
 *
 * Usage:
 *   llama_logits_ref.exe <model.gguf> <out_dir> <tok1> [tok2 ...]
 */
#include "llama.h"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

// ---- dynamically resolved llama.cpp entry points -----------------------------
static HMODULE g_lib = nullptr;

#define LLAMA_FN(ret, name, params, args)                                     \
    typedef ret(*name##_t) params;                                            \
    static name##_t p_##name = nullptr;                                       \
    static bool Resolve_##name() {                                            \
        p_##name = reinterpret_cast<name##_t>(GetProcAddress(g_lib, #name));  \
        return p_##name != nullptr;                                           \
    }

LLAMA_FN(void, llama_backend_init, (void), ())
LLAMA_FN(void, llama_backend_free, (void), ())
LLAMA_FN(llama_model_params, llama_model_default_params, (void), ())
LLAMA_FN(llama_context_params, llama_context_default_params, (void), ())
LLAMA_FN(llama_model*, llama_model_load_from_file,
         (const char*, llama_model_params), (a, b))
LLAMA_FN(llama_context*, llama_init_from_model,
         (llama_model*, llama_context_params), (a, b))
LLAMA_FN(llama_batch, llama_batch_init, (int, int, int), (a, b, c))
LLAMA_FN(void, llama_batch_free, (llama_batch), (a))
LLAMA_FN(int, llama_decode, (llama_context*, llama_batch), (a, b))
LLAMA_FN(float*, llama_get_logits_ith, (llama_context*, int), (a, b))
LLAMA_FN(int, llama_vocab_n_tokens, (const llama_vocab*), (a))
LLAMA_FN(const llama_vocab*, llama_model_get_vocab, (const llama_model*), (a))
LLAMA_FN(void, llama_model_free, (llama_model*), (a))
LLAMA_FN(void, llama_free, (llama_context*), (a))

#undef LLAMA_FN

static bool ResolveAll() {
    bool ok = true;
#define R(name) ok = Resolve_##name() && ok
    R(llama_backend_init);        R(llama_backend_free);
    R(llama_model_default_params); R(llama_context_default_params);
    R(llama_model_load_from_file); R(llama_init_from_model);
    R(llama_batch_init);          R(llama_batch_free);
    R(llama_decode);              R(llama_get_logits_ith);
    R(llama_vocab_n_tokens);      R(llama_model_get_vocab);
    R(llama_model_free);          R(llama_free);
#undef R
    return ok;
}

static bool WriteFloats(const std::string& path, const float* data, size_t n) {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    const size_t wrote = std::fwrite(data, sizeof(float), n, f);
    std::fclose(f);
    return wrote == n;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::printf("usage: %s <model.gguf> <out_dir> <tok1> [tok2 ...]\n", argv[0]);
        return 2;
    }
    const std::string model_path = argv[1];
    const std::string out_dir = argv[2];
    std::vector<llama_token> tokens;
    for (int i = 3; i < argc; ++i) tokens.push_back((llama_token)std::atoi(argv[i]));
    if (tokens.empty()) {
        std::printf("REF_FAIL stage=no_tokens\n");
        return 2;
    }

    g_lib = LoadLibraryExW(L"F:\\llama.cpp-ref\\build\\bin\\llama.dll", nullptr,
                           LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                           LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!g_lib) {
        std::printf("REF_FAIL stage=load_dll error=%lu\n",
                    static_cast<unsigned long>(GetLastError()));
        return 3;
    }
    if (!ResolveAll()) {
        std::printf("REF_FAIL stage=resolve_exports\n");
        return 3;
    }

    p_llama_backend_init();

    llama_model_params mp = p_llama_model_default_params();
    mp.n_gpu_layers = 0;   // reference oracle runs on CPU by design
    llama_model* model = p_llama_model_load_from_file(model_path.c_str(), mp);
    if (!model) {
        std::printf("REF_FAIL stage=model_load\n");
        return 4;
    }

    const llama_vocab* vocab = p_llama_model_get_vocab(model);
    const int n_vocab = p_llama_vocab_n_tokens(vocab);
    std::printf("REF_MODEL n_vocab=%d\n", n_vocab);

    for (llama_token t : tokens) {
        if (t < 0 || t >= n_vocab) {
            std::printf("REF_FAIL stage=token_out_of_range token=%d n_vocab=%d\n",
                        (int)t, n_vocab);
            return 5;
        }
    }

    llama_context_params cp = p_llama_context_default_params();
    cp.n_ctx = 512;
    cp.n_batch = (int)tokens.size() > 8 ? (int)tokens.size() : 8;
    cp.n_threads = 8;
    llama_context* ctx = p_llama_init_from_model(model, cp);
    if (!ctx) {
        std::printf("REF_FAIL stage=context_init\n");
        return 6;
    }

    llama_batch batch = p_llama_batch_init((int)tokens.size(), 0, 1);
    if (!batch.token) {
        std::printf("REF_FAIL stage=batch_init\n");
        return 6;
    }
    for (size_t i = 0; i < tokens.size(); ++i) {
        batch.token[i] = tokens[i];
        batch.pos[i] = (llama_pos)i;
        batch.n_seq_id[i] = 1;
        batch.seq_id[i][0] = 0;
        batch.logits[i] = 1;
    }
    // Set explicitly rather than trusting the returned count: llama_decode rejects a
    // batch with n_tokens == 0 before looking at any of the per-token fields.
    batch.n_tokens = (int)tokens.size();

    if (p_llama_decode(ctx, batch) != 0) {
        std::printf("REF_FAIL stage=decode\n");
        return 7;
    }

    for (size_t i = 0; i < tokens.size(); ++i) {
        const float* logits = p_llama_get_logits_ith(ctx, (int)i);
        if (!logits) {
            std::printf("REF_FAIL stage=logits pos=%zu\n", i);
            return 8;
        }
        char name[64];
        std::snprintf(name, sizeof(name), "ref_logits_pos%zu.bin", i);
        if (!WriteFloats(out_dir + "/" + name, logits, (size_t)n_vocab)) {
            std::printf("REF_FAIL stage=write pos=%zu\n", i);
            return 8;
        }
        int best = 0;
        for (int k = 1; k < n_vocab; ++k)
            if (logits[k] > logits[best]) best = k;
        std::printf("REF_POS pos=%zu token=%d argmax=%d logit=%.6f\n",
                    i, (int)tokens[i], best, logits[best]);
    }

    if (std::FILE* meta = std::fopen((out_dir + "/ref_meta.txt").c_str(), "w")) {
        std::fprintf(meta, "REFERENCE_ORACLE=llama.cpp\n");
        std::fprintf(meta, "REFERENCE_DLL=F:\\llama.cpp-ref\\build\\bin\\llama.dll\n");
        std::fprintf(meta, "REFERENCE_BUILD=b1-961c376\n");
        std::fprintf(meta, "REFERENCE_MODEL=%s\n", model_path.c_str());
        std::fprintf(meta, "TOKEN_IDS=");
        for (size_t i = 0; i < tokens.size(); ++i)
            std::fprintf(meta, "%s%d", i ? "," : "", (int)tokens[i]);
        std::fprintf(meta, "\nPOSITIONS=0..%zu\n", tokens.size() - 1);
        std::fprintf(meta, "LOGITS_ALL=1\n");
        std::fprintf(meta, "CHAT_TEMPLATE=DISABLED\n");
        std::fprintf(meta, "SAMPLING=DISABLED\n");
        std::fprintf(meta, "GPU_LAYERS=0\n");
        std::fprintf(meta, "KV_CACHE_INITIAL=EMPTY\n");
        std::fprintf(meta, "N_VOCAB=%d\n", n_vocab);
        std::fclose(meta);
    }

    p_llama_batch_free(batch);
    p_llama_free(ctx);
    p_llama_model_free(model);
    p_llama_backend_free();
    FreeLibrary(g_lib);

    std::printf("REF_PASS n_vocab=%d positions=%zu\n", n_vocab, tokens.size());
    return 0;
}