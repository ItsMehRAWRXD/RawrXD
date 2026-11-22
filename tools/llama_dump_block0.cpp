// ============================================================================
// llama_dump_block0.cpp — MLA-H08 reference block-0 tensor capture.
//
// Links against the DIAGNOSTIC libllama.a (wp01_diagnostic_llama) which has
// ggml_set_name(cur, name) in llm_graph_context::cb(), so every graph tensor
// carries its name. A cb_eval handler captures blk.0 tensors to .f32 files.
//
// Protocol: ask=true -> declare whether we want to observe this tensor; the
// scheduler then re-invokes with ask=false for the tensors we selected, at
// which point the tensor is computed and (on CPU) host-readable.
// ============================================================================
#include "llama.h"
#include "ggml.h"
#include "ggml-backend.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

struct DumpState {
    std::string dir;
    int captured = 0;
};

// Return true only for the block-0 MLA intermediates we want to capture.
static bool wantTensor(const ggml_tensor* t) {
    if (!t || !t->name || !*t->name) return false;
    return std::strcmp(t->name, "Qcur-0") == 0 ||
           std::strcmp(t->name, "kv_cmpr-0") == 0 ||
           std::strcmp(t->name, "Vcur-0") == 0 ||
           std::strcmp(t->name, "Kcur-0") == 0 ||
           std::strcmp(t->name, "q-0") == 0;
}

static bool dumpCbEval(ggml_tensor* t, bool ask, void* ud) {
    auto* st = static_cast<DumpState*>(ud);
    if (!st || !t) return false;

    const bool selected = wantTensor(t);
    if (ask) return selected;

    if (!selected) return true;

    if (!t->data) {
        std::fprintf(stderr, "[blk0-dump] SKIP %s (no data)\n", t->name);
        return true;
    }
    if (t->type != GGML_TYPE_F32) {
        std::fprintf(stderr, "[blk0-dump] SKIP %s (type=%d not F32)\n",
                     t->name, (int)t->type);
        return true;
    }
    const size_t nElems = ggml_nelements(t);
    if (nElems == 0 || nElems > 64 * 1024 * 1024) return true;

    std::vector<float> buf(nElems);
    std::memcpy(buf.data(), t->data, nElems * sizeof(float));

    std::string safe = t->name;
    for (char& c : safe) if (!(std::isalnum((unsigned char)c) || c=='_' || c=='-')) c = '_';
    char path[512];
    std::snprintf(path, sizeof(path), "%s/%s.f32", st->dir.c_str(), safe.c_str());
    std::FILE* f = std::fopen(path, "wb");
    if (f) {
        std::fwrite(buf.data(), sizeof(float), nElems, f);
        std::fclose(f);
        double ss = 0.0; size_t nf = 0;
        for (float v : buf) { if (!std::isfinite(v)) ++nf; else ss += (double)v*v; }
        std::fprintf(stderr, "[blk0-dump] %s n=%zu rms=%.6g nonfinite=%zu\n",
                     path, nElems, nElems ? std::sqrt(ss/nElems) : 0.0, nf);
        ++st->captured;
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s <model.gguf> <prompt> <dump_dir>\n", argv[0]);
        return 2;
    }
    const char* modelPath = argv[1];
    const std::string prompt = argv[2];
    DumpState st;
    st.dir = argv[3];

    llama_backend_init();
    llama_model_params mp = llama_model_default_params();
    llama_model* model = llama_model_load_from_file(modelPath, mp);
    if (!model) { std::fprintf(stderr, "LOAD_FAIL\n"); return 1; }

    llama_context_params cp = llama_context_default_params();
    cp.n_ctx = 2048;
    cp.n_threads = 8;
    cp.n_batch = 512;
    cp.embeddings = true;
    cp.cb_eval = dumpCbEval;
    cp.cb_eval_user_data = &st;
    llama_context* ctx = llama_init_from_model(model, cp);
    if (!ctx) { std::fprintf(stderr, "CTX_FAIL\n"); return 1; }

    const llama_vocab* vocab = llama_model_get_vocab(model);
    const bool addBos = llama_vocab_get_add_bos(vocab);
    std::vector<llama_token> tokens(1 + prompt.size() + 8);
    int nTokens = llama_tokenize(vocab, prompt.data(), (int)prompt.size(),
                                 tokens.data(), (int)tokens.size(), addBos, false);
    if (nTokens < 0) { std::fprintf(stderr, "TOKENIZE_FAIL\n"); return 1; }
    tokens.resize(nTokens);
    std::fprintf(stderr, "PROMPT_TOKENS=%d\n", nTokens);

    llama_batch batch = llama_batch_get_one(tokens.data(), nTokens);
    if (llama_decode(ctx, batch) != 0) { std::fprintf(stderr, "DECODE_FAIL\n"); return 1; }

    std::fprintf(stderr, "CAPTURED=%d\n", st.captured);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return st.captured > 0 ? 0 : 1;
}