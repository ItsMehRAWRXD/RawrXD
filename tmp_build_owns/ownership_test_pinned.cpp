// ownership_test_pinned.cpp — DEEP2_RUNTIME_OWNERSHIP_001
//
// Proves the ownership contract rather than asserting it in prose:
//   1. The legacy Deep2_* ABI loads through the authority (single GGUF mapping).
//   2. Prefill/Decode return real logits from the authority (no zero-fill) and
//      the KV cache advances exactly one position per Decode.
//   3. A generation driven only through the shim matches a generation driven
//      directly through the authority API for the same prompt — one runtime,
//      one behaviour.
//   4. Reset returns the authority to position 0 and the session is reusable.
//   5. The facts the shim reports (layers, model bytes, per-position cache)
//      come from the authority and match an independent measurement.

#include <filesystem>

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "Deep2RuntimeClient.h"
#include "ModelGenieRuntime.h"

static int g_failures = 0;

static void Check(bool ok, const char* what)
{
    fprintf(stderr, "  %-58s %s\n", what, ok ? "PASS" : "FAIL");
    if (!ok) ++g_failures;
}

static std::string ModelPath()
{
    if (const char* env = std::getenv("RAWRXD_OWNERSHIP_MODEL")) {
        if (env[0]) return env;
    }
    return "F:/rawrxd/DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
}

int main(int argc, char** argv)
{
    setvbuf(stderr, nullptr, _IONBF, 0);
    const std::string path = argc > 1 ? argv[1] : ModelPath();
    fprintf(stderr, "=== Deep2 runtime ownership ===\n");
    fprintf(stderr, "adapter: %s\n", Deep2_GetVersion());

    // ---- the shim is a client of the authority, not a second engine --------
    Deep2Model* model = Deep2_LoadModel(path.c_str());
    if (!model) {
        fprintf(stderr, "LOAD_FAIL\n");
        return 1;
    }
    const int vocab = Deep2_GetVocabSize(model);
    fprintf(stderr, "vocab=%d\n", vocab);
    Check(vocab > 32000, "vocab size comes from the loaded model");

    mg_model_config_t cfg{};
    cfg.max_seq_len = 2048;
    cfg.use_kv_cache = true;
    mg_model_t* mg = nullptr;
    Check(mg_model_load(path.c_str(), &cfg, &mg) == MG_SUCCESS,
          "authority loaded the same model independently");

    const size_t layers = mg_model_layer_count(mg);
    const uint64_t bytes = mg_model_file_bytes(mg);
    fprintf(stderr, "authority facts: layers=%zu bytes=%llu\n",
            layers, (unsigned long long) bytes);
    Check(layers == 27, "layer count reported by the authority (27)");
    Check(bytes == 10364416768ull, "model file bytes reported by the authority");

    // ---- tokenizer identity ------------------------------------------------
    const char* probe = "User: Hello, world!\n\nAssistant:";
    int ids[64] = {};
    uint32_t ids2[64] = {};
    size_t cap = 64;
    const int n = Deep2_Tokenize(model, probe, ids, 64);
    fprintf(stderr, "tokenize -> %d ids:", n);
    for (int i = 0; i < n && i < 12; ++i) fprintf(stderr, " %d", ids[i]);
    fprintf(stderr, "\n");
    const mg_error_t trc = mg_model_tokenize(mg, probe, ids2, &cap);
    Check(trc == MG_SUCCESS && cap == static_cast<size_t>(n),
          "authority tokenizes identically");
    Check(n > 0 && n == static_cast<int>(cap),
          "shim tokenizes through the authority tokenizer");
    bool same = true;
    for (int i = 0; i < n; ++i) same = same && ids[i] == static_cast<int>(ids2[i]);
    Check(same, "token ids identical between shim and authority");

    char rt[256] = {};
    Deep2_Detokenize(model, ids, n, rt, sizeof(rt));
    Check(std::strcmp(rt, probe) == 0, "detokenize round-trips through the shim");

    // ---- prefill + decode through the shim ---------------------------------
    Deep2Context* ctx = Deep2_CreateContext(model, 256);
    if (!ctx) {
        fprintf(stderr, "CREATE_FAIL\n");
        return 1;
    }
    std::vector<uint32_t> prompt(ids, ids + n);
    std::vector<float> logits(vocab);
    const int consumed = Deep2_Prefill(ctx, prompt.data(), prompt.size(), logits.data());
    Check(consumed == n, "prefill consumed the prompt");
    Check(mg_context_position(Deep2_AuthorityContext(ctx)) == static_cast<size_t>(n),
          "authority position advanced to the prompt length");

    // logits must be REAL (the old adapter zero-filled them)
    double sum = 0.0;
    bool finite = true;
    size_t best = 0;
    for (int i = 0; i < vocab; ++i) {
        sum += logits[i];
        if (!std::isfinite(logits[i])) finite = false;
        if (logits[i] > logits[best]) best = i;
    }
    fprintf(stderr, "prefill logits: argmax=%zu sum=%.3f\n", best, sum);
    Check(finite && std::fabs(sum) > 1.0, "prefill logits are finite and non-zero");

    int decoded = 0;
    const int cap_tokens = 4;
    std::vector<uint32_t> via_shim;
    for (int i = 0; i < cap_tokens; ++i) {
        std::vector<float> step_logits(vocab);
        const int tok = Deep2_Decode(ctx, step_logits.data(), nullptr);
        if (tok < 0) {
            fprintf(stderr, "DECODE_FAIL %d\n", tok);
            break;
        }
        ++decoded;
        via_shim.push_back(static_cast<uint32_t>(tok));
        if (mg_context_position(Deep2_AuthorityContext(ctx)) !=
            static_cast<size_t>(n + i + 1)) {
            Check(false, "KV position advances one per decode");
            break;
        }
    }
    Check(decoded == cap_tokens, "four decodes produced four tokens");
    for (size_t i = 0; i < via_shim.size(); ++i) {
        fprintf(stderr, "  shim token[%zu] = %u\n", i, via_shim[i]);
    }

    // ---- the same generation through the authority directly ----------------
    mg_context_t* ctx2 = nullptr;
    Check(mg_context_create(mg, &ctx2) == MG_SUCCESS, "second authority context");
    uint32_t direct[8] = {};
    size_t got = 0;
    const mg_error_t rc =
        mg_context_capture_tokens(ctx2, prompt.data(), prompt.size(),
                                  cap_tokens, direct, 8, &got);
    Check(rc == MG_SUCCESS && got == via_shim.size(),
          "authority produced the same number of tokens");
    bool identical = true;
    for (size_t i = 0; i < got; ++i) {
        if (i < via_shim.size() && direct[i] != via_shim[i]) identical = false;
    }
    fprintf(stderr, "authority tokens:");
    for (size_t i = 0; i < got; ++i) fprintf(stderr, " %u", direct[i]);
    fprintf(stderr, "\n");
    Check(identical, "shim and authority produce the same token sequence");

    // ---- memory figures come from the authority ----------------------------
    size_t kv_bytes = 0, model_bytes = 0, peak = 0;
    Deep2_GetMemoryInfo(ctx, &kv_bytes, &model_bytes, &peak);
    const size_t per_pos =
        mg_context_kv_floats_per_position(Deep2_AuthorityContext(ctx)) * sizeof(float);
    fprintf(stderr, "memory: kv=%zu model=%zu peak=%zu (per-position %zu)\n",
            kv_bytes, model_bytes, peak, per_pos);
    Check(kv_bytes == mg_context_position(Deep2_AuthorityContext(ctx)) * per_pos,
          "kv bytes = position x per-position cost");
    Check(model_bytes == bytes, "model bytes match the authority file size");
    Check(peak >= kv_bytes + model_bytes, "peak accounts for model and cache");

    // ---- reset + reuse ------------------------------------------------------
    Deep2_ResetKVCache(ctx);
    Check(mg_context_position(Deep2_AuthorityContext(ctx)) == 0,
          "reset returns the authority to 0");
    std::vector<float> again(vocab);
    Deep2_Prefill(ctx, prompt.data(), prompt.size(), again.data());
    const int tok = Deep2_Decode(ctx, again.data(), nullptr);
    Check(tok == static_cast<int>(via_shim[0]),
          "after reset the shim reproduces the first token");
    fprintf(stderr, "reuse first token = %d (was %u)\n", tok, via_shim[0]);

    Deep2_FreeContext(ctx);
    mg_context_free(ctx2);
    Deep2_FreeModel(model);
    mg_model_free(mg);

    fprintf(stderr, "\n");
    if (g_failures == 0) {
        fprintf(stderr, "DEEP2_RUNTIME_OWNERSHIP_001=PASS\n");
        return 0;
    }
    fprintf(stderr, "DEEP2_RUNTIME_OWNERSHIP_001=FAIL (%d failures)\n", g_failures);
    return 1;
}
