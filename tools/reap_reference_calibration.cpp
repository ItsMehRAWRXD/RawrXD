#include "llama.h"
#include "ggml.h"

#include <windows.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using ggml_backend_tensor_get_fn = void (*)(const ggml_tensor *, void *, size_t, size_t);
static ggml_backend_tensor_get_fn p_ggml_backend_tensor_get = nullptr;

struct Capture {
    bool enabled = false;
    bool invalid = false;
    std::string error;
    std::map<int, std::vector<int32_t>> ids;
    std::map<int, std::vector<float>> weights;
};

static bool starts(const char * s, const char * p) {
    return s && p && std::strncmp(s, p, std::strlen(p)) == 0;
}

static bool parse_layer(const char * name, const char * prefix, int & layer) {
    if (!starts(name, prefix)) return false;
    const char * dash = std::strrchr(name, '-');
    if (!dash || !dash[1]) return false;
    char * end = nullptr;
    long value = std::strtol(dash + 1, &end, 10);
    if (!end || *end || value < 0 || value > 100000) return false;
    layer = static_cast<int>(value);
    return true;
}

static bool capture_eval(struct ggml_tensor * t, bool ask, void * user) {
    auto * c = static_cast<Capture *>(user);
    if (!c || !c->enabled || !t || !t->name) return false;
    int layer = -1;
    const bool isIds = parse_layer(t->name, "ffn_moe_topk-", layer);
    const bool isWeights = parse_layer(t->name, "ffn_moe_weights_norm-", layer);
    if (!isIds && !isWeights) return false;
    if (ask) return true;
    if (layer < 1 || layer > 46) {
        c->invalid = true; c->error = "routing layer outside GLM MoE range"; return false;
    }
    if (ask) return true;
    size_t elements = 1;
    const size_t typeBytes = t->type == GGML_TYPE_I32 || t->type == GGML_TYPE_F32 ? 4 : 0;
    const bool supportedType = typeBytes != 0;
    for (int d = 0; d < GGML_MAX_DIMS; ++d) {
        if (t->ne[d] <= 0 || static_cast<size_t>(t->ne[d]) > SIZE_MAX / elements) { c->invalid = true; c->error = "routing tensor dimensions overflow"; return false; }
        elements *= static_cast<size_t>(t->ne[d]);
    }
    if (!supportedType) {
        c->invalid = true; c->error = "routing tensor type is unsupported"; return false;
    }
    if (elements == 0 || elements % 4 != 0) {
        c->invalid = true; c->error = "routing tensor element count is not top-4 aligned"; return false;
    }
    if (isIds) {
        if (t->type != GGML_TYPE_I32) { c->invalid = true; c->error = "top-k tensor is not I32"; return false; }
        auto & dst = c->ids[layer];
        if (!dst.empty()) { c->invalid = true; c->error = "duplicate top-k capture"; return false; }
        dst.resize(elements);
        p_ggml_backend_tensor_get(t, dst.data(), 0, elements * sizeof(int32_t));
        for (int32_t id : dst) if (id < 0 || id >= 59) { c->invalid = true; c->error = "expert id out of range"; return false; }
    } else {
        if (t->type != GGML_TYPE_F32) { c->invalid = true; c->error = "routing weight tensor is not F32"; return false; }
        auto & dst = c->weights[layer];
        if (!dst.empty()) { c->invalid = true; c->error = "duplicate weight capture"; return false; }
        dst.resize(elements);
        p_ggml_backend_tensor_get(t, dst.data(), 0, elements * sizeof(float));
        for (float w : dst) if (!std::isfinite(w) || w < 0.0f) { c->invalid = true; c->error = "invalid routing weight"; return false; }
    }
    // Returning true tells the scheduler to continue evaluating subsequent
    // graph nodes; false is reserved for a validation/readback failure.
    return true;
}

static HMODULE lib;
static HMODULE ggml_lib;
#define FN(ret, name, args) using name##_fn = ret (*) args; static name##_fn p_##name
FN(void, llama_backend_init, (void)); FN(void, llama_backend_free, (void));
FN(llama_model_params, llama_model_default_params, (void));
FN(llama_context_params, llama_context_default_params, (void));
FN(llama_model *, llama_model_load_from_file, (const char *, llama_model_params));
FN(llama_context *, llama_init_from_model, (llama_model *, llama_context_params));
FN(llama_batch, llama_batch_init, (int, int, int)); FN(void, llama_batch_free, (llama_batch));
FN(int, llama_decode, (llama_context *, llama_batch));
FN(float *, llama_get_logits_ith, (llama_context *, int));
FN(const llama_vocab *, llama_model_get_vocab, (const llama_model *));
FN(int32_t, llama_vocab_n_tokens, (const llama_vocab *));
FN(void, llama_model_free, (llama_model *)); FN(void, llama_free, (llama_context *));
#undef FN

template <class T> static bool resolve(const char * n, T & out) {
    out = reinterpret_cast<T>(GetProcAddress(lib, n));
    if (!out) std::fprintf(stderr, "CALIBRATION_MISSING_EXPORT=%s\n", n);
    return out != nullptr;
}

static bool load_api() {
    lib = LoadLibraryExW(L"F:\\llama.cpp-ref\\build\\bin\\llama.dll", nullptr,
                         LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!lib) return false;
    ggml_lib = LoadLibraryExW(L"F:\\llama.cpp-ref\\build\\bin\\ggml.dll", nullptr,
                              LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!ggml_lib) return false;
#define R(n) if (!resolve(#n, p_##n)) return false
    R(llama_backend_init); R(llama_backend_free); R(llama_model_default_params);
    R(llama_context_default_params); R(llama_model_load_from_file); R(llama_init_from_model);
    R(llama_batch_init); R(llama_batch_free); R(llama_decode); R(llama_get_logits_ith);
    R(llama_model_get_vocab); R(llama_vocab_n_tokens); R(llama_model_free); R(llama_free);
#undef R
    // The reference build may place the public GGML backend entry point in a
    // split DLL. Resolve it from every compatible module loaded by this build;
    // do not fall back to t->data because evaluated tensors may be device-backed.
    const wchar_t * modules[] = { L"ggml.dll", L"ggml-base.dll", L"ggml-cpu.dll", L"llama.dll" };
    for (const wchar_t * module : modules) {
        HMODULE h = LoadLibraryExW(module, nullptr,
                                   LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!h) continue;
        p_ggml_backend_tensor_get = reinterpret_cast<ggml_backend_tensor_get_fn>(GetProcAddress(h, "ggml_backend_tensor_get"));
        if (!p_ggml_backend_tensor_get) p_ggml_backend_tensor_get = reinterpret_cast<ggml_backend_tensor_get_fn>(GetProcAddress(h, "_ggml_backend_tensor_get"));
        if (p_ggml_backend_tensor_get) {
            std::fprintf(stderr, "CALIBRATION_READBACK_MODULE=%ls\n", module);
            break;
        }
    }
    if (!p_ggml_backend_tensor_get) { std::fprintf(stderr, "CALIBRATION_MISSING_EXPORT=ggml_backend_tensor_get\n"); return false; }
    return true;
}

struct Run { std::vector<float> logits; Capture capture; int vocab = 0; };

static bool run_once(const std::string & modelPath, const std::vector<int32_t> & tokens,
                    bool telemetry, Run & out) {
    p_llama_backend_init();
    auto mp = p_llama_model_default_params(); mp.n_gpu_layers = 0;
    llama_model * model = p_llama_model_load_from_file(modelPath.c_str(), mp);
    if (!model) return false;
    const llama_vocab * vocab = p_llama_model_get_vocab(model);
    out.vocab = p_llama_vocab_n_tokens(vocab);
    auto cp = p_llama_context_default_params(); cp.n_ctx = 512; cp.n_batch = static_cast<uint32_t>(std::max<size_t>(8, tokens.size())); cp.n_threads = 8;
    out.capture.enabled = telemetry; cp.cb_eval = telemetry ? capture_eval : nullptr; cp.cb_eval_user_data = telemetry ? &out.capture : nullptr;
    llama_context * ctx = p_llama_init_from_model(model, cp);
    if (!ctx) { p_llama_model_free(model); return false; }
    llama_batch batch = p_llama_batch_init(static_cast<int>(tokens.size()), 0, 1);
    if (!batch.token) { p_llama_free(ctx); p_llama_model_free(model); return false; }
    for (size_t i = 0; i < tokens.size(); ++i) { batch.token[i] = tokens[i]; batch.pos[i] = static_cast<llama_pos>(i); batch.n_seq_id[i] = 1; batch.seq_id[i][0] = 0; batch.logits[i] = 1; }
    batch.n_tokens = static_cast<int32_t>(tokens.size());
    const bool decoded = p_llama_decode(ctx, batch) == 0;
    if (decoded) {
        out.logits.resize(static_cast<size_t>(tokens.size()) * static_cast<size_t>(out.vocab));
        for (size_t i = 0; i < tokens.size(); ++i) { const float * p = p_llama_get_logits_ith(ctx, static_cast<int>(i)); if (!p) { out.logits.clear(); break; } std::memcpy(out.logits.data() + i * out.vocab, p, static_cast<size_t>(out.vocab) * sizeof(float)); }
    }
    p_llama_batch_free(batch); p_llama_free(ctx); p_llama_model_free(model); p_llama_backend_free();
    return decoded && !out.logits.empty();
}

int main(int argc, char ** argv) {
    if (argc < 6) { std::fprintf(stderr, "usage: reap_reference_calibration <model> <out-dir> <model-sha256> <prompt-sha256> <reference-revision> <token>...\n"); return 2; }
    const std::string model = argv[1], outDir = argv[2], modelHash = argv[3], promptHash = argv[4], revision = argv[5];
    std::vector<int32_t> tokens; for (int i = 6; i < argc; ++i) tokens.push_back(std::atoi(argv[i]));
    if (tokens.empty() || !load_api()) { std::fprintf(stderr, "CALIBRATION_FAIL=API_OR_INPUT\n"); return 3; }
    fs::create_directories(outDir);
    Run plain, instrumented;
    if (!run_once(model, tokens, false, plain) || !run_once(model, tokens, true, instrumented)) { std::fprintf(stderr, "CALIBRATION_FAIL=REFERENCE_DECODE\n"); return 4; }
    if (plain.vocab != instrumented.vocab || plain.logits.size() != instrumented.logits.size()) { std::fprintf(stderr, "CALIBRATION_FAIL=LOGIT_SHAPE\n"); return 5; }
    float maxDiff = 0.0f; for (size_t i = 0; i < plain.logits.size(); ++i) maxDiff = std::max(maxDiff, std::fabs(plain.logits[i] - instrumented.logits[i]));
    std::array<std::array<uint64_t, 59>, 46> expertCounts{};
    std::array<std::array<double, 59>, 46> expertWeightSums{};
    bool coverageOk = instrumented.capture.ids.size() == 46 && instrumented.capture.weights.size() == 46;
    for (int layer = 1; layer <= 46 && coverageOk; ++layer) {
        const auto & ids = instrumented.capture.ids[layer];
        const auto & weights = instrumented.capture.weights[layer];
        coverageOk = ids.size() == weights.size() && ids.size() == tokens.size() * 4;
        if (!coverageOk) break;
        for (size_t i = 0; i < ids.size(); ++i) {
            ++expertCounts[layer - 1][static_cast<size_t>(ids[i])];
            expertWeightSums[layer - 1][static_cast<size_t>(ids[i])] += weights[i];
        }
    }
    if (maxDiff != 0.0f || instrumented.capture.invalid || !coverageOk) { std::fprintf(stderr, "CALIBRATION_FAIL=PARITY_OR_COVERAGE max_logit_diff=%g layers=%zu weights=%zu error=%s\n", maxDiff, instrumented.capture.ids.size(), instrumented.capture.weights.size(), instrumented.capture.error.c_str()); return 6; }
    std::ofstream receipt(fs::path(outDir) / "calibration_receipt.json", std::ios::binary | std::ios::trunc);
    if (!receipt) return 7;
    receipt << "{\"schema\":\"rawrxd.reap.reference_calibration.002\",\"model_sha256\":\"" << modelHash << "\",\"prompt_set_sha256\":\"" << promptHash << "\",\"reference_revision\":\"" << revision << "\",\"tokens\":" << tokens.size() << ",\"layers\":46,\"top_k\":4,\"instrumented_uninstrumented_max_logit_diff\":" << maxDiff << ",\"telemetry_validated\":true,\"per_layer\":[";
    for (int layer = 0; layer < 46; ++layer) {
        if (layer) receipt << ',';
        receipt << "{\"layer\":" << layer + 1 << ",\"tokens\":" << tokens.size() << ",\"expert_counts\":[";
        for (int expert = 0; expert < 59; ++expert) { if (expert) receipt << ','; receipt << expertCounts[layer][expert]; }
        receipt << "],\"expert_weight_sums\":[";
        for (int expert = 0; expert < 59; ++expert) { if (expert) receipt << ','; receipt << expertWeightSums[layer][expert]; }
        receipt << "]}";
    }
    receipt << "]}\n";
    std::printf("CALIBRATION_PASS layers=46 tokens=%zu max_logit_diff=%g receipt=%s\n", tokens.size(), maxDiff, (fs::path(outDir) / "calibration_receipt.json").string().c_str());
    return 0;
}
