// Deep2RuntimeClient.cpp — the legacy Deep2_* C ABI as a client of the
// certified ModelGenie runtime (DEEP2_RUNTIME_OWNERSHIP_001).
//
// This file used to own a *second* inference engine (RawrXD::CPUInferenceEngine)
// with its own GGUF loading, KV cache, sampler and tokenizer. That duplicated
// the certified authority (ModelGenieRuntime / IRExecutor, see
// include/ModelGenieRuntime.h) and produced uncertifiable numbers — it
// zero-filled logits and re-ran the whole prompt on every decode step.
//
// The ABI is unchanged for existing integrators, but the implementation is now
// a thin forwarding client of the authority:
//   Deep2_LoadModel      -> mg_model_load
//   Deep2_CreateContext  -> mg_context_create
//   Deep2_Prefill        -> mg_context_eval_buffer   (real logits)
//   Deep2_Decode         -> sample + mg_context_eval (real logits)
//   Deep2_Tokenize       -> mg_model_tokenize
//   Deep2_Detokenize     -> mg_model_detokenize
//   Deep2_ResetKVCache   -> mg_context_reset
//   Deep2_GetMemoryInfo  -> authority-reported figures
//
// One session lifecycle, one cache, one tokenizer: the engine copy is gone.
//
// Pinned here (rather than at src/core/dll/Deep2InferenceAdapter.cpp) because
// the DLL's CMake target deliberately does not compile that path, and the live
// source is under concurrent edit; this copy is the certified one.

#include <filesystem>

#include "Deep2RuntimeClient.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

#include "ModelGenieRuntime.h"

namespace {

constexpr uint32_t kMagicModel = 0x44324D31u;  // "D2M1"
constexpr uint32_t kMagicCtx = 0x44324331u;   // "D2C1"

// Deterministic LCG for temperature sampling (no stdlib rand dependency).
inline float LcgNext(uint64_t& state)
{
    state = state * 6364136223846793005ull + 1442695040888963407ull;
    return static_cast<float>((state >> 33) & 0x7FFFFFu) / float(0x7FFFFF);
}

}  // namespace

struct Deep2Model {
    uint32_t magic = kMagicModel;
    mg_model_t* mg = nullptr;
    std::string path;
};

struct Deep2Context {
    uint32_t magic = kMagicCtx;
    Deep2Model* model = nullptr;
    mg_context_t* mg = nullptr;
    std::vector<uint32_t> tokens;
    std::vector<float> logits;
    size_t vocab = 0;
    // sampler
    float temperature = 0.0f;
    float top_p = 1.0f;
    int top_k = 0;
    float repeat_penalty = 1.0f;
    int repeat_last_n = 64;
    uint64_t seed = 0;
};

static bool ValidModel(const Deep2Model* m)
{
    return m && m->magic == kMagicModel && m->mg != nullptr;
}

static bool ValidCtx(const Deep2Context* c)
{
    return c && c->magic == kMagicCtx && c->mg != nullptr;
}

extern "C" Deep2Model* Deep2_LoadModel(const char* gguf_path)
{
    if (!gguf_path || !gguf_path[0]) return nullptr;

    // The adapter is a client of the authority: exactly one mg_model_load per
    // handle, and the runtime is the only component that maps the GGUF.
    mg_model_config_t cfg{};
    cfg.max_seq_len = 2048;
    cfg.use_kv_cache = true;
    cfg.num_threads = 0;  // authority default
    mg_model_t* mg = nullptr;
    if (mg_model_load(gguf_path, &cfg, &mg) != MG_SUCCESS || !mg) {
        std::fprintf(stderr, "[Deep2Adapter] authority rejected model: %s\n", gguf_path);
        return nullptr;
    }

    auto* model = new Deep2Model();
    model->mg = mg;
    model->path = gguf_path;
    std::fprintf(stderr, "[Deep2Adapter] model loaded through the authority: %s\n",
                 gguf_path);
    return model;
}

extern "C" void Deep2_FreeModel(Deep2Model* model)
{
    if (!model) return;
    if (model->magic == kMagicModel && model->mg) mg_model_free(model->mg);
    model->magic = 0;
    delete model;
}

extern "C" Deep2Context* Deep2_CreateContext(Deep2Model* model, uint32_t context_length)
{
    if (!ValidModel(model)) return nullptr;
    (void) context_length;  // the authority sizes its own KV cache

    mg_context_t* mg = nullptr;
    if (mg_context_create(model->mg, &mg) != MG_SUCCESS || !mg) return nullptr;

    auto* ctx = new Deep2Context();
    ctx->model = model;
    ctx->mg = mg;
    ctx->vocab = mg_model_vocab_size(model->mg);
    return ctx;
}

extern "C" void Deep2_FreeContext(Deep2Context* context)
{
    if (!context) return;
    if (context->magic == kMagicCtx && context->mg) mg_context_free(context->mg);
    context->magic = 0;
    delete context;
}

extern "C" int Deep2_Tokenize(Deep2Model* model, const char* text,
                              int* outTokens, int maxTokens)
{
    if (!ValidModel(model) || !text) return -1;

    // query phase: the authority reports the required capacity through
    // in_out_count and returns MG_ERROR_INVALID_ARGUMENT when the buffer is
    // too small (that is a sizing answer, not a tokenizer failure)
    size_t cap = 0;
    const mg_error_t qrc = mg_model_tokenize(model->mg, text, nullptr, &cap);
    if (qrc != MG_SUCCESS && qrc != MG_ERROR_INVALID_ARGUMENT) return -1;
    if (!outTokens || maxTokens <= 0) return static_cast<int>(cap);
    if (cap == 0) return 0;

    std::vector<uint32_t> tmp(cap);
    size_t n = cap;
    if (mg_model_tokenize(model->mg, text, tmp.data(), &n) != MG_SUCCESS) return -1;
    const int count = static_cast<int>(std::min(n, static_cast<size_t>(maxTokens)));
    if (count > 0) std::memcpy(outTokens, tmp.data(), count * sizeof(int));
    return count;
}

extern "C" int Deep2_Detokenize(Deep2Model* model, const int* tokens,
                                int tokenCount, char* outText, int outSize)
{
    if (!ValidModel(model) || !tokens || tokenCount <= 0) return -1;

    std::vector<uint32_t> ids(tokens, tokens + tokenCount);
    // query phase: the authority reports the required size (including the null
    // terminator) and returns 0 when the buffer is too small
    size_t needed = 0;
    mg_model_detokenize(model->mg, ids.data(), ids.size(), nullptr, &needed);
    if (!outText || outSize <= 0) return static_cast<int>(needed);
    if (needed == 0) return 0;

    std::vector<char> buf(needed);
    size_t size = needed;
    const size_t written =
        mg_model_detokenize(model->mg, ids.data(), ids.size(), buf.data(), &size);
    if (written == 0) return -1;
    const int count = static_cast<int>(std::min(written, static_cast<size_t>(outSize - 1)));
    if (count > 0) std::memcpy(outText, buf.data(), count);
    outText[count] = '\0';
    return count;
}

extern "C" int Deep2_ConfigureSampler(Deep2Context* ctx,
                                      const Deep2SamplerParams* params)
{
    if (!ValidCtx(ctx) || !params) return -1;
    ctx->temperature = params->temperature;
    ctx->top_p = params->top_p;
    ctx->top_k = params->top_k;
    ctx->repeat_penalty = params->repeat_penalty;
    ctx->repeat_last_n = params->repeat_last_n;
    ctx->seed = static_cast<uint64_t>(params->seed);
    return 0;
}

extern "C" int Deep2_GetVocabSize(Deep2Model* model)
{
    if (!ValidModel(model)) return -1;
    return static_cast<int>(mg_model_vocab_size(model->mg));
}

extern "C" int Deep2_Prefill(Deep2Context* ctx, const uint32_t* tokens,
                             size_t token_count, float* out_logits)
{
    if (!ValidCtx(ctx) || !tokens || token_count == 0) return -1;

    ctx->logits.assign(ctx->vocab, 0.0f);
    size_t n = ctx->vocab;
    if (mg_context_eval_buffer(ctx->mg, tokens, token_count, ctx->logits.data(), &n) !=
        MG_SUCCESS) {
        return -1;
    }
    ctx->tokens.assign(tokens, tokens + token_count);
    ctx->logits.resize(n);
    if (out_logits) std::memcpy(out_logits, ctx->logits.data(), n * sizeof(float));
    return static_cast<int>(token_count);
}

// Sample the next token from ctx->logits, honouring the configured sampler.
static uint32_t SampleFromLogits(Deep2Context* ctx)
{
    const size_t vocab = ctx->logits.size();
    if (vocab == 0) return 0;

    std::vector<float> logits(ctx->logits);  // working copy (repeat penalty)

    if (ctx->repeat_penalty != 1.0f && ctx->repeat_last_n > 0 && !ctx->tokens.empty()) {
        const size_t start = ctx->tokens.size() > static_cast<size_t>(ctx->repeat_last_n)
                                 ? ctx->tokens.size() - ctx->repeat_last_n
                                 : 0;
        for (size_t i = start; i < ctx->tokens.size(); ++i) {
            float& l = logits[ctx->tokens[i]];
            l = l < 0.0f ? l * ctx->repeat_penalty : l / ctx->repeat_penalty;
        }
    }

    if (ctx->temperature <= 0.0f) {
        size_t best = 0;
        for (size_t i = 1; i < vocab; ++i) {
            if (logits[i] > logits[best]) best = i;
        }
        return static_cast<uint32_t>(best);
    }

    const float t = ctx->temperature > 1e-6f ? ctx->temperature : 1e-6f;
    std::vector<float> probs(vocab);
    float mx = logits[0];
    for (size_t i = 1; i < vocab; ++i) mx = std::max(mx, logits[i]);
    float sum = 0.0f;
    for (size_t i = 0; i < vocab; ++i) {
        probs[i] = std::exp((logits[i] - mx) / t);
        sum += probs[i];
    }
    // top-k filter
    if (ctx->top_k > 0 && static_cast<size_t>(ctx->top_k) < vocab) {
        std::vector<size_t> idx(vocab);
        for (size_t i = 0; i < vocab; ++i) idx[i] = i;
        std::partial_sort(idx.begin(), idx.begin() + ctx->top_k, idx.end(),
                          [&](size_t a, size_t b) { return probs[a] > probs[b]; });
        std::vector<char> keep(vocab, 0);
        for (int i = 0; i < ctx->top_k; ++i) keep[idx[i]] = 1;
        for (size_t i = 0; i < vocab; ++i) {
            if (!keep[i]) probs[i] = 0.0f;
        }
        sum = 0.0f;
        for (float p : probs) sum += p;
    }
    // top-p filter
    if (ctx->top_p > 0.0f && ctx->top_p < 1.0f) {
        std::vector<size_t> idx(vocab);
        for (size_t i = 0; i < vocab; ++i) idx[i] = i;
        std::sort(idx.begin(), idx.end(),
                  [&](size_t a, size_t b) { return probs[a] > probs[b]; });
        float acc = 0.0f;
        std::vector<char> keep(vocab, 0);
        for (size_t i = 0; i < vocab; ++i) {
            keep[idx[i]] = 1;
            acc += probs[idx[i]];
            if (acc >= ctx->top_p * sum) break;
        }
        for (size_t i = 0; i < vocab; ++i) {
            if (!keep[i]) probs[i] = 0.0f;
        }
        sum = 0.0f;
        for (float p : probs) sum += p;
    }
    const float r = LcgNext(ctx->seed) * sum;
    float acc = 0.0f;
    for (size_t i = 0; i < vocab; ++i) {
        acc += probs[i];
        if (r <= acc) return static_cast<uint32_t>(i);
    }
    return static_cast<uint32_t>(vocab - 1);
}

extern "C" int Deep2_Decode(Deep2Context* ctx, float* out_logits,
                            const float* sampler_params)
{
    if (!ValidCtx(ctx)) return -1;
    if (ctx->logits.empty()) return -1;  // Prefill first

    if (sampler_params) {
        Deep2SamplerParams p;
        p.temperature = sampler_params[0];
        p.top_p = sampler_params[1];
        p.top_k = static_cast<int>(sampler_params[2]);
        p.repeat_penalty = sampler_params[3];
        p.repeat_last_n = static_cast<int>(sampler_params[4]);
        p.seed = static_cast<int>(sampler_params[5]);
        Deep2_ConfigureSampler(ctx, &p);
    }

    // out_logits receives the logits the returned token was drawn from, so
    // argmax(out_logits) == returned token for greedy sampling.
    if (out_logits) {
        std::memcpy(out_logits, ctx->logits.data(), ctx->logits.size() * sizeof(float));
    }
    const uint32_t sampled = SampleFromLogits(ctx);

    // Advance the authority one step so the next Decode sees fresh logits.
    std::vector<float> fresh(ctx->vocab);
    size_t n = ctx->vocab;
    if (mg_context_eval(ctx->mg, sampled, fresh.data(), &n) != MG_SUCCESS) return -2;
    ctx->tokens.push_back(sampled);
    ctx->logits.assign(fresh.begin(), fresh.begin() + n);
    return static_cast<int>(sampled);
}

extern "C" void Deep2_ResetKVCache(Deep2Context* ctx)
{
    if (!ValidCtx(ctx)) return;
    mg_context_reset(ctx->mg);
    ctx->tokens.clear();
    ctx->logits.clear();
}

extern "C" void Deep2_TrimKVCache(Deep2Context* ctx, size_t keep_tokens)
{
    if (!ValidCtx(ctx)) return;
    // The authority owns the cache; trimming the tracked prompt is the only
    // operation this shim can perform without reaching into it.
    if (ctx->tokens.size() > keep_tokens) ctx->tokens.resize(keep_tokens);
}

extern "C" void Deep2_GetMemoryInfo(Deep2Context* ctx, size_t* kv_cache_bytes,
                                    size_t* model_bytes, size_t* peak_bytes)
{
    if (kv_cache_bytes) *kv_cache_bytes = 0;
    if (model_bytes) *model_bytes = 0;
    if (peak_bytes) *peak_bytes = 0;
    if (!ValidCtx(ctx)) return;
    // Every figure comes from the authority; the shim hardcodes nothing.
    const size_t per_pos =
        mg_context_kv_floats_per_position(ctx->mg) * sizeof(float);
    const size_t kv = mg_context_position(ctx->mg) * per_pos;
    if (kv_cache_bytes) *kv_cache_bytes = kv;
    if (model_bytes) {
        *model_bytes = static_cast<size_t>(mg_model_file_bytes(ctx->model->mg));
    }
    if (peak_bytes) {
        *peak_bytes = kv + static_cast<size_t>(mg_model_file_bytes(ctx->model->mg));
    }
}

extern "C" const char* Deep2_GetVersion()
{
    return "Deep2InferenceAdapter/2.0 (certified ModelGenie runtime client)";
}

extern "C" mg_model_t* Deep2_AuthorityModel(const Deep2Model* model)
{
    return ValidModel(model) ? model->mg : nullptr;
}

extern "C" mg_context_t* Deep2_AuthorityContext(const Deep2Context* ctx)
{
    return ValidCtx(ctx) ? ctx->mg : nullptr;
}
