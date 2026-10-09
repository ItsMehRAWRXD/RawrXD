// Deep2InferenceAdapter.cpp — C API implementation bridging RawrXDCore to Deep2 CPUInferenceEngine
// Implements the Deep2InferenceAdapter.h C API using RawrXD::CPUInferenceEngine

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <cstdint>
#include <algorithm>

#include "Deep2InferenceAdapter.h"
#include "cpu_inference_engine.h"

// ============================================================================
// Opaque handle structures
// ============================================================================

struct Deep2Model {
    RawrXD::CPUInferenceEngine* engine = nullptr;
    std::string model_path;
    size_t vocab_size = 32000;
    bool loaded = false;
};

struct Deep2Context {
    Deep2Model* model = nullptr;
    uint32_t context_length = 4096;
    std::vector<int32_t> prompt_tokens;
    size_t current_pos = 0;
    std::vector<float> logits_buffer;
    float sampler_params[6] = {0.7f, 0.9f, 40.0f, 1.1f, 64.0f, 0.0f};
};

// Global engine instance (singleton)
static RawrXD::CPUInferenceEngine* g_global_engine = nullptr;
static std::mutex g_engine_mutex;

// ============================================================================
// Helper: Get or create the global CPUInferenceEngine
// ============================================================================
static RawrXD::CPUInferenceEngine* get_global_engine() {
    std::lock_guard<std::mutex> lock(g_engine_mutex);
    if (!g_global_engine) {
        g_global_engine = RawrXD::CPUInferenceEngine::getInstance();
    }
    return g_global_engine;
}

// ============================================================================
// Model loading
// ============================================================================

extern "C" Deep2Model* Deep2_LoadModel(const char* gguf_path) {
    if (!gguf_path || !gguf_path[0]) {
        return nullptr;
    }

    RawrXD::CPUInferenceEngine* engine = get_global_engine();
    if (!engine) {
        return nullptr;
    }

    // Load the model
    if (!engine->LoadModel(std::string(gguf_path))) {
        fprintf(stderr, "[Deep2Adapter] LoadModel failed for: %s\n", gguf_path);
        return nullptr;
    }

    // Create model handle
    Deep2Model* model = new Deep2Model();
    model->engine = engine;
    model->model_path = gguf_path;
    model->vocab_size = static_cast<size_t>(engine->GetVocabSize());
    model->loaded = true;

    fprintf(stderr, "[Deep2Adapter] Model loaded: %s (vocab=%zu)\n", gguf_path, model->vocab_size);
    return model;
}

extern "C" void Deep2_FreeModel(Deep2Model* model) {
    if (model) {
        // Engine is singleton, don't destroy it
        delete model;
    }
}

// ============================================================================
// Context creation
// ============================================================================

extern "C" Deep2Context* Deep2_CreateContext(Deep2Model* model, uint32_t context_length) {
    if (!model || !model->loaded || !model->engine) {
        return nullptr;
    }

    Deep2Context* ctx = new Deep2Context();
    ctx->model = model;
    ctx->context_length = context_length ? context_length : 4096;
    ctx->logits_buffer.resize(model->vocab_size);
    return ctx;
}

extern "C" void Deep2_FreeContext(Deep2Context* context) {
    if (context) {
        delete context;
    }
}

// ============================================================================
// Tokenization (engine's real BPE tokenizer from the GGUF metadata)
// ============================================================================

extern "C" int Deep2_Tokenize(Deep2Model* model, const char* text,
                                  int* outTokens, int maxTokens) {
    if (!model || !model->loaded || !model->engine || !text) {
        return -1;
    }

    std::vector<int> tokens = model->engine->Tokenize(text);
    if (!outTokens || maxTokens <= 0) {
        // Query mode: return the total token count
        return static_cast<int>(tokens.size());
    }

    int count = static_cast<int>(std::min(tokens.size(),
                                          static_cast<size_t>(maxTokens)));
    if (count > 0) {
        std::memcpy(outTokens, tokens.data(), count * sizeof(int));
    }
    return count;
}

extern "C" int Deep2_Detokenize(Deep2Model* model, const int* tokens,
                                    int tokenCount, char* outText, int outSize) {
    if (!model || !model->loaded || !model->engine || !tokens || tokenCount <= 0) {
        return -1;
    }

    std::vector<int> tokenVec(tokens, tokens + tokenCount);
    std::string text = model->engine->Detokenize(tokenVec);

    if (!outText || outSize <= 0) {
        // Query mode: return the required size (excluding null terminator)
        return static_cast<int>(text.size());
    }

    int count = static_cast<int>(std::min(text.size(),
                                          static_cast<size_t>(outSize - 1)));
    if (count > 0) {
        std::memcpy(outText, text.data(), count);
    }
    outText[count] = '\0';
    return count;
}

// ============================================================================
// Sampler configuration
// ============================================================================

extern "C" int Deep2_ConfigureSampler(Deep2Context* ctx,
                                          const Deep2SamplerParams* params) {
    if (!ctx || !ctx->model || !ctx->model->loaded || !ctx->model->engine || !params) {
        return -1;
    }

    ctx->sampler_params[0] = params->temperature;
    ctx->sampler_params[1] = params->top_p;
    ctx->sampler_params[2] = static_cast<float>(params->top_k);
    ctx->sampler_params[3] = params->repeat_penalty;
    ctx->sampler_params[4] = static_cast<float>(params->repeat_last_n);
    ctx->sampler_params[5] = static_cast<float>(params->seed);

    ctx->model->engine->ConfigureGeneration(
        params->temperature,
        params->top_p,
        static_cast<uint32_t>(params->top_k),
        params->repeat_penalty,
        static_cast<uint64_t>(params->seed));

    return 0;
}

// ============================================================================
// Vocabulary size
// ============================================================================

extern "C" int Deep2_GetVocabSize(Deep2Model* model) {
    if (!model || !model->loaded) {
        return -1;
    }
    return static_cast<int>(model->vocab_size);
}

// ============================================================================
// Prefill - process prompt tokens and compute KV cache
// ============================================================================

extern "C" int Deep2_Prefill(
    Deep2Context* ctx,
    const uint32_t* tokens,
    size_t token_count,
    float* out_logits  // optional, size = vocab_size
) {
    if (!ctx || !ctx->model || !ctx->model->loaded || !ctx->model->engine || !tokens || token_count == 0) {
        return -1;
    }

    // Store the prompt tokens in the context. The underlying Deep2Engine
    // rebuilds its KV cache on every generate() call, so each decode step
    // re-runs the full (prompt + generated) context. This is correct but
    // O(n^2) in context length — acceptable for the minimal integration.
    ctx->prompt_tokens.assign(tokens, tokens + token_count);
    ctx->current_pos = token_count;

    // The streaming generation path does not expose per-token logits.
    if (out_logits) {
        std::fill(out_logits, out_logits + ctx->model->vocab_size, 0.0f);
    }

    return static_cast<int>(token_count);
}

// ============================================================================
// Decode single token - autoregressive step
// ============================================================================

extern "C" int Deep2_Decode(
    Deep2Context* ctx,
    float* out_logits,  // optional, size = vocab_size
    const float* sampler_params  // temperature, top_p, top_k, repeat_penalty
) {
    if (!ctx || !ctx->model || !ctx->model->loaded || !ctx->model->engine) {
        return -1;
    }

    // Update sampler parameters if provided
    if (sampler_params) {
        Deep2SamplerParams params;
        params.temperature = sampler_params[0];
        params.top_p = sampler_params[1];
        params.top_k = static_cast<int>(sampler_params[2]);
        params.repeat_penalty = sampler_params[3];
        params.repeat_last_n = static_cast<int>(sampler_params[4]);
        params.seed = static_cast<int>(sampler_params[5]);
        Deep2_ConfigureSampler(ctx, &params);
    }

    // Generate exactly one token from the full context via the engine's
    // real generation path (prefill + sampled decode). The token id is
    // captured through the per-token callback.
    int sampled_token = -1;
    ctx->model->engine->GenerateStreaming(
        ctx->prompt_tokens,
        1,  // max_tokens = 1: single autoregressive step
        [](const std::string& /*tokenText*/) {},
        nullptr,
        [&](int32_t tokenId) {
            sampled_token = tokenId;
        }
    );

    if (sampled_token < 0) {
        return -2;  // generation failed (context full, engine error, ...)
    }

    // Extend the context so the next decode step conditions on this token
    ctx->prompt_tokens.push_back(sampled_token);
    ctx->current_pos++;

    // The streaming path does not expose logits; zero-fill when requested.
    if (out_logits) {
        std::fill(out_logits, out_logits + ctx->model->vocab_size, 0.0f);
    }

    return sampled_token;
}

// ============================================================================
// KV Cache management
// ============================================================================

extern "C" void Deep2_ResetKVCache(Deep2Context* ctx) {
    if (ctx && ctx->model && ctx->model->engine) {
        ctx->model->engine->ClearCache();
        ctx->prompt_tokens.clear();
        ctx->current_pos = 0;
    }
}

extern "C" void Deep2_TrimKVCache(Deep2Context* ctx, size_t keep_tokens) {
    if (ctx && ctx->model && ctx->model->engine) {
        if (ctx->prompt_tokens.size() > keep_tokens) {
            ctx->prompt_tokens.resize(keep_tokens);
            ctx->current_pos = keep_tokens;
        }
        // Note: Full KV cache trim would require engine support
    }
}

// ============================================================================
// Memory info
// ============================================================================

extern "C" void Deep2_GetMemoryInfo(
    Deep2Context* ctx,
    size_t* kv_cache_bytes,
    size_t* model_bytes,
    size_t* peak_bytes
) {
    if (ctx && ctx->model && ctx->model->engine) {
        if (kv_cache_bytes) *kv_cache_bytes = 0; // TODO: track actual KV cache size
        if (model_bytes) *model_bytes = 0;       // TODO: track model size
        if (peak_bytes) *peak_bytes = ctx->model->engine->GetMemoryUsage();
    } else {
        if (kv_cache_bytes) *kv_cache_bytes = 0;
        if (model_bytes) *model_bytes = 0;
        if (peak_bytes) *peak_bytes = 0;
    }
}

// ============================================================================
// Engine version
// ============================================================================

extern "C" const char* Deep2_GetVersion() {
    return "Deep2InferenceAdapter/1.0 (CPUInferenceEngine wrapper)";
}