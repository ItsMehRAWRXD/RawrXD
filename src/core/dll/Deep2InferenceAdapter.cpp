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

    // Convert tokens to int32_t vector
    ctx->prompt_tokens.assign(tokens, tokens + token_count);

    // Use the engine's GenerateStreaming with a callback that captures logits
    // For prefill, we need to process the prompt and build KV cache
    // The CPUInferenceEngine handles KV cache internally during generation

    // We'll use a workaround: call GenerateStreaming with max_tokens=0 to just do prefill
    // But the engine doesn't expose a direct prefill function, so we use a trick:
    // Run generation for 0 tokens to build the KV cache from the prompt

    bool prefill_done = false;
    int prefill_result = -1;

    // Convert tokens to the format expected by GenerateStreaming
    std::vector<int32_t> input_tokens(ctx->prompt_tokens.begin(), ctx->prompt_tokens.end());

    // Use a custom streaming callback that just completes immediately
    // This forces the engine to process the prompt through all layers (prefill)
    ctx->model->engine->GenerateStreaming(
        input_tokens,
        0,  // max_tokens = 0 means just prefill
        [&](const std::string& /*token*/) {
            // No tokens generated during prefill
        },
        [&]() {
            prefill_done = true;
            prefill_result = static_cast<int>(token_count);
        },
        nullptr
    );

    if (!prefill_done || prefill_result < 0) {
        return -2;
    }

    // If logits requested, get them from the last forward pass
    // The engine's Eval returns logits for the last token
    if (out_logits) {
        std::vector<float> logits = ctx->model->engine->Eval(input_tokens);
        if (logits.size() >= ctx->model->vocab_size) {
            std::memcpy(out_logits, logits.data(), ctx->model->vocab_size * sizeof(float));
        }
    }

    ctx->current_pos = token_count;
    return prefill_result;
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
        ctx->sampler_params[0] = sampler_params[0];  // temperature
        ctx->sampler_params[1] = sampler_params[1];  // top_p
        ctx->sampler_params[2] = sampler_params[2];  // top_k
        ctx->sampler_params[3] = sampler_params[3];  // repeat_penalty
        ctx->sampler_params[4] = sampler_params[4];  // repeat_last_n
        ctx->sampler_params[5] = sampler_params[5];  // seed
    }

    // Apply sampler parameters to engine
    ctx->model->engine->SetThreadCount(1); // Ensure deterministic for now

    // For decoding, we need to generate one token
    // The engine's GenerateStreaming with max_tokens=1 will do one decode step
    // But we need access to the logits

    // Use Eval to get logits for the next position
    std::vector<int32_t> current_context = ctx->prompt_tokens;
    // Note: In a real implementation, we'd only pass the new token
    // For now, we re-evaluate the full context (inefficient but correct)

    std::vector<float> logits = ctx->model->engine->Eval(current_context);
    
    if (logits.empty() || logits.size() < ctx->model->vocab_size) {
        return -2;
    }

    // Apply sampling (greedy for now, could add temperature/top_p/top_k)
    float temperature = ctx->sampler_params[0];
    float top_p = ctx->sampler_params[1];
    int top_k = static_cast<int>(ctx->sampler_params[2]);
    
    int sampled_token = 0;
    float max_logit = -1e30f;
    
    // Simple greedy sampling (temperature=0) or with temperature
    if (temperature <= 0.0f) {
        // Greedy: argmax
        for (size_t i = 0; i < ctx->model->vocab_size; ++i) {
            if (logits[i] > max_logit) {
                max_logit = logits[i];
                sampled_token = static_cast<int>(i);
            }
        }
    } else {
        // Temperature sampling with top-k
        // Create vector of (logit, token) pairs
        std::vector<std::pair<float, int>> candidates;
        candidates.reserve(ctx->model->vocab_size);
        for (size_t i = 0; i < ctx->model->vocab_size; ++i) {
            candidates.emplace_back(logits[i] / temperature, static_cast<int>(i));
        }
        
        // Sort by logit descending
        std::sort(candidates.begin(), candidates.end(), 
                  [](const auto& a, const auto& b) { return a.first > b.first; });
        
        // Apply top-k
        if (top_k > 0 && top_k < static_cast<int>(candidates.size())) {
            candidates.resize(top_k);
        }
        
        // Apply top-p (nucleus sampling) - simplified
        // For now, just pick from top-k with temperature
        float sum_exp = 0.0f;
        for (auto& c : candidates) {
            c.first = std::exp(c.first);
            sum_exp += c.first;
        }
        
        // Normalize
        for (auto& c : candidates) {
            c.first /= sum_exp;
        }
        
        // Sample (simplified: pick max for now)
        // TODO: Add proper random sampling with seed
        max_logit = -1e30f;
        for (const auto& c : candidates) {
            if (c.first > max_logit) {
                max_logit = c.first;
                sampled_token = c.second;
            }
        }
    }

    // Add sampled token to context for next iteration
    ctx->prompt_tokens.push_back(sampled_token);
    ctx->current_pos++;

    // Return logits if requested
    if (out_logits) {
        std::memcpy(out_logits, logits.data(), ctx->model->vocab_size * sizeof(float));
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