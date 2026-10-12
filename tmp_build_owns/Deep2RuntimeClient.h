// Deep2RuntimeClient.h — the legacy Deep2_* C ABI, now a client of the
// certified ModelGenie runtime (DEEP2_RUNTIME_OWNERSHIP_001).
//
// Pinned copy of src/core/dll/Deep2InferenceAdapter.h: the DLL's CMake target
// deliberately does not compile that path, and the live source is under
// concurrent edit, so this is the certified copy. ABI-compatible with the
// original header so existing integrators keep compiling.

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Deep2Model Deep2Model;
typedef struct Deep2Context Deep2Context;

// Model lifecycle
extern "C" Deep2Model* Deep2_LoadModel(const char* gguf_path);
extern "C" void Deep2_FreeModel(Deep2Model* model);

// Context lifecycle
extern "C" Deep2Context* Deep2_CreateContext(Deep2Model* model, uint32_t context_length);
extern "C" void Deep2_FreeContext(Deep2Context* context);

typedef struct Deep2SamplerParams {
    float temperature;
    float top_p;
    int top_k;
    float repeat_penalty;
    int repeat_last_n;
    int seed;
} Deep2SamplerParams;

// Prefill the prompt; returns the number of tokens consumed. When out_logits is
// non-null it receives the authority's logits for the final prompt position
// (real values - the previous adapter zero-filled them).
extern "C" int Deep2_Prefill(
    Deep2Context* ctx,
    const uint32_t* tokens,
    size_t token_count,
    float* out_logits
);

// One autoregressive step: samples from the logits produced by the previous
// Prefill/Decode, advances the authority, and returns the sampled token id.
// out_logits receives the logits the returned token was drawn from.
extern "C" int Deep2_Decode(
    Deep2Context* ctx,
    float* out_logits,
    const float* sampler_params
);

// KV cache management
extern "C" void Deep2_ResetKVCache(Deep2Context* ctx);
extern "C" void Deep2_TrimKVCache(Deep2Context* ctx, size_t keep_tokens);

// Tokenizer (the authority's SentencePiece tokenizer from the GGUF).
// Deep2_Tokenize returns the total token count; when outTokens/maxTokens are
// provided it writes up to maxTokens ids (two-phase sizing supported).
extern "C" int Deep2_Tokenize(Deep2Model* model, const char* text,
                              int* outTokens, int maxTokens);

// Deep2_Detokenize writes the decoded text into outText (null-terminated) and
// returns its length; when outText is null it returns the required size.
extern "C" int Deep2_Detokenize(Deep2Model* model, const int* tokens,
                                int tokenCount, char* outText, int outSize);

extern "C" int Deep2_ConfigureSampler(Deep2Context* ctx,
                                      const Deep2SamplerParams* params);

extern "C" int Deep2_GetVocabSize(Deep2Model* model);

extern "C" void Deep2_GetMemoryInfo(
    Deep2Context* ctx,
    size_t* kv_cache_bytes,
    size_t* model_bytes,
    size_t* peak_bytes
);

extern "C" const char* Deep2_GetVersion();

// DEEP2_RUNTIME_OWNERSHIP_001: the authority this shim delegates to. Exposed so
// a client can verify (rather than assume) that both entry points share one
// runtime: the same mg_model_t* / mg_context_t* back both APIs.
typedef struct mg_model_t mg_model_t;
typedef struct mg_context_t mg_context_t;
extern "C" mg_model_t* Deep2_AuthorityModel(const Deep2Model* model);
extern "C" mg_context_t* Deep2_AuthorityContext(const Deep2Context* ctx);

#ifdef __cplusplus
}
#endif
