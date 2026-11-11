// Deep2InferenceAdapter.h — Bridge between RawrXDCore and Deep2 inference engine

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

#ifdef __cplusplus
extern "C" {
#endif

// Deep2 engine opaque handle
typedef struct Deep2Engine Deep2Engine;
typedef struct Deep2Context Deep2Context;
typedef struct Deep2Model Deep2Model;

// Model loading
extern "C" Deep2Model* Deep2_LoadModel(const char* gguf_path);
extern "C" void Deep2_FreeModel(Deep2Model* model);

// Context creation
extern "C" Deep2Context* Deep2_CreateContext(Deep2Model* model, uint32_t context_length);
extern "C" void Deep2_FreeContext(Deep2Context* context);

// Prefill - process prompt tokens and compute KV cache
// Returns: number of tokens processed, or negative error code
extern "C" int Deep2_Prefill(
    Deep2Context* ctx,
    const uint32_t* tokens,
    size_t token_count,
    float* out_logits  // optional, size = vocab_size
);

// Decode single token - autoregressive step
// Returns: sampled token ID, or negative error code
extern "C" int Deep2_Decode(
    Deep2Context* ctx,
    float* out_logits,  // optional, size = vocab_size
    const float* sampler_params  // temperature, top_p, top_k, repeat_penalty
);

// Sampler parameters structure
typedef struct Deep2SamplerParams {
    float temperature;
    float top_p;
    int top_k;
    float repeat_penalty;
    int repeat_last_n;
    int seed;
} Deep2SamplerParams;

// KV cache management
extern "C" void Deep2_ResetKVCache(Deep2Context* ctx);
extern "C" void Deep2_TrimKVCache(Deep2Context* ctx, size_t keep_tokens);

// Tokenization (uses the engine's real BPE tokenizer loaded from the GGUF)
// Deep2_Tokenize returns the total token count; when outTokens/maxTokens are
// provided it writes up to maxTokens ids (two-phase sizing supported).
extern "C" int Deep2_Tokenize(Deep2Model* model, const char* text,
                              int* outTokens, int maxTokens);

// Deep2_Detokenize writes the decoded text into outText (null-terminated) and
// returns its length; when outText is null it returns the required size.
extern "C" int Deep2_Detokenize(Deep2Model* model, const int* tokens,
                                int tokenCount, char* outText, int outSize);

// Apply sampler parameters to the engine (temperature, top_p, top_k, ...)
extern "C" int Deep2_ConfigureSampler(Deep2Context* ctx,
                                      const Deep2SamplerParams* params);

// Vocabulary size of the loaded model
extern "C" int Deep2_GetVocabSize(Deep2Model* model);

// Memory info
extern "C" void Deep2_GetMemoryInfo(
    Deep2Context* ctx,
    size_t* kv_cache_bytes,
    size_t* model_bytes,
    size_t* peak_bytes
);

// Engine version
extern "C" const char* Deep2_GetVersion();

#ifdef __cplusplus
}
#endif

// C++ wrapper
#ifdef __cplusplus

namespace Deep2 {

class Model {
public:
    Model() : handle_(nullptr) {}
    explicit Model(const char* path) { load(path); }
    ~Model() { if (handle_) Deep2_FreeModel(handle_); }
    
    Model(Model&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    Model& operator=(Model&& other) noexcept {
        if (handle_) Deep2_FreeModel(handle_);
        handle_ = other.handle_;
        other.handle_ = nullptr;
        return *this;
    }
    
    Model(const Model&) = delete;
    Model& operator=(const Model&) = delete;
    
    bool load(const char* path) {
        if (handle_) Deep2_FreeModel(handle_);
        handle_ = Deep2_LoadModel(path);
        return handle_ != nullptr;
    }
    
    operator bool() const { return handle_ != nullptr; }
    Deep2Model* get() const { return handle_; }
    
private:
    Deep2Model* handle_;
};

class Context {
public:
    Context() : handle_(nullptr) {}
    explicit Context(Model& model, uint32_t context_len = 4096) { create(model, context_len); }
    ~Context() { if (handle_) Deep2_FreeContext(handle_); }
    
    Context(Context&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    Context& operator=(Context&& other) noexcept {
        if (handle_) Deep2_FreeContext(handle_);
        handle_ = other.handle_;
        other.handle_ = nullptr;
        return *this;
    }
    
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    
    bool create(Model& model, uint32_t context_len = 4096) {
        if (handle_) Deep2_FreeContext(handle_);
        handle_ = Deep2_CreateContext(model.get(), context_len);
        return handle_ != nullptr;
    }
    
    int prefill(const std::vector<uint32_t>& tokens, std::vector<float>* out_logits = nullptr) {
        if (!handle_) return -1;
        if (out_logits) out_logits->resize(vocab_size_); // vocab_size should be known
        return Deep2_Prefill(handle_, tokens.data(), tokens.size(), out_logits ? out_logits->data() : nullptr);
    }
    
    int decode(float* out_logits, const float* sampler_params = nullptr) {
        if (!handle_) return -1;
        return Deep2_Decode(handle_, out_logits, sampler_params);
    }
    
    void resetKV() { if (handle_) Deep2_ResetKVCache(handle_); }
    void trimKV(size_t keep) { if (handle_) Deep2_TrimKVCache(handle_, keep); }
    
    void getMemoryInfo(size_t* kv, size_t* model, size_t* peak) {
        if (handle_) Deep2_GetMemoryInfo(handle_, kv, model, peak);
    }
    
    operator bool() const { return handle_ != nullptr; }
    Deep2Context* get() const { return handle_; }
    
    void setVocabSize(size_t sz) { vocab_size_ = sz; }
    
private:
    Deep2Context* handle_;
    size_t vocab_size_ = 32000; // default
};

} // namespace Deep2

#endif // __cplusplus