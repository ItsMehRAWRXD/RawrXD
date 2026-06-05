// RawrXD_LlamaNative.h - Native llama.cpp DLL Bridge
// Zero-copy binding via LoadLibraryW + GetProcAddress
// Target: llama.cpp b3506+ (cdecl, 8-byte aligned)
// GPU: AMD RX 7800 XT via ggml-vulkan.dll
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>

// ============================================================================
// C ABI from llama.cpp (minimal subset - llama.h compatible)
// ============================================================================
extern "C" {
    typedef struct llama_model* llama_model_t;
    typedef struct llama_context* llama_context_t;
    typedef struct llama_vocab* llama_vocab_t;
    typedef struct llama_sampler* llama_sampler_t;
    typedef int32_t llama_token;
    typedef int32_t llama_pos;
    typedef int32_t llama_seq_id;
    typedef void* ggml_backend_dev_t;
    typedef void* ggml_backend_buffer_type_t;

    using llama_progress_callback = bool (*)(float, void*);
    using ggml_backend_sched_eval_callback = void (*)(void*, void*);
    using ggml_abort_callback = bool (*)(void*);

    struct llama_model_tensor_buft_override {
        const char* pattern;
        ggml_backend_buffer_type_t buft;
    };

    struct llama_sampler_seq_config {
        llama_seq_id seq_id;
        llama_sampler_t sampler;
    };

    struct llama_sampler_chain_params {
        bool no_perf;
    };

    // llama_model_params (simplified - zero-init for defaults)
    struct llama_model_params {
        ggml_backend_dev_t* devices;
        const llama_model_tensor_buft_override* tensor_buft_overrides;
        int32_t n_gpu_layers;           // layers to offload to GPU
        int32_t split_mode;             // 0=none, 1=layer, 2=row
        int32_t main_gpu;               // main GPU index
        const float* tensor_split;      // per-GPU memory split (nullptr = auto)
        llama_progress_callback progress_callback;
        void* progress_callback_user_data;
        void* kv_overrides;             // metadata overrides
        bool vocab_only;
        bool use_mmap;
        bool use_direct_io;
        bool use_mlock;
        bool check_tensors;
        bool use_extra_bufts;
        bool no_host;
        bool no_alloc;
    };

    // llama_context_params (llama.cpp compatible layout)
    struct llama_context_params {
        uint32_t n_ctx;
        uint32_t n_batch;
        uint32_t n_ubatch;
        uint32_t n_seq_max;
        int32_t n_threads;
        int32_t n_threads_batch;

        int32_t rope_scaling_type;
        int32_t pooling_type;
        int32_t attention_type;
        int32_t flash_attn_type;

        float rope_freq_base;
        float rope_freq_scale;
        float yarn_ext_factor;
        float yarn_attn_factor;
        float yarn_beta_fast;
        float yarn_beta_slow;
        uint32_t yarn_orig_ctx;
        float defrag_thold;

        ggml_backend_sched_eval_callback cb_eval;
        void* cb_eval_user_data;

        int32_t type_k;                 // KV cache quantization
        int32_t type_v;

        ggml_abort_callback abort_callback;
        void* abort_callback_data;

        bool embeddings;
        bool offload_kqv;
        bool no_perf;
        bool op_offload;
        bool swa_full;
        bool kv_unified;

        llama_sampler_seq_config* samplers;
        size_t n_samplers;
    };

    // llama_batch (token batching)
    struct llama_batch {
        int32_t n_tokens;
        llama_token* token;             // tokens to decode
        float* embd;                    // embeddings (optional)
        llama_pos* pos;                 // positions
        int32_t* n_seq_id;
        llama_seq_id** seq_id;
        int8_t* logits;                 // which tokens get logits
    };

    // ========================================================================
    // Function pointer types (cdecl)
    // ========================================================================
    
    // Backend lifecycle
    using pfn_backend_init = void (*)();
    using pfn_backend_free = void (*)();
    using pfn_numa_init = void (*)(int32_t);
    using pfn_ggml_backend_load_all = void (*)();
    
    // Model lifecycle
    using pfn_model_default_params = llama_model_params (*)();
    using pfn_load_model = llama_model_t (*)(const char*, llama_model_params);
    using pfn_free_model = void (*)(llama_model_t);
    using pfn_model_get_vocab = const llama_vocab_t (*)(const llama_model_t);
    using pfn_model_n_vocab = int32_t (*)(const llama_vocab_t);
    
    // Context lifecycle
    using pfn_context_default_params = llama_context_params (*)();
    using pfn_new_context = llama_context_t (*)(llama_model_t, llama_context_params);
    using pfn_free_context = void (*)(llama_context_t);
    using pfn_kv_cache_clear = void (*)(llama_context_t);
    
    // Tokenization
    using pfn_tokenize = int32_t (*)(const llama_vocab_t, const char*, int32_t,
                                     llama_token*, int32_t, bool, bool);
    using pfn_token_to_piece = int32_t (*)(const llama_vocab_t, llama_token,
                                           char*, int32_t, int32_t, bool);
    using pfn_token_bos = llama_token (*)(const llama_vocab_t);
    using pfn_token_eos = llama_token (*)(const llama_vocab_t);
    
    // Inference
    using pfn_batch_init = llama_batch (*)(int32_t, int32_t, int32_t);
    using pfn_batch_free = void (*)(llama_batch);
    using pfn_decode = int32_t (*)(llama_context_t, llama_batch);
    using pfn_get_logits_ith = float* (*)(llama_context_t, int32_t);
    
    // Sampling chain (b3506+)
    using pfn_sampler_chain_init = llama_sampler_t (*)(llama_sampler_chain_params);
    using pfn_sampler_chain_add = void (*)(llama_sampler_t, llama_sampler_t);
    using pfn_sampler_sample = llama_token (*)(llama_sampler_t, llama_context_t, int32_t);
    using pfn_sampler_free = void (*)(llama_sampler_t);
    using pfn_sampler_init_temp = llama_sampler_t (*)(float);
    using pfn_sampler_init_top_k = llama_sampler_t (*)(int32_t);
    using pfn_sampler_init_top_p = llama_sampler_t (*)(float, size_t);
    using pfn_sampler_init_greedy = llama_sampler_t (*)();
}

// ============================================================================
// Streaming callback — invoked for each generated token piece
// ============================================================================
using TokenCallback = std::function<void(const std::string& token_piece)>;

// ============================================================================
// LlamaNativeBridge - Dynamic DLL binding for llama.cpp inference
// ============================================================================
class LlamaNativeBridge {
public:
    // Generation result (synchronous, non-streaming)
    struct GenerationResult {
        std::string text;
        std::vector<int32_t> generated_token_ids;
        int32_t tokens_generated = 0;
        int32_t prompt_tokens = 0;
        int32_t prompt_tokens_reused = 0;
        int32_t prompt_tokens_computed = 0;
        int32_t prefix_tokens_matched_pre_reset = 0;
        int32_t cached_tokens_before_reset = 0;
        bool cache_hit = false;
        bool cache_reset_due_to_mismatch = false;
        bool cache_reset_due_to_policy = false;
        int32_t n_past_start = 0;
        int32_t n_past_end = 0;
        double t_first_token_ms = 0.0;
        double t_prompt_ms = 0.0;
        double t_gen_ms = 0.0;
        bool success = false;
        std::string error;
    };

    // Model info
    struct ModelInfo {
        int32_t n_vocab = 0;
        int32_t n_ctx_train = 0;
        int32_t n_embd = 0;
        llama_token bos = 0;
        llama_token eos = 0;
        std::string path;
        bool loaded = false;
    };

    // Speculative decoding configuration
    struct SpeculativeConfig {
        bool enabled = false;
        int32_t draft_tokens = 5;
        float draft_temperature = 0.6f;
        std::string draft_model_path;  // Optional smaller draft model
    };

    LlamaNativeBridge();
    ~LlamaNativeBridge();

    // Non-copyable
    LlamaNativeBridge(const LlamaNativeBridge&) = delete;
    LlamaNativeBridge& operator=(const LlamaNativeBridge&) = delete;

    // ========================================================================
    // Lifecycle
    // ========================================================================
    
    // Initialize DLL binding (dllDir = directory containing llama.dll, or nullptr for exe dir)
    bool Initialize(const wchar_t* dllDir = nullptr);
    void Shutdown();
    
    // Load GGUF model (gpuLayers = -1 for auto/max)
    bool LoadModel(const wchar_t* modelPath, int32_t gpuLayers = -1, uint32_t ctxSize = 4096);
    void UnloadModel();
    
    // Configure runtime thread count (defaults to 8)
    void SetThreads(int32_t nThreads);
    
    // ========================================================================
    // Inference
    // ========================================================================
    
    // Synchronous generation (blocks until complete or maxTokens reached)
    GenerationResult Generate(
        const std::string& prompt,
        int32_t maxTokens = 2048,
        float temperature = 0.8f,
        float topP = 0.95f,
        int32_t topK = 40
    );

    // Streaming generation — invokes on_token for each detokenized piece
    GenerationResult GenerateStream(
        const std::string& prompt,
        TokenCallback on_token,
        int32_t maxTokens = 2048,
        float temperature = 0.8f,
        float topP = 0.95f,
        int32_t topK = 40
    );

    // Continuation generation — appends only new suffix tokens to existing KV state.
    GenerationResult ContinueStream(
        const std::string& promptSuffix,
        TokenCallback on_token,
        int32_t maxTokens = 2048,
        float temperature = 0.8f,
        float topP = 0.95f,
        int32_t topK = 40
    );

    // Read current top-1 token from last logits row (argmax).
    // Returns -1 when logits are unavailable.
    int32_t GetTopToken();

    // Detokenize a single token id into UTF-8 text piece.
    std::string TokenToPiece(int32_t token);

    // Decode a provided token batch into KV state.
    // When logitsOnLastToken=true, last token requests logits for next-step verification.
    bool DecodeTokenBatch(const std::vector<int32_t>& tokens, bool logitsOnLastToken = true);

    // Rewind KV/cached-token state to an exact token count by clear+replay.
    // Returns false if replay fails.
    bool RewindToTokenCount(int32_t tokenCount);

    // Current token count represented in cached prompt/KV sequence.
    int32_t GetCachedTokenCount() const { return static_cast<int32_t>(cachedPromptTokens_.size()); }
    
    // Clear KV cache (for new conversation)
    void ClearKVCache();

    // Preserve KV cache across calls when the next prompt extends the previous one.
    void SetKVCachePreservation(bool enable) { preserveKVCache_ = enable; }
    
    // ========================================================================
    // Configuration
    // ========================================================================
    void SetSpeculativeConfig(const SpeculativeConfig& cfg) { speculativeCfg_ = cfg; }
    void SetKVQuantType(int32_t type_k, int32_t type_v) { kvTypeK_ = type_k; kvTypeV_ = type_v; }

    // ========================================================================
    // State queries
    // ========================================================================
    bool IsInitialized() const { return hLlama_ != nullptr; }
    bool IsModelLoaded() const { return ctx_ != nullptr; }
    const ModelInfo& GetModelInfo() const { return modelInfo_; }
    const char* GetLastError() const { return lastError_.c_str(); }

private:
    // DLL handles
    HMODULE hLlama_ = nullptr;
    HMODULE hGgml_ = nullptr;
    HMODULE hGgmlVk_ = nullptr;
    HMODULE hGgmlCpu_ = nullptr;

    // Function pointers (bound via GetProcAddress)
    pfn_backend_init fn_backend_init = nullptr;
    pfn_backend_free fn_backend_free = nullptr;
    pfn_ggml_backend_load_all fn_ggml_backend_load_all = nullptr;
    pfn_model_default_params fn_model_default_params = nullptr;
    pfn_load_model fn_load_model = nullptr;
    pfn_free_model fn_free_model = nullptr;
    pfn_model_get_vocab fn_model_get_vocab = nullptr;
    pfn_model_n_vocab fn_model_n_vocab = nullptr;
    pfn_context_default_params fn_context_default_params = nullptr;
    pfn_new_context fn_new_context = nullptr;
    pfn_free_context fn_free_context = nullptr;
    pfn_kv_cache_clear fn_kv_cache_clear = nullptr;
    pfn_tokenize fn_tokenize = nullptr;
    pfn_token_to_piece fn_token_to_piece = nullptr;
    pfn_token_bos fn_token_bos = nullptr;
    pfn_token_eos fn_token_eos = nullptr;
    pfn_batch_init fn_batch_init = nullptr;
    pfn_batch_free fn_batch_free = nullptr;
    pfn_decode fn_decode = nullptr;
    pfn_get_logits_ith fn_get_logits_ith = nullptr;
    pfn_sampler_chain_init fn_sampler_chain_init = nullptr;
    pfn_sampler_chain_add fn_sampler_chain_add = nullptr;
    pfn_sampler_sample fn_sampler_sample = nullptr;
    pfn_sampler_free fn_sampler_free = nullptr;
    pfn_sampler_init_temp fn_sampler_init_temp = nullptr;
    pfn_sampler_init_top_k fn_sampler_init_top_k = nullptr;
    pfn_sampler_init_top_p fn_sampler_init_top_p = nullptr;
    pfn_sampler_init_greedy fn_sampler_init_greedy = nullptr;

    // Runtime state
    llama_model_t model_ = nullptr;
    llama_context_t ctx_ = nullptr;
    llama_vocab_t vocab_ = nullptr;
    llama_sampler_t sampler_ = nullptr;
    llama_batch batch_ = {};
    ModelInfo modelInfo_ = {};
    std::string lastError_;

    // Token buffers
    std::vector<llama_token> tokenBuf_;
    std::vector<char> pieceBuf_;
    std::vector<llama_pos> posBuf_;
    std::vector<llama_seq_id> seqBuf_;
    std::vector<int8_t> logitsBuf_;
    std::vector<llama_token> cachedPromptTokens_;

    // Configuration
    SpeculativeConfig speculativeCfg_;
    int32_t kvTypeK_ = 0;   // 0=default, 1=Q8_0, 2=Q4_0, 3=Q4_K
    int32_t kvTypeV_ = 0;
    int32_t nThreads_ = 8;
    bool preserveKVCache_ = false;
    uint32_t ctxSize_ = 4096;

    // Internal helpers
    bool BindExports();
    bool SetupSampler(float temp, float topP, int32_t topK);
    void SetError(const char* msg);
};

// ============================================================================
// Global singleton accessor (optional convenience)
// ============================================================================
LlamaNativeBridge& GetLlamaBridge();
