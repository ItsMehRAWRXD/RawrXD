// RawrXD_LlamaNative.cpp - llama.cpp Native DLL Bridge Implementation
// Zero HTTP. Zero MASM. Pure LoadLibraryW + GetProcAddress + cdecl calls.
// Target: llama.cpp b3506+ with Vulkan backend for RX 7800 XT

#include "RawrXD_LlamaNative.h"
#include "inference/pipeline_telemetry.hpp"
#include <chrono>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <filesystem>

// ============================================================================
// Static singleton instance (no heap allocation on first access)
// ============================================================================
LlamaNativeBridge& GetLlamaBridge() {
    static LlamaNativeBridge g_bridge;
    return g_bridge;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================
LlamaNativeBridge::LlamaNativeBridge() {
    // Defer heap-backed buffer growth to generation-time to avoid startup allocator spikes.
}

LlamaNativeBridge::~LlamaNativeBridge() {
    Shutdown();
}

void LlamaNativeBridge::SetError(const char* msg) {
    lastError_ = msg;
}

// ============================================================================
// Initialize - Load DLLs and bind exports
// ============================================================================
bool LlamaNativeBridge::Initialize(const wchar_t* dllDir) {
    if (hLlama_) return true;  // Already initialized

    // Build DLL path prefix
    std::wstring prefix;
    if (dllDir) {
        prefix = dllDir;
        if (!prefix.empty() && prefix.back() != L'\\' && prefix.back() != L'/') {
            prefix += L'\\';
        }
    } else {
        // Default to the executable directory only; avoid implicit PATH-wide DLL side-loading.
        wchar_t exePath[MAX_PATH] = {};
        const DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        if (len > 0 && len < MAX_PATH) {
            std::wstring p(exePath, len);
            const size_t slash = p.find_last_of(L"\\/");
            if (slash != std::wstring::npos) {
                prefix = p.substr(0, slash + 1);
            }
        }
    }

    // Load ggml backends from explicit prefix only.
    std::wstring ggmlVkPath = prefix + L"ggml-vulkan.dll";
    std::wstring ggmlCpuPath = prefix + L"ggml-cpu.dll";
    std::wstring ggmlBasePath = prefix + L"ggml.dll";

    hGgmlVk_ = LoadLibraryW(ggmlVkPath.c_str());
    hGgmlCpu_ = LoadLibraryW(ggmlCpuPath.c_str());
    hGgml_ = LoadLibraryW(ggmlBasePath.c_str());

    // Load llama.dll
    std::wstring llamaPath = prefix + L"llama.dll";
    hLlama_ = LoadLibraryW(llamaPath.c_str());
    if (!hLlama_) {
        std::stringstream ss;
        ss << "Failed to load llama.dll (error " << GetLastError() << "). "
           << "Ensure llama.dll is in: " << (dllDir ? "specified directory" : "exe directory");
        SetError(ss.str().c_str());
        return false;
    }

    if (hGgml_) {
        fn_ggml_backend_load_all = reinterpret_cast<pfn_ggml_backend_load_all>(
            GetProcAddress(hGgml_, "ggml_backend_load_all"));
    }
    if (!fn_ggml_backend_load_all && hLlama_) {
        fn_ggml_backend_load_all = reinterpret_cast<pfn_ggml_backend_load_all>(
            GetProcAddress(hLlama_, "ggml_backend_load_all"));
    }

    if (!BindExports()) {
        FreeLibrary(hLlama_);
        hLlama_ = nullptr;
        return false;
    }

    // Initialize backend
    if (fn_backend_init) {
        fn_backend_init();
    }

    return true;
}

// ============================================================================
// BindExports - GetProcAddress for all required functions
// ============================================================================
bool LlamaNativeBridge::BindExports() {
    auto bindRequired = [this](const char* name) -> FARPROC {
        FARPROC proc = GetProcAddress(hLlama_, name);
        if (!proc) {
            std::string err = "Missing export: ";
            err += name;
            SetError(err.c_str());
        }
        return proc;
    };

    auto bindAny = [this](std::initializer_list<const char*> names) -> FARPROC {
        for (const char* name : names) {
            if (FARPROC proc = GetProcAddress(hLlama_, name)) {
                return proc;
            }
        }
        if (names.size() > 0) {
            std::string err = "Missing export (aliases): ";
            bool first = true;
            for (const char* name : names) {
                if (!first) {
                    err += " | ";
                }
                first = false;
                err += name;
            }
            SetError(err.c_str());
        }
        return nullptr;
    };

    // Required exports (support old/new llama.cpp symbol naming)
    fn_backend_init = reinterpret_cast<pfn_backend_init>(bindRequired("llama_backend_init"));
    if (!fn_backend_init) {
        return false;
    }

    fn_model_default_params = reinterpret_cast<pfn_model_default_params>(
        bindRequired("llama_model_default_params"));
    if (!fn_model_default_params) {
        return false;
    }

    fn_load_model = reinterpret_cast<pfn_load_model>(bindAny({
        "llama_load_model",
        "llama_load_model_from_file",
        "llama_model_load_from_file"
    }));
    if (!fn_load_model) {
        return false;
    }

    fn_free_model = reinterpret_cast<pfn_free_model>(bindAny({
        "llama_free_model",
        "llama_model_free"
    }));
    if (!fn_free_model) {
        return false;
    }

    fn_model_get_vocab = reinterpret_cast<pfn_model_get_vocab>(
        bindRequired("llama_model_get_vocab"));
    if (!fn_model_get_vocab) {
        return false;
    }
    fn_model_n_vocab = reinterpret_cast<pfn_model_n_vocab>(bindAny({
        "llama_vocab_n_tokens",
        "llama_n_vocab"
    }));
    fn_context_default_params = reinterpret_cast<pfn_context_default_params>(
        bindRequired("llama_context_default_params"));
    if (!fn_context_default_params) {
        return false;
    }
    fn_new_context = reinterpret_cast<pfn_new_context>(bindAny({
        "llama_new_context_with_model",
        "llama_init_from_model"
    }));
    fn_free_context = reinterpret_cast<pfn_free_context>(bindRequired("llama_free"));
    fn_kv_cache_clear = reinterpret_cast<pfn_kv_cache_clear>(bindAny({
        "llama_kv_cache_clear",
        "llama_kv_self_clear"
    }));
    fn_tokenize = reinterpret_cast<pfn_tokenize>(bindRequired("llama_tokenize"));
    fn_token_to_piece = reinterpret_cast<pfn_token_to_piece>(bindRequired("llama_token_to_piece"));
    fn_token_bos = reinterpret_cast<pfn_token_bos>(bindRequired("llama_token_bos"));
    fn_token_eos = reinterpret_cast<pfn_token_eos>(bindRequired("llama_token_eos"));
    fn_batch_init = reinterpret_cast<pfn_batch_init>(bindRequired("llama_batch_init"));
    fn_batch_free = reinterpret_cast<pfn_batch_free>(bindRequired("llama_batch_free"));
    fn_decode = reinterpret_cast<pfn_decode>(bindRequired("llama_decode"));
    fn_get_logits_ith = reinterpret_cast<pfn_get_logits_ith>(bindRequired("llama_get_logits_ith"));

    if (!fn_new_context || !fn_free_context || !fn_tokenize ||
        !fn_token_to_piece || !fn_token_bos || !fn_token_eos || !fn_batch_init ||
        !fn_batch_free || !fn_decode || !fn_get_logits_ith) {
        // bindRequired()/bindAny() already set a detailed message for the first miss.
        if (lastError_.empty()) {
            SetError("Critical exports missing from llama.dll");
        }
        return false;
    }

    // Optional sampler exports (b3506+)
    fn_sampler_chain_init = (pfn_sampler_chain_init)GetProcAddress(hLlama_, "llama_sampler_chain_init");
    fn_sampler_chain_add = (pfn_sampler_chain_add)GetProcAddress(hLlama_, "llama_sampler_chain_add");
    fn_sampler_sample = (pfn_sampler_sample)GetProcAddress(hLlama_, "llama_sampler_sample");
    fn_sampler_free = (pfn_sampler_free)GetProcAddress(hLlama_, "llama_sampler_free");
    fn_sampler_init_temp = (pfn_sampler_init_temp)GetProcAddress(hLlama_, "llama_sampler_init_temp");
    fn_sampler_init_top_k = (pfn_sampler_init_top_k)GetProcAddress(hLlama_, "llama_sampler_init_top_k");
    fn_sampler_init_top_p = (pfn_sampler_init_top_p)GetProcAddress(hLlama_, "llama_sampler_init_top_p");
    fn_sampler_init_greedy = (pfn_sampler_init_greedy)GetProcAddress(hLlama_, "llama_sampler_init_greedy");

    // Backend cleanup (optional)
    fn_backend_free = (pfn_backend_free)GetProcAddress(hLlama_, "llama_backend_free");

    return true;
}

// ============================================================================
// Shutdown - Free resources
// ============================================================================
void LlamaNativeBridge::Shutdown() {
    UnloadModel();

    if (fn_backend_free) {
        fn_backend_free();
    }

    if (hLlama_) { FreeLibrary(hLlama_); hLlama_ = nullptr; }
    if (hGgml_) { FreeLibrary(hGgml_); hGgml_ = nullptr; }
    if (hGgmlVk_) { FreeLibrary(hGgmlVk_); hGgmlVk_ = nullptr; }
    if (hGgmlCpu_) { FreeLibrary(hGgmlCpu_); hGgmlCpu_ = nullptr; }

    // Clear function pointers
    fn_backend_init = nullptr;
    fn_load_model = nullptr;
    // ... (all others implicitly nullptr after DLL unload)
}

// ============================================================================
// LoadModel - Load GGUF model file
// ============================================================================
bool LlamaNativeBridge::LoadModel(const wchar_t* modelPath, int32_t gpuLayers, uint32_t ctxSize) {
    if (!hLlama_) {
        SetError("DLL not initialized");
        return false;
    }

    UnloadModel();  // Unload any existing model

    if (fn_ggml_backend_load_all) {
        fn_ggml_backend_load_all();
    }

    // Convert wide path to UTF-8
    char pathUtf8[1024];
    int pathLen = WideCharToMultiByte(CP_UTF8, 0, modelPath, -1, pathUtf8, sizeof(pathUtf8), nullptr, nullptr);
    if (pathLen == 0) {
        SetError("Invalid model path encoding");
        return false;
    }

    // Get default params
    llama_model_params mParams = {};
    if (fn_model_default_params) {
        mParams = fn_model_default_params();
    }
    
    // Override GPU layers (-1 = max offload)
    mParams.n_gpu_layers = (gpuLayers < 0) ? 999 : gpuLayers;
    mParams.use_mmap = true;
    mParams.use_mlock = false;

    // Load model
    model_ = fn_load_model(pathUtf8, mParams);
    if (!model_) {
        SetError("Failed to load model file (invalid GGUF or missing tensors)");
        return false;
    }

    // Get context params
    llama_context_params cParams = {};
    if (fn_context_default_params) {
        cParams = fn_context_default_params();
    }
    cParams.n_ctx = ctxSize;
    cParams.n_batch = 512;
    cParams.n_ubatch = 512;
    cParams.n_threads = nThreads_;
    cParams.n_threads_batch = nThreads_;
    ctxSize_ = ctxSize;

    // Apply KV cache quantization if configured
    if (kvTypeK_ > 0) cParams.type_k = kvTypeK_;
    if (kvTypeV_ > 0) cParams.type_v = kvTypeV_;

    // Create context
    ctx_ = fn_new_context(model_, cParams);
    if (!ctx_) {
        fn_free_model(model_);
        model_ = nullptr;
        SetError("Failed to create inference context (OOM?)");
        return false;
    }

    // Initialize batch
    batch_ = fn_batch_init(512, 0, 1);

    // Store model info
    modelInfo_.loaded = true;
    modelInfo_.path = pathUtf8;
    vocab_ = nullptr;
    if (fn_model_get_vocab) {
        vocab_ = const_cast<llama_vocab_t>(fn_model_get_vocab(model_));
    }
    if (!vocab_) {
        SetError("Failed to resolve model vocabulary handle");
        return false;
    }

    if (fn_model_n_vocab) {
        modelInfo_.n_vocab = fn_model_n_vocab(vocab_);
    }
    if (fn_token_bos) {
        modelInfo_.bos = fn_token_bos(vocab_);
    }
    if (fn_token_eos) {
        modelInfo_.eos = fn_token_eos(vocab_);
    }

    return true;
}

// ============================================================================
// UnloadModel - Free model and context
// ============================================================================
void LlamaNativeBridge::UnloadModel() {
    if (sampler_ && fn_sampler_free) {
        fn_sampler_free(sampler_);
        sampler_ = nullptr;
    }

    if (batch_.token && fn_batch_free) {
        fn_batch_free(batch_);
        batch_ = {};
    }

    if (ctx_ && fn_free_context) {
        fn_free_context(ctx_);
        ctx_ = nullptr;
    }

    vocab_ = nullptr;

    if (model_ && fn_free_model) {
        fn_free_model(model_);
        model_ = nullptr;
    }

    modelInfo_ = {};
}

// ============================================================================
// ClearKVCache - Reset for new conversation
// ============================================================================
void LlamaNativeBridge::SetThreads(int32_t nThreads) {
    if (nThreads > 0) {
        nThreads_ = nThreads;
    }
}

void LlamaNativeBridge::ClearKVCache() {
    if (ctx_ && fn_kv_cache_clear) {
        fn_kv_cache_clear(ctx_);
    } else if (ctx_ && model_ && fn_free_context && fn_new_context && fn_context_default_params) {
        // Older llama.dll ABIs may not export kv-cache clear; recreate context to force a clean state.
        llama_context_params cParams = fn_context_default_params();
        cParams.n_ctx = ctxSize_;
        cParams.n_batch = 512;
        cParams.n_ubatch = 512;
        cParams.n_threads = 8;
        cParams.n_threads_batch = 8;
        if (kvTypeK_ > 0) cParams.type_k = kvTypeK_;
        if (kvTypeV_ > 0) cParams.type_v = kvTypeV_;

        if (llama_context_t freshCtx = fn_new_context(model_, cParams)) {
            fn_free_context(ctx_);
            ctx_ = freshCtx;
        }
    }
    cachedPromptTokens_.clear();
}

int32_t LlamaNativeBridge::GetTopToken() {
    if (!ctx_ || !fn_get_logits_ith) {
        return -1;
    }

    float* logits = fn_get_logits_ith(ctx_, -1);
    if (!logits) {
        return -1;
    }

    const int32_t vocabSize = modelInfo_.n_vocab > 0 ? modelInfo_.n_vocab : 32000;
    int32_t best = 0;
    float maxLogit = logits[0];
    for (int32_t v = 1; v < vocabSize; ++v) {
        if (logits[v] > maxLogit) {
            maxLogit = logits[v];
            best = v;
        }
    }
    return best;
}

std::string LlamaNativeBridge::TokenToPiece(int32_t token) {
    if (!vocab_ || !fn_token_to_piece) {
        return {};
    }

    if (pieceBuf_.size() < 512) {
        pieceBuf_.resize(512);
    }

    const int32_t nChars = fn_token_to_piece(
        vocab_,
        static_cast<llama_token>(token),
        pieceBuf_.data(),
        static_cast<int32_t>(pieceBuf_.size()),
        0,
        false
    );
    if (nChars <= 0) {
        return {};
    }
    return std::string(pieceBuf_.data(), nChars);
}

bool LlamaNativeBridge::DecodeTokenBatch(const std::vector<int32_t>& tokens, bool logitsOnLastToken) {
    if (!ctx_ || !fn_decode) {
        SetError("DecodeTokenBatch called before model/context ready");
        return false;
    }

    if (tokens.empty()) {
        return true;
    }

    int32_t nPast = static_cast<int32_t>(cachedPromptTokens_.size());
    for (size_t i = 0; i < tokens.size(); ++i) {
        batch_.n_tokens = 1;
        batch_.token[0] = static_cast<llama_token>(tokens[i]);
        batch_.pos[0] = nPast;
        batch_.n_seq_id[0] = 1;
        batch_.seq_id[0][0] = 0;
        batch_.logits[0] = (logitsOnLastToken && i + 1 == tokens.size()) ? 1 : 0;

        const int32_t decodeResult = fn_decode(ctx_, batch_);
        if (decodeResult != 0) {
            std::stringstream ss;
            ss << "DecodeTokenBatch failed at idx " << i << " (code " << decodeResult << ")";
            SetError(ss.str().c_str());
            return false;
        }

        cachedPromptTokens_.push_back(static_cast<llama_token>(tokens[i]));
        ++nPast;
    }

    return true;
}

bool LlamaNativeBridge::RewindToTokenCount(int32_t tokenCount) {
    if (!ctx_) {
        SetError("RewindToTokenCount called before model/context ready");
        return false;
    }

    if (tokenCount < 0) {
        tokenCount = 0;
    }
    const int32_t current = static_cast<int32_t>(cachedPromptTokens_.size());
    if (tokenCount > current) {
        SetError("Rewind target exceeds current token count");
        return false;
    }
    if (tokenCount == current) {
        return true;
    }

    std::vector<llama_token> replayPrefix(
        cachedPromptTokens_.begin(),
        cachedPromptTokens_.begin() + tokenCount
    );

    ClearKVCache();
    if (tokenCount == 0) {
        return true;
    }

    int32_t nPast = 0;
    for (int32_t i = 0; i < tokenCount; ++i) {
        batch_.n_tokens = 1;
        batch_.token[0] = replayPrefix[static_cast<size_t>(i)];
        batch_.pos[0] = nPast;
        batch_.n_seq_id[0] = 1;
        batch_.seq_id[0][0] = 0;
        batch_.logits[0] = (i + 1 == tokenCount) ? 1 : 0;

        const int32_t decodeResult = fn_decode(ctx_, batch_);
        if (decodeResult != 0) {
            std::stringstream ss;
            ss << "Rewind replay failed at idx " << i << " (code " << decodeResult << ")";
            SetError(ss.str().c_str());
            ClearKVCache();
            return false;
        }
        ++nPast;
    }

    cachedPromptTokens_ = std::move(replayPrefix);
    return true;
}

// ============================================================================
// SetupSampler - Configure sampling chain
// ============================================================================
bool LlamaNativeBridge::SetupSampler(float temp, float topP, int32_t topK) {
    (void)temp;
    (void)topP;
    (void)topK;

    // Free existing sampler
    if (sampler_ && fn_sampler_free) {
        fn_sampler_free(sampler_);
        sampler_ = nullptr;
    }

    // Bridge safe mode: rely on deterministic greedy path in Generate()/GenerateStream().
    return true;
}

// ============================================================================
// Generate - Synchronous text generation
// ============================================================================
LlamaNativeBridge::GenerationResult LlamaNativeBridge::Generate(
    const std::string& prompt,
    int32_t maxTokens,
    float temperature,
    float topP,
    int32_t topK
) {
    GenerationResult result;

    if (!ctx_) {
        result.error = "Model not loaded";
        return result;
    }

    auto timeStart = std::chrono::high_resolution_clock::now();

    if (tokenBuf_.size() < 8192) tokenBuf_.resize(8192);
    if (pieceBuf_.size() < 512) pieceBuf_.resize(512);
    if (posBuf_.size() < 8192) posBuf_.resize(8192);
    if (seqBuf_.size() < 1) seqBuf_.resize(1);
    if (logitsBuf_.size() < 8192) logitsBuf_.resize(8192);

    // Setup sampler chain
    SetupSampler(temperature, topP, topK);

    // ========================================================================
    // 1. Tokenize prompt
    // ========================================================================
    int32_t nPromptTokens = fn_tokenize(
        vocab_,
        prompt.c_str(),
        static_cast<int32_t>(prompt.length()),
        tokenBuf_.data(),
        static_cast<int32_t>(tokenBuf_.size()),
        true,   // add_special (BOS)
        false   // parse_special
    );

    if (nPromptTokens < 0) {
        result.error = "Tokenization failed (prompt too long?)";
        return result;
    }
    result.prompt_tokens = nPromptTokens;

    size_t reusePrefix = 0;
    const bool canReuse = preserveKVCache_ && !cachedPromptTokens_.empty();
    if (canReuse) {
        const size_t limit = std::min<size_t>(cachedPromptTokens_.size(), static_cast<size_t>(nPromptTokens));
        while (reusePrefix < limit && cachedPromptTokens_[reusePrefix] == tokenBuf_[reusePrefix]) {
            ++reusePrefix;
        }
    }

    result.prefix_tokens_matched_pre_reset = static_cast<int32_t>(reusePrefix);
    result.cached_tokens_before_reset = static_cast<int32_t>(cachedPromptTokens_.size());

    const bool resetDueToPolicy = !preserveKVCache_;
    const bool resetDueToMismatch = preserveKVCache_ && (reusePrefix != cachedPromptTokens_.size());
    if (resetDueToPolicy || resetDueToMismatch) {
        ClearKVCache();
        reusePrefix = 0;
    }

    result.prompt_tokens_reused = static_cast<int32_t>(reusePrefix);
    result.prompt_tokens_computed = nPromptTokens - static_cast<int32_t>(reusePrefix);
    result.cache_hit = (result.prompt_tokens_reused > 0);
    result.cache_reset_due_to_mismatch = resetDueToMismatch;
    result.cache_reset_due_to_policy = resetDueToPolicy;

    // ========================================================================
    // 2. Decode prompt tokens (fill KV cache)
    // ========================================================================
    int32_t nPast = static_cast<int32_t>(reusePrefix);
    result.n_past_start = nPast;
    for (int32_t i = static_cast<int32_t>(reusePrefix); i < nPromptTokens; ++i) {
        // Setup batch for single token
        batch_.n_tokens = 1;
        batch_.token[0] = tokenBuf_[i];
        batch_.pos[0] = nPast;
        batch_.n_seq_id[0] = 1;
        batch_.seq_id[0][0] = 0;
        batch_.logits[0] = (i == nPromptTokens - 1) ? 1 : 0;  // Only last token needs logits

        int32_t decodeResult = fn_decode(ctx_, batch_);
        if (decodeResult != 0) {
            std::stringstream ss;
            ss << "Decode failed at prompt token " << i << " (code " << decodeResult << ")";
            result.error = ss.str();
            return result;
        }

        ++nPast;
    }

    auto timePromptDone = std::chrono::high_resolution_clock::now();
    result.t_prompt_ms = std::chrono::duration<double, std::milli>(timePromptDone - timeStart).count();
    bool firstTokenSeen = false;

    // ========================================================================
    // 3. Generation loop
    // ========================================================================
    cachedPromptTokens_.assign(tokenBuf_.begin(), tokenBuf_.begin() + nPromptTokens);
    result.text.reserve(maxTokens * 4);  // Rough estimate

    for (int32_t i = 0; i < maxTokens; ++i) {
        // Get logits for last decoded token
        float* logits = fn_get_logits_ith(ctx_, -1);
        if (!logits) {
            result.error = "Failed to get logits";
            break;
        }

        // Sample next token
        llama_token nextToken;
        
        if (sampler_ && fn_sampler_sample) {
            // Use sampler chain
            nextToken = fn_sampler_sample(sampler_, ctx_, -1);
        } else {
            // Greedy argmax fallback
            int32_t vocabSize = modelInfo_.n_vocab > 0 ? modelInfo_.n_vocab : 32000;
            nextToken = 0;
            float maxLogit = logits[0];
            for (int32_t v = 1; v < vocabSize; ++v) {
                if (logits[v] > maxLogit) {
                    maxLogit = logits[v];
                    nextToken = v;
                }
            }
        }

        // Check for EOS
        if (nextToken == modelInfo_.eos || nextToken == 2) {
            break;
        }

        // Detokenize
        if (fn_token_to_piece) {
            int32_t nChars = fn_token_to_piece(
                vocab_, nextToken,
                pieceBuf_.data(), static_cast<int32_t>(pieceBuf_.size()),
                0, false
            );
            if (nChars > 0) {
                result.text.append(pieceBuf_.data(), nChars);
                if (!firstTokenSeen) {
                    const auto now = std::chrono::high_resolution_clock::now();
                    result.t_first_token_ms = std::chrono::duration<double, std::milli>(now - timeStart).count();
                    firstTokenSeen = true;
                }
            }
        }

        // Decode next token
        batch_.n_tokens = 1;
        batch_.token[0] = nextToken;
        batch_.pos[0] = nPast;
        batch_.n_seq_id[0] = 1;
        batch_.seq_id[0][0] = 0;
        batch_.logits[0] = 1;

        int32_t decodeResult = fn_decode(ctx_, batch_);
        if (decodeResult != 0) {
            result.error = "Generation decode failed";
            break;
        }

        ++nPast;
        cachedPromptTokens_.push_back(nextToken);
        result.generated_token_ids.push_back(static_cast<int32_t>(nextToken));
        ++result.tokens_generated;
    }

    result.n_past_end = nPast;

    auto timeGenDone = std::chrono::high_resolution_clock::now();
    result.t_gen_ms = std::chrono::duration<double, std::milli>(timeGenDone - timePromptDone).count();
    result.success = true;
    
    // Record telemetry for the governor/dashboard
    if (result.tokens_generated > 0 && result.t_gen_ms > 0) {
        auto* telemetry = RawrXD::Inference::PipelineTelemetryCollector::Instance();
        telemetry->RecordTokenBatch(
            static_cast<size_t>(result.tokens_generated),
            result.t_gen_ms
        );
    }

    return result;
}

// ============================================================================
// GenerateStream — token-by-token streaming with callback
// ============================================================================
LlamaNativeBridge::GenerationResult LlamaNativeBridge::GenerateStream(
    const std::string& prompt,
    TokenCallback on_token,
    int32_t maxTokens,
    float temperature,
    float topP,
    int32_t topK
) {
    GenerationResult result;

    if (!ctx_) {
        result.error = "Model not loaded";
        return result;
    }

    auto timeStart = std::chrono::high_resolution_clock::now();

    if (tokenBuf_.size() < 8192) tokenBuf_.resize(8192);
    if (pieceBuf_.size() < 512) pieceBuf_.resize(512);
    if (posBuf_.size() < 8192) posBuf_.resize(8192);
    if (seqBuf_.size() < 1) seqBuf_.resize(1);
    if (logitsBuf_.size() < 8192) logitsBuf_.resize(8192);

    // Setup sampler chain
    SetupSampler(temperature, topP, topK);

    // ========================================================================
    // 1. Tokenize prompt
    // ========================================================================
    int32_t nPromptTokens = fn_tokenize(
        vocab_,
        prompt.c_str(),
        static_cast<int32_t>(prompt.length()),
        tokenBuf_.data(),
        static_cast<int32_t>(tokenBuf_.size()),
        true,   // add_special (BOS)
        false   // parse_special
    );

    if (nPromptTokens < 0) {
        result.error = "Tokenization failed (prompt too long?)";
        return result;
    }
    result.prompt_tokens = nPromptTokens;

    size_t reusePrefix = 0;
    const bool canReuse = preserveKVCache_ && !cachedPromptTokens_.empty();
    if (canReuse) {
        const size_t limit = std::min<size_t>(cachedPromptTokens_.size(), static_cast<size_t>(nPromptTokens));
        while (reusePrefix < limit && cachedPromptTokens_[reusePrefix] == tokenBuf_[reusePrefix]) {
            ++reusePrefix;
        }
    }

    result.prefix_tokens_matched_pre_reset = static_cast<int32_t>(reusePrefix);
    result.cached_tokens_before_reset = static_cast<int32_t>(cachedPromptTokens_.size());

    const bool resetDueToPolicy = !preserveKVCache_;
    const bool resetDueToMismatch = preserveKVCache_ && (reusePrefix != cachedPromptTokens_.size());
    if (resetDueToPolicy || resetDueToMismatch) {
        ClearKVCache();
        reusePrefix = 0;
    }

    result.prompt_tokens_reused = static_cast<int32_t>(reusePrefix);
    result.prompt_tokens_computed = nPromptTokens - static_cast<int32_t>(reusePrefix);
    result.cache_hit = (result.prompt_tokens_reused > 0);
    result.cache_reset_due_to_mismatch = resetDueToMismatch;
    result.cache_reset_due_to_policy = resetDueToPolicy;

    // ========================================================================
    // 2. Decode prompt tokens (fill KV cache)
    // ========================================================================
    int32_t nPast = static_cast<int32_t>(reusePrefix);
    result.n_past_start = nPast;
    for (int32_t i = static_cast<int32_t>(reusePrefix); i < nPromptTokens; ++i) {
        batch_.n_tokens = 1;
        batch_.token[0] = tokenBuf_[i];
        batch_.pos[0] = nPast;
        batch_.n_seq_id[0] = 1;
        batch_.seq_id[0][0] = 0;
        batch_.logits[0] = (i == nPromptTokens - 1) ? 1 : 0;

        int32_t decodeResult = fn_decode(ctx_, batch_);
        if (decodeResult != 0) {
            std::stringstream ss;
            ss << "Decode failed at prompt token " << i << " (code " << decodeResult << ")";
            result.error = ss.str();
            return result;
        }

        ++nPast;
    }

    auto timePromptDone = std::chrono::high_resolution_clock::now();
    result.t_prompt_ms = std::chrono::duration<double, std::milli>(timePromptDone - timeStart).count();
    bool firstTokenSeen = false;

    // ========================================================================
    // 3. Streaming generation loop
    // ========================================================================
    cachedPromptTokens_.assign(tokenBuf_.begin(), tokenBuf_.begin() + nPromptTokens);
    result.text.reserve(maxTokens * 4);

    for (int32_t i = 0; i < maxTokens; ++i) {
        float* logits = fn_get_logits_ith(ctx_, -1);
        if (!logits) {
            result.error = "Failed to get logits";
            break;
        }

        llama_token nextToken;
        if (sampler_ && fn_sampler_sample) {
            nextToken = fn_sampler_sample(sampler_, ctx_, -1);
        } else {
            int32_t vocabSize = modelInfo_.n_vocab > 0 ? modelInfo_.n_vocab : 32000;
            nextToken = 0;
            float maxLogit = logits[0];
            for (int32_t v = 1; v < vocabSize; ++v) {
                if (logits[v] > maxLogit) {
                    maxLogit = logits[v];
                    nextToken = v;
                }
            }
        }

        if (nextToken == modelInfo_.eos || nextToken == 2) {
            break;
        }

        // Detokenize and stream
        if (fn_token_to_piece) {
            int32_t nChars = fn_token_to_piece(
                vocab_, nextToken,
                pieceBuf_.data(), static_cast<int32_t>(pieceBuf_.size()),
                0, false
            );
            if (nChars > 0) {
                std::string piece(pieceBuf_.data(), nChars);
                result.text += piece;
                if (!firstTokenSeen) {
                    const auto now = std::chrono::high_resolution_clock::now();
                    result.t_first_token_ms = std::chrono::duration<double, std::milli>(now - timeStart).count();
                    firstTokenSeen = true;
                }
                if (on_token) {
                    on_token(piece);
                }
            }
        }

        batch_.n_tokens = 1;
        batch_.token[0] = nextToken;
        batch_.pos[0] = nPast;
        batch_.n_seq_id[0] = 1;
        batch_.seq_id[0][0] = 0;
        batch_.logits[0] = 1;

        int32_t decodeResult = fn_decode(ctx_, batch_);
        if (decodeResult != 0) {
            result.error = "Generation decode failed";
            break;
        }

        ++nPast;
        cachedPromptTokens_.push_back(nextToken);
        result.generated_token_ids.push_back(static_cast<int32_t>(nextToken));
        ++result.tokens_generated;
    }

    result.n_past_end = nPast;

    auto timeGenDone = std::chrono::high_resolution_clock::now();
    result.t_gen_ms = std::chrono::duration<double, std::milli>(timeGenDone - timePromptDone).count();
    result.success = true;
    
    // Record telemetry for the governor/dashboard
    if (result.tokens_generated > 0 && result.t_gen_ms > 0) {
        auto* telemetry = RawrXD::Inference::PipelineTelemetryCollector::Instance();
        telemetry->RecordTokenBatch(
            static_cast<size_t>(result.tokens_generated),
            result.t_gen_ms
        );
    }

    return result;
}

// ============================================================================
// ContinueStream — append-only generation against existing KV context
// ============================================================================
LlamaNativeBridge::GenerationResult LlamaNativeBridge::ContinueStream(
    const std::string& promptSuffix,
    TokenCallback on_token,
    int32_t maxTokens,
    float temperature,
    float topP,
    int32_t topK
) {
    GenerationResult result;

    if (!ctx_) {
        result.error = "Model not loaded";
        return result;
    }

    auto timeStart = std::chrono::high_resolution_clock::now();

    if (tokenBuf_.size() < 8192) tokenBuf_.resize(8192);
    if (pieceBuf_.size() < 512) pieceBuf_.resize(512);
    if (posBuf_.size() < 8192) posBuf_.resize(8192);
    if (seqBuf_.size() < 1) seqBuf_.resize(1);
    if (logitsBuf_.size() < 8192) logitsBuf_.resize(8192);

    SetupSampler(temperature, topP, topK);

    // Tokenize only the new suffix and do not add BOS for continuation turns.
    int32_t nSuffixTokens = fn_tokenize(
        vocab_,
        promptSuffix.c_str(),
        static_cast<int32_t>(promptSuffix.length()),
        tokenBuf_.data(),
        static_cast<int32_t>(tokenBuf_.size()),
        false,
        false
    );

    if (nSuffixTokens < 0) {
        result.error = "Tokenization failed (suffix too long?)";
        return result;
    }

    result.prompt_tokens = nSuffixTokens;
    result.prefix_tokens_matched_pre_reset = static_cast<int32_t>(cachedPromptTokens_.size());
    result.cached_tokens_before_reset = static_cast<int32_t>(cachedPromptTokens_.size());
    result.prompt_tokens_reused = static_cast<int32_t>(cachedPromptTokens_.size());
    result.prompt_tokens_computed = nSuffixTokens;
    result.cache_hit = !cachedPromptTokens_.empty();
    result.cache_reset_due_to_mismatch = false;
    result.cache_reset_due_to_policy = false;

    int32_t nPast = static_cast<int32_t>(cachedPromptTokens_.size());
    result.n_past_start = nPast;

    // Decode only new suffix tokens into the existing KV cache.
    for (int32_t i = 0; i < nSuffixTokens; ++i) {
        batch_.n_tokens = 1;
        batch_.token[0] = tokenBuf_[i];
        batch_.pos[0] = nPast;
        batch_.n_seq_id[0] = 1;
        batch_.seq_id[0][0] = 0;
        batch_.logits[0] = (i == nSuffixTokens - 1) ? 1 : 0;

        int32_t decodeResult = fn_decode(ctx_, batch_);
        if (decodeResult != 0) {
            std::stringstream ss;
            ss << "Decode failed at suffix token " << i << " (code " << decodeResult << ")";
            result.error = ss.str();
            return result;
        }

        ++nPast;
    }

    cachedPromptTokens_.insert(cachedPromptTokens_.end(), tokenBuf_.begin(), tokenBuf_.begin() + nSuffixTokens);

    auto timePromptDone = std::chrono::high_resolution_clock::now();
    result.t_prompt_ms = std::chrono::duration<double, std::milli>(timePromptDone - timeStart).count();
    bool firstTokenSeen = false;

    result.text.reserve(maxTokens * 4);

    for (int32_t i = 0; i < maxTokens; ++i) {
        float* logits = fn_get_logits_ith(ctx_, -1);
        if (!logits) {
            result.error = "Failed to get logits";
            break;
        }

        llama_token nextToken;
        if (sampler_ && fn_sampler_sample) {
            nextToken = fn_sampler_sample(sampler_, ctx_, -1);
        } else {
            int32_t vocabSize = modelInfo_.n_vocab > 0 ? modelInfo_.n_vocab : 32000;
            nextToken = 0;
            float maxLogit = logits[0];
            for (int32_t v = 1; v < vocabSize; ++v) {
                if (logits[v] > maxLogit) {
                    maxLogit = logits[v];
                    nextToken = v;
                }
            }
        }

        if (nextToken == modelInfo_.eos || nextToken == 2) {
            break;
        }

        if (fn_token_to_piece) {
            int32_t nChars = fn_token_to_piece(
                vocab_, nextToken,
                pieceBuf_.data(), static_cast<int32_t>(pieceBuf_.size()),
                0, false
            );
            if (nChars > 0) {
                std::string piece(pieceBuf_.data(), nChars);
                result.text += piece;
                if (!firstTokenSeen) {
                    const auto now = std::chrono::high_resolution_clock::now();
                    result.t_first_token_ms = std::chrono::duration<double, std::milli>(now - timeStart).count();
                    firstTokenSeen = true;
                }
                if (on_token) {
                    on_token(piece);
                }
            }
        }

        batch_.n_tokens = 1;
        batch_.token[0] = nextToken;
        batch_.pos[0] = nPast;
        batch_.n_seq_id[0] = 1;
        batch_.seq_id[0][0] = 0;
        batch_.logits[0] = 1;

        int32_t decodeResult = fn_decode(ctx_, batch_);
        if (decodeResult != 0) {
            result.error = "Generation decode failed";
            break;
        }

        ++nPast;
        cachedPromptTokens_.push_back(nextToken);
        result.generated_token_ids.push_back(static_cast<int32_t>(nextToken));
        ++result.tokens_generated;
    }

    result.n_past_end = nPast;

    auto timeGenDone = std::chrono::high_resolution_clock::now();
    result.t_gen_ms = std::chrono::duration<double, std::milli>(timeGenDone - timePromptDone).count();
    result.success = true;

    if (result.tokens_generated > 0 && result.t_gen_ms > 0) {
        auto* telemetry = RawrXD::Inference::PipelineTelemetryCollector::Instance();
        telemetry->RecordTokenBatch(
            static_cast<size_t>(result.tokens_generated),
            result.t_gen_ms
        );
    }

    return result;
}
