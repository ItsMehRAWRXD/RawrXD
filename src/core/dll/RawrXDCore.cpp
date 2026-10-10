// RawrXDCore.cpp - Core runtime DLL implementation with ModelGenie IR inference
#include "RawrXDCore.h"
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <cstdarg>
#include <cstdio>
#include <windows.h>
#include <psapi.h>
#include <memory>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <thread>
#include <atomic>

// Deep2 includes
#include <GGUFLoader.hpp>

// Native chat template renderer (GGUF tokenizer.chat_template)
#include "ChatTemplate.hpp"

// ModelGenie IRExecutor - the certified 300-op executor. This header pulls in
// the authoritative generated IR table, tensor ROM and model config, so there
// is exactly one definition of the execution graph for both the runtime library
// and this DLL.
#include "../../modelgenie/ModelGenieExecutor.hpp"

// ModelGenie runtime C API (mg_model_t / mg_context_t). The DLL's only
// inference path: mg_model_load verifies the IR ROM table against the GGUF,
// mg_context_generate streams generated tokens through the certified
// dispatch table.
#include <ModelGenieRuntime.h>

namespace {
    using namespace ::Deep2;  // Bring global Deep2 namespace into scope

    // The IR table this runtime executes; mirrors GEN::kExecutionOpCount from
    // src/deep2/modelgenie/ExecutionIR.generated.hpp.
    constexpr unsigned int kExpectedIrOpCount = GEN::kExecutionOpCount;

    struct InitState {
        bool initialized = false;
        RawrXDConfig config{};
        RawrXDLogCallback logCallback = nullptr;
        void* logUserData = nullptr;
        RawrXDLogLevel logLevel = RAWXD_LOG_INFO;
        RawrXDError lastError = RAWXD_OK;
        std::mutex mutex;
    };

    InitState& getState() {
        static InitState state;
        return state;
    }

    void setLastError(RawrXDError err) {
        getState().lastError = err;
    }

    void logMessage(RawrXDLogLevel level, const char* fmt, ...) {
        auto& state = getState();
        if (level < state.logLevel || !state.logCallback) return;

        va_list args;
        va_start(args, fmt);
        char buffer[4096];
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);

        state.logCallback(level, buffer, state.logUserData);
    }

    // Trampoline carrying the user callback + userData through
    // the ModelGenie runtime's token callback. EOS terminates
    // the stream (it is not delivered as text); returning false
    // from the user callback cancels generation.
    struct TokenCallbackBridge {
        RawrXDTokenCallback callback;
        void* userData;
        uint32_t eosId;
        int delivered = 0;

        static bool Invoke(uint32_t tokenId, const char* tokenText,
                             void* userData) {
            auto* self = static_cast<TokenCallbackBridge*>(userData);
            if (!self || !self->callback) return false;
            if (self->eosId != 0 && tokenId == self->eosId) {
                return false;  // EOS terminates the stream
            }
            if (!self->callback(static_cast<int>(tokenId),
                                  tokenText ? tokenText : "",
                                  self->userData)) {
                return false;  // caller requested cancellation
            }
            self->delivered++;
            return true;
        }
    };

    // Real model implementation using Deep2::GGUFLoader
    struct ModelImpl {
        std::string path;
        std::string name;
        std::string arch;
        size_t size = 0;
        int layers = 0;
        bool loaded = false;

        // Deep2 loader
        std::shared_ptr<::Deep2::GGUFLoader> loader;
        ::Deep2::GGUFTensor* getTensor(const std::string& name) {
            return loader ? loader->getTensor(name) : nullptr;
        }

        const std::vector<std::string> listTensors() const {
            return loader ? loader->listTensors() : std::vector<std::string>{};
        }

        int64_t getMetaInt(const std::string& key, int64_t def = 0) const {
            return loader ? loader->getMetaInt(key, def) : def;
        }

        double getMetaFloat(const std::string& key, double def = 0.0) const {
            return loader ? loader->getMetaFloat(key, def) : def;
        }

        std::string getMetaString(const std::string& key, const std::string& def = {}) const {
            return loader ? loader->getMetaString(key, def) : def;
        }

        size_t tensorCount() const {
            return loader ? loader->tensorCount() : 0;
        }

        uint64_t mappedBytes() const {
            return loader ? loader->mappedBytes() : 0;
        }

        // Minimal inference state
        bool inferenceReady = false;

        // ModelGenie runtime model handle. Owned by the DLL; one per loaded
        // model. The DLL never touches IRExecutor directly - every token comes
        // from the runtime's certified IR dispatch table.
        mg_model_t* mgModel = nullptr;
    };

    // Real inference context using the ModelGenie runtime
    struct ContextImpl {
        ModelImpl* model = nullptr;
        RawrXDInferenceParams params{};
        bool active = false;

        // Inference state
        std::vector<int> promptTokens;
        size_t currentPosition = 0;

        // ModelGenie runtime context. One runtime context per
        // inference context so the KV cache and decode
        // position are unambiguously owned.
        mg_context_t* mgContext = nullptr;

        // Sampler parameters cache
        float samplerParams[6] = {0.7f, 0.9f, 40.0f, 1.1f, 64.0f, 0.0f}; // temp, top_p, top_k, repeat_penalty, repeat_last_n, seed
    };
}

// C API implementations
extern "C" {

const char* RawrXDCore_GetVersion(void) {
    return "14.7.3";
}

int RawrXDCore_GetVersionMajor(void) {
    return 14;
}

int RawrXDCore_GetVersionMinor(void) {
    return 7;
}

int RawrXDCore_GetVersionPatch(void) {
    return 3;
}

bool RawrXDCore_Initialize(void) {
    auto& state = getState();
    if (state.initialized) {
        setLastError(RAWXD_ERROR_ALREADY_INITIALIZED);
        return false;
    }
    state.initialized = true;
    logMessage(RAWXD_LOG_INFO, "RawrXDCore initialized");
    return true;
}

void RawrXDCore_Shutdown(void) {
    auto& state = getState();
    if (!state.initialized) return;

    // Note: Models and contexts are managed by caller via handles
    state.initialized = false;
    logMessage(RAWXD_LOG_INFO, "RawrXDCore shutdown");
}

bool RawrXDCore_IsInitialized(void) {
    return getState().initialized;
}

void RawrXDCore_SetLogCallback(RawrXDLogCallback callback, void* userData) {
    auto& state = getState();
    state.logCallback = callback;
    state.logUserData = userData;
}

void RawrXDCore_SetLogLevel(RawrXDLogLevel level) {
    getState().logLevel = level;
}

void RawrXDCore_GetDefaultConfig(RawrXDConfig* config) {
    if (!config) return;
    config->enableVulkan = true;
    config->enableMASM = true;
    config->enableTelemetry = false;
    config->workerThreadCount = 4;
    config->maxMemoryMB = 4096;
    config->modelCachePath = nullptr;
    config->logFilePath = nullptr;
}

bool RawrXDCore_Configure(const RawrXDConfig* config) {
    if (!config) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return false;
    }
    auto& state = getState();
    state.config = *config;
    logMessage(RAWXD_LOG_INFO, "RawrXDCore configured");
    return true;
}

RawrXDModel* RawrXDCore_LoadModel(const char* path) {
    if (!path || !path[0]) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return nullptr;
    }

    auto& state = getState();
    if (!state.initialized) {
        setLastError(RAWXD_ERROR_NOT_INITIALIZED);
        return nullptr;
    }

    ModelImpl impl;
    impl.path = path;

    // Load using Deep2 GGUFLoader
    try {
        impl.loader = std::make_shared<::Deep2::GGUFLoader>();
        if (!impl.loader->load(path)) {
            setLastError(RAWXD_ERROR_MODEL_NOT_FOUND);
            logMessage(RAWXD_LOG_ERROR, "Failed to open model: %s", path);
            return nullptr;
        }

        // Extract model metadata
        impl.name = impl.loader->getMetaString("general.name", "unknown");
        impl.arch = impl.loader->getMetaString("general.architecture", "unknown");
        // general.file_size is optional; when a GGUF omits it, report the
        // bytes the loader actually mapped instead of 0. mappedBytes() is the
        // sum of the mapped shard sizes, so a single-file model is its size.
        uint64_t fileSize = static_cast<uint64_t>(
            impl.loader->getMetaInt("general.file_size", 0));
        if (fileSize == 0) {
            fileSize = impl.loader->mappedBytes();
        }
        impl.size = static_cast<size_t>(fileSize);
        // Block count is written per architecture: deepseek2 models carry
        // deepseek2.block_count and only some writers mirror it to
        // llama.block_count. Resolve the arch key first, then fall back.
        int64_t blockCount = impl.loader->getMetaInt(impl.arch + ".block_count", 0);
        if (blockCount == 0) {
            blockCount = impl.loader->getMetaInt("llama.block_count", 0);
        }
        impl.layers = static_cast<int>(blockCount);
        impl.loaded = true;

        // Bind the certified ModelGenie IR executor to this model. This is
        // the only inference path in the DLL; there is no prompt-echo
        // fallback. mg_model_load verifies the IR ROM table resolves
        // against the GGUF before handing the handle back, so a model
        // the runtime accepts is a model the executor can execute.
        mg_model_config_t mgCfg{};
        mgCfg.max_seq_len = 1024;
        mgCfg.use_kv_cache = true;
        if (mg_model_load(path, &mgCfg, &impl.mgModel) != MG_SUCCESS ||
            !impl.mgModel) {
            impl.mgModel = nullptr;
            impl.inferenceReady = false;
            setLastError(RAWXD_ERROR_MODEL_CORRUPT);
            logMessage(RAWXD_LOG_ERROR,
                       "ModelGenie runtime rejected model (IR ROM table mismatch): %s",
                       path);
            return nullptr;
        }
        impl.inferenceReady = true;

        // Store in global map - use integer handle
        uintptr_t handle = reinterpret_cast<uintptr_t>(new ModelImpl(std::move(impl)));

        logMessage(RAWXD_LOG_INFO, "Model loaded: %s (layers=%d, size=%zu, engine=ModelGenie IR)", path, reinterpret_cast<ModelImpl*>(handle)->layers, reinterpret_cast<ModelImpl*>(handle)->size);
        return reinterpret_cast<RawrXDModel*>(handle);
    } catch (const std::exception& e) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR, "Exception loading model: %s", e.what());
        return nullptr;
    } catch (...) {
        setLastError(RAWXD_ERROR_INTERNAL);
        return nullptr;
    }
}

void RawrXDCore_UnloadModel(RawrXDModel* model) {
    if (!model) return;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(model);
    if (impl->mgModel) {
        mg_model_free(impl->mgModel);
        impl->mgModel = nullptr;
    }
    if (impl->loader) {
        impl->loader.reset();
    }
    delete impl;
}

const char* RawrXDCore_GetModelName(const RawrXDModel* model) {
    if (!model) return "";
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    static thread_local std::string name;
    name = impl->name;
    return name.c_str();
}

size_t RawrXDCore_GetModelSize(const RawrXDModel* model) {
    if (!model) return 0;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    return impl->size;
}

int RawrXDCore_GetModelLayerCount(const RawrXDModel* model) {
    if (!model) return 0;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    return impl->layers;
}

size_t RawrXDCore_GetModelTensorCount(const RawrXDModel* model) {
    if (!model) return 0;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    if (impl && impl->loader) {
        return impl->tensorCount();
    }
    return 0;
}

uint64_t RawrXDCore_GetModelMappedBytes(const RawrXDModel* model) {
    if (!model) return 0;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    if (impl && impl->loader) {
        return impl->mappedBytes();
    }
    return 0;
}

int64_t RawrXDCore_GetModelMetaInt(const RawrXDModel* model, const char* key, int64_t def) {
    if (!model || !key) return def;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    if (impl && impl->loader) {
        return impl->getMetaInt(key, def);
    }
    return def;
}

double RawrXDCore_GetModelMetaFloat(const RawrXDModel* model, const char* key, double def) {
    if (!model || !key) return def;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    if (impl && impl->loader) {
        return impl->getMetaFloat(key, def);
    }
    return def;
}

const char* RawrXDCore_GetModelMetaString(const RawrXDModel* model, const char* key) {
    if (!model || !key) return "";
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    if (impl && impl->loader) {
        static thread_local std::string str;
        str = impl->getMetaString(key, "");
        return str.c_str();
    }
    return "";
}

size_t RawrXDCore_ListModelTensors(const RawrXDModel* model, char*** outNames) {
    if (!model || !outNames) return 0;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    if (impl && impl->loader) {
        auto tensors = impl->listTensors();
        *outNames = static_cast<char**>(malloc(tensors.size() * sizeof(char*)));
        for (size_t i = 0; i < tensors.size(); ++i) {
            (*outNames)[i] = _strdup(tensors[i].c_str());
        }
        return tensors.size();
    }
    return 0;
}

void RawrXDCore_FreeTensorList(char** names, size_t count) {
    if (!names) return;
    for (size_t i = 0; i < count; ++i) {
        free(names[i]);
    }
    free(names);
}

RawrXDInferenceContext* RawrXDCore_CreateContext(RawrXDModel* model) {
    if (!model) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return nullptr;
    }

    auto& state = getState();
    if (!state.initialized) {
        setLastError(RAWXD_ERROR_NOT_INITIALIZED);
        return nullptr;
    }

    ModelImpl* modelImpl = reinterpret_cast<ModelImpl*>(model);
    if (!modelImpl || !modelImpl->loaded) {
        setLastError(RAWXD_ERROR_MODEL_NOT_FOUND);
        return nullptr;
    }

    // Create context with direct pointer
    ContextImpl* ctxImpl = new ContextImpl();
    ctxImpl->model = modelImpl;

    // Bind a ModelGenie runtime context. One runtime context
    // per inference context so the KV cache and decode
    // position are unambiguously owned.
    if (!modelImpl->mgModel ||
        mg_context_create(modelImpl->mgModel, &ctxImpl->mgContext) != MG_SUCCESS ||
        !ctxImpl->mgContext) {
        delete ctxImpl;
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR, "Failed to create ModelGenie runtime context");
        return nullptr;
    }

    // Return as opaque handle
    uintptr_t handle = reinterpret_cast<uintptr_t>(ctxImpl);

    logMessage(RAWXD_LOG_INFO, "Context created for model (ModelGenie runtime=ready)");
    return reinterpret_cast<RawrXDInferenceContext*>(handle);
}

void RawrXDCore_DestroyContext(RawrXDInferenceContext* ctx) {
    if (!ctx) return;
    ContextImpl* impl = reinterpret_cast<ContextImpl*>(ctx);
    if (impl->mgContext) {
        mg_context_free(impl->mgContext);
        impl->mgContext = nullptr;
    }
    delete impl;
}

void RawrXDCore_GetDefaultInferenceParams(RawrXDInferenceParams* params) {
    if (!params) return;
    params->maxTokens = 100;
    params->temperature = 0.7f;
    params->topP = 0.9f;
    params->topK = 40;
    params->repeatPenalty = 1.1f;
    params->seed = 0;
    params->useGPU = false;
    params->gpuDeviceId = 0;
}

int RawrXDCore_RunInference(
    RawrXDInferenceContext* ctx,
    const char* prompt,
    const RawrXDInferenceParams* params,
    RawrXDTokenCallback callback,
    void* userData
) {
    if (!ctx || !prompt || !callback) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return 0;
    }

    ContextImpl* impl = reinterpret_cast<ContextImpl*>(ctx);
    if (!impl->model || !impl->model->loaded || !impl->model->inferenceReady) {
        setLastError(RAWXD_ERROR_MODEL_NOT_FOUND);
        return 0;
    }

    // ModelGenie runtime must be available - no fallback to
    // prompt-echo
    if (!impl->mgContext || !impl->model->mgModel) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR, "ModelGenie runtime unavailable; refusing to echo prompt");
        return 0;
    }

    RawrXDInferenceParams p = params ? *params : RawrXDInferenceParams{};
    if (p.maxTokens <= 0) p.maxTokens = 100;
    if (p.temperature < 0) p.temperature = 0.7f;
    if (p.topP <= 0) p.topP = 0.9f;
    if (p.topK <= 0) p.topK = 40;
    if (p.repeatPenalty <= 0) p.repeatPenalty = 1.1f;

    impl->params = p;

    // Native prompt construction (RAWRXD_MODELGENIE_NATIVE_CHAT_001):
    // 1. Apply the model's native chat template (GGUF
    //    tokenizer.chat_template) for a single user turn
    //    with the assistant generation prefix.
    // 2. Tokenize with the runtime's native tokenizer
    //    (mg_model_tokenize - GGUFEmbeddedTokenizer
    //    SentencePiece longest-match, the same
    //    implementation the standalone runtime uses).
    const uint32_t bosId = mg_model_bos_token_id(impl->model->mgModel);
    const uint32_t eosId = mg_model_eos_token_id(impl->model->mgModel);
    char bosText[256] = {};
    char eosText[256] = {};
    mg_model_token_text(impl->model->mgModel, bosId, bosText, sizeof(bosText));
    mg_model_token_text(impl->model->mgModel, eosId, eosText, sizeof(eosText));

    const std::string chatTemplate =
        impl->model->getMetaString("tokenizer.chat_template", "");
    std::string rendered;
    bool templated = false;
    if (!chatTemplate.empty()) {
        RawrXD::ChatTemplateVars tmplVars;
        tmplVars.bosToken = bosText;
        tmplVars.eosToken = eosText;
        tmplVars.addGenerationPrompt = true;
        tmplVars.messages.push_back({"user", prompt});
        templated = RawrXD::RenderChatTemplate(chatTemplate, tmplVars, rendered);
        if (!templated) {
            logMessage(RAWXD_LOG_WARN,
                       "Chat template uses unsupported constructs; "
                       "falling back to raw prompt");
        }
    }

    // Tokenize. The template renders {{ bos_token }} as the
    // BOS token's string form; emit the BOS id directly so
    // the first token never depends on atomic special-token
    // matching. mg_model_tokenize reports the required
    // capacity when the output buffer is too small.
    std::vector<uint32_t> promptTokens;
    const char* encodeText = prompt;
    bool prependBos = true;
    if (templated) {
        encodeText = rendered.c_str();
        const size_t bosLen = std::char_traits<char>::length(bosText);
        if (bosId != 0 && bosLen > 0 &&
            rendered.size() >= bosLen &&
            rendered.compare(0, bosLen, bosText) == 0) {
            promptTokens.push_back(bosId);
            encodeText = rendered.c_str() + bosLen;
            prependBos = false;
        }
    }

    size_t tokenCount = 0;
    const mg_error_t capRc = mg_model_tokenize(
        impl->model->mgModel, encodeText, nullptr, &tokenCount);
    if (capRc == MG_ERROR_INVALID_STATE) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR, "Native tokenizer unavailable (model vocab not loaded)");
        return 0;
    }
    if (tokenCount == 0) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        logMessage(RAWXD_LOG_ERROR, "Prompt encoded to zero tokens: %s", prompt);
        return 0;
    }

    if (prependBos && bosId != 0) promptTokens.push_back(bosId);
    const size_t baseCount = promptTokens.size();
    promptTokens.resize(baseCount + tokenCount);
    size_t fillCount = tokenCount;
    if (mg_model_tokenize(impl->model->mgModel, encodeText,
                              promptTokens.data() + baseCount,
                              &fillCount) != MG_SUCCESS ||
        fillCount != tokenCount) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR, "Native tokenizer capacity mismatch");
        return 0;
    }

    impl->promptTokens.assign(promptTokens.begin(), promptTokens.end());
    impl->currentPosition = 0;

    // Reset the runtime context (executor position + KV
    // cache) so this prompt starts from a clean slate.
    mg_context_reset(impl->mgContext);

    // Generation configuration
    mg_generation_config_t mgGenCfg{};
    mgGenCfg.max_tokens = static_cast<size_t>(p.maxTokens);
    mgGenCfg.temperature = p.temperature;
    mgGenCfg.top_p = p.topP;
    mgGenCfg.top_k = p.topK;
    mgGenCfg.repeat_penalty = p.repeatPenalty;
    mgGenCfg.seed = static_cast<uint64_t>(p.seed);

    // Generate. The runtime prefills the prompt, decodes
    // greedily, and streams tokens through the callback;
    // EOS terminates the stream and a false return from
    // the user callback cancels it. Both terminations are
    // reported as MG_ERROR_CANCELLED by the runtime because
    // the callback bridge refuses the terminating token; a
    // cancellation is a normal end of stream, not a failure.
    TokenCallbackBridge bridge{callback, userData, eosId};
    const mg_error_t genRc = mg_context_generate(
        impl->mgContext, promptTokens.data(), promptTokens.size(),
        &mgGenCfg, &TokenCallbackBridge::Invoke, &bridge);

    if (genRc != MG_SUCCESS && genRc != MG_ERROR_CANCELLED) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR, "ModelGenie generation failed (mg_error_t=%d)",
                   static_cast<int>(genRc));
        return bridge.delivered;
    }
    if (mg_context_last_generate_status(impl->mgContext) ==
            MG_GENERATE_EXECUTION_FAILED) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR,
                   "ModelGenie generation failed at IR op %u",
                   mg_context_last_failed_op(impl->mgContext));
        return bridge.delivered;
    }

    // Verify IR dispatch completeness (the runtime's
    // certified 300-operation dispatch table must be fully
    // exercised on every step)
    const uint32_t dispatched = mg_context_ops_dispatched(impl->mgContext);
    const uint32_t skipped = mg_context_ops_skipped(impl->mgContext);
    const uint32_t visited = mg_context_ops_visited(impl->mgContext);
    if (visited != kExpectedIrOpCount || skipped != 0) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR,
                   "ModelGenie IR dispatch degraded: visited=%u dispatched=%u skipped=%u (expected %u/0)",
                   visited, dispatched, skipped, kExpectedIrOpCount);
        return 0;
    }

    impl->currentPosition = mg_context_position(impl->mgContext);

    return bridge.delivered;
}

size_t RawrXDCore_Tokenize(
    const RawrXDModel* model,
    const char* text,
    int* outTokens,
    size_t maxTokens
) {
    if (!model || !text) return 0;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    if (!impl->loaded || !impl->mgModel) return 0;

    // Encode with the runtime's native tokenizer - the
    // same GGUFEmbeddedTokenizer the standalone runtime
    // uses. No BOS is prepended and no chat template is
    // applied; the text is encoded exactly as given.
    size_t tokenCount = 0;
    const mg_error_t capRc = mg_model_tokenize(
        impl->mgModel, text, nullptr, &tokenCount);
    if ((capRc != MG_SUCCESS && capRc != MG_ERROR_INVALID_ARGUMENT) ||
        tokenCount == 0) {
        return 0;
    }

    if (!outTokens || maxTokens == 0) return tokenCount;

    std::vector<uint32_t> ids(tokenCount);
    size_t fillCount = tokenCount;
    if (mg_model_tokenize(impl->mgModel, text, ids.data(),
                              &fillCount) != MG_SUCCESS ||
        fillCount != tokenCount) {
        return 0;
    }

    const size_t n = ids.size() < maxTokens ? ids.size() : maxTokens;
    for (size_t i = 0; i < n; ++i) {
        outTokens[i] = static_cast<int>(ids[i]);
    }
    return ids.size();
}

size_t RawrXDCore_Detokenize(
    const RawrXDModel* model,
    const int* tokenIds,
    size_t count,
    char* outText,
    size_t* outSize
) {
    if (!model || !outSize) {
        if (outSize) *outSize = 0;
        return 0;
    }
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    if (!impl || !impl->loaded || !impl->mgModel) {
        *outSize = 0;
        return 0;
    }

    // ids come from the runtime as ints; remap to the runtime's
    // uint32 domain first.
    std::vector<uint32_t> ids;
    ids.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        ids.push_back(static_cast<uint32_t>(tokenIds[i]));
    }

    size_t required = 0;
    mg_model_detokenize(impl->mgModel, ids.data(), ids.size(),
                        nullptr, &required);
    if (required == 0) {
        *outSize = 0;
        return 0;
    }

    if (!outText || *outSize < required) {
        *outSize = required;
        return 0;
    }

    size_t cap = required;
    const size_t written = mg_model_detokenize(
        impl->mgModel, ids.data(), ids.size(), outText, &cap);
    *outSize = required;
    return written;
}

void RawrXDCore_GetMemoryStats(RawrXDMemoryStats* stats) {
    if (!stats) return;
    stats->totalAllocated = 0;
    stats->totalReserved = 0;
    stats->gpuAllocated = 0;
    stats->gpuReserved = 0;
    stats->peakUsage = 0;
    // Memory stats would require tracking active contexts
}

void RawrXDCore_TrimMemory(void) {
    // Runtime-owned caches are trimmed inside the ModelGenie
    // runtime; nothing DLL-side to release.
}

const char* RawrXDCore_GetErrorString(RawrXDError error) {
    switch (error) {
        case RAWXD_OK: return "Success";
        case RAWXD_ERROR_INVALID_ARGUMENT: return "Invalid argument";
        case RAWXD_ERROR_OUT_OF_MEMORY: return "Out of memory";
        case RAWXD_ERROR_MODEL_NOT_FOUND: return "Model not found";
        case RAWXD_ERROR_MODEL_CORRUPT: return "Model corrupt";
        case RAWXD_ERROR_GPU_UNAVAILABLE: return "GPU unavailable";
        case RAWXD_ERROR_VULKAN_UNSUPPORTED: return "Vulkan unsupported";
        case RAWXD_ERROR_NOT_INITIALIZED: return "Not initialized";
        case RAWXD_ERROR_ALREADY_INITIALIZED: return "Already initialized";
        case RAWXD_ERROR_INTERNAL: return "Internal error";
        default: return "Unknown error";
    }
}

RawrXDError RawrXDCore_GetLastError(void) {
    return getState().lastError;
}

void RawrXDCore_GetHardwareCaps(RawrXDHardwareCaps* caps) {
    if (!caps) return;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    caps->cpuCoreCount = sysInfo.dwNumberOfProcessors;
    caps->hasAVX2 = false; // Would need CPUID check
    caps->hasAVX512 = false;
    caps->hasVulkan = false; // Would need Vulkan check
    caps->hasCUDA = false;
    caps->systemMemoryMB = 65536; // Placeholder
    caps->gpuCount = 0;

    for (int i = 0; i < 4; ++i) {
        caps->gpuMemoryMB[i] = 0;
        caps->gpuNames[i][0] = '\0';
    }
}

} // extern "C"
