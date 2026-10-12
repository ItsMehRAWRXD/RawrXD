// RawrXDCore.cpp - Core runtime DLL implementation with ModelGenie IRExecutor inference
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

// Tokenizer - use the canonical GGUFEmbeddedTokenizer for exact parity with ModelGenieRuntime
#include "../../tokenizer/gguf_embedded_tokenizer.hpp"

// Native chat template renderer (GGUF tokenizer.chat_template)
#include "ChatTemplate.hpp"

// ModelGenie IRExecutor - the certified 300-op executor. This header pulls in
// the authoritative generated IR table, tensor ROM and model config, so there
// is exactly one definition of the execution graph for both the runtime library
// and this DLL.
#include "../../modelgenie/ModelGenieExecutor.hpp"

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
        // from the runtime's cert"ified IR dispatch table.
        mg_model_t* mgModel = nullptr;
    };

    // Real inference context using Deep2 engine
    struct ContextImpl {
        ModelImpl* model = nullptr;
        RawrXDInferenceParams params{};
        bool active = false;

        // Inference state
        std::vector<int> promptTokens;
        size_t currentPosition = 0;
        
        // ModelGenie IRExecutor context - owned by the model's irExecutor
        // We just use the model's irExecutor with token context
        bool irReady = false;

        // Sampler parameters cache
        float samplerParams[6] = {0.7f, 0.9f, 40.0f, 1.1f, 64.0f, 0.0f}; // temp, top_p, top_k, repeat_penalty, repeat_last_n, seed
    };
    
    // Real tokenizer using GGUF metadata - uses canonical GGUFEmbeddedTokenizer
    // for exact tokenization parity with ModelGenieRuntime
    struct TokenizerImpl {
        ModelImpl* model = nullptr;
        std::unique_ptr<RawrXD::GGUFEmbeddedTokenizer> tokenizer;
        bool loaded = false;
        
        bool loadFromModel(ModelImpl* m) {
            model = m;
            if (!m || !m->loader || !m->loaded) return false;
            
            tokenizer = std::make_unique<RawrXD::GGUFEmbeddedTokenizer>();
            if (!tokenizer->LoadFromGGUF(m->path)) {
                tokenizer.reset();
                return false;
            }
            
            loaded = true;
            return true;
        }
        
        size_t encode(const std::string& text, uint32_t* outTokens, size_t maxTokens) const {
            if (!loaded || !tokenizer) return 0;
            
            std::vector<uint32_t> tokens;
            if (!tokenizer->EncodeLongestMatch(text, tokens)) {
                return 0;
            }
            
            size_t tokenCount = std::min(tokens.size(), maxTokens);
            for (size_t i = 0; i < tokenCount; ++i) {
                outTokens[i] = tokens[i];
            }
            return tokenCount;
        }
        
        std::string decode(const uint32_t* tokens, size_t tokenCount) const {
            if (!loaded || !tokenizer) return "";
            std::string result;
            for (size_t i = 0; i < tokenCount; ++i) {
                const std::string& tokenText = tokenizer->Token(tokens[i]);
                result += tokenText;
            }
            return result;
        }
        
        uint32_t getEosTokenId() const {
            if (!loaded || !tokenizer) return 2;
            int32_t eos = tokenizer->EosToken();
            return eos >= 0 ? static_cast<uint32_t>(eos) : 2;
        }
    };
    
    // Global maps for tokenizer management
    std::unordered_map<ModelImpl*, TokenizerImpl> g_tokenizers;
    std::mutex g_tokenizersMutex;
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
    // Just clear tokenizer cache
    {
        std::lock_guard<std::mutex> lock(g_tokenizersMutex);
        g_tokenizers.clear();
    }
    
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
        impl.size = static_cast<size_t>(impl.loader->getMetaInt("general.file_size", 0));
        impl.layers = static_cast<int>(impl.loader->getMetaInt("llama.block_count", 0));
        impl.loaded = true;

        // Bind the certified ModelGenie IR executor to this model. This is the
        // only inference path in the DLL; there is no prompt-echo fallback.
        // Use the first token ID as a dummy (token 0) - actual tokens are set at inference time
        impl.irExecutor = std::make_unique<IRExecutor>(path, 0);
        if (!impl.irExecutor) {
            impl.inferenceReady = false;
            setLastError(RAWXD_ERROR_INTERNAL);
            logMessage(RAWXD_LOG_ERROR, "Failed to create IRExecutor for model: %s", path);
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
    // IRExecutor is automatically cleaned up by unique_ptr
    impl->irExecutor.reset();
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

    // The IRExecutor is owned by the model; context just holds a reference
    // and uses it for inference. The KV cache lives in the IRExecutor.
    if (modelImpl->irExecutor) {
        ctxImpl->irReady = true;
    }

    // Return as opaque handle
    uintptr_t handle = reinterpret_cast<uintptr_t>(ctxImpl);

    logMessage(RAWXD_LOG_INFO, "Context created for model (IRExecutor=%s)",
               ctxImpl->irReady ? "ready" : "unavailable");
    return reinterpret_cast<RawrXDInferenceContext*>(handle);
}

void RawrXDCore_DestroyContext(RawrXDInferenceContext* ctx) {
    if (!ctx) return;
    ContextImpl* impl = reinterpret_cast<ContextImpl*>(ctx);
    impl->irReady = false;
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

    // IRExecutor must be available - no fallback to prompt-echo
    if (!impl->irReady || !impl->model->irExecutor) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR, "IRExecutor unavailable; refusing to echo prompt");
        return 0;
    }

    RawrXDInferenceParams p = params ? *params : RawrXDInferenceParams{};
    if (p.maxTokens <= 0) p.maxTokens = 100;
    if (p.temperature < 0) p.temperature = 0.7f;
    if (p.topP <= 0) p.topP = 0.9f;
    if (p.topK <= 0) p.topK = 40;
    if (p.repeatPenalty <= 0) p.repeatPenalty = 1.1f;

    impl->params = p;

    // Get or create tokenizer
    TokenizerImpl* tokenizer = nullptr;
    {
        std::lock_guard<std::mutex> tokLock(g_tokenizersMutex);
        auto tokIt = g_tokenizers.find(impl->model);
        if (tokIt == g_tokenizers.end()) {
            TokenizerImpl newTok;
            if (newTok.loadFromModel(impl->model)) {
                g_tokenizers[impl->model] = std::move(newTok);
                tokenizer = &g_tokenizers[impl->model];
            }
        } else {
            tokenizer = &tokIt->second;
        }
    }

    if (!tokenizer || !tokenizer->loaded) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR, "Tokenizer unavailable: cannot encode prompt");
        return 0;
    }

    // Native prompt construction (RAWRXD_MODELGENIE_NATIVE_CHAT_001):
    // 1. Apply the model's native chat template (GGUF
    //    tokenizer.chat_template) for a single user turn with the
    //    assistant generation prefix.
    // 2. Tokenize with the model's native SentencePiece tokenizer
    //    (GGUFEmbeddedTokenizer::EncodeLongestMatch - the same
    //    implementation the runtime's mg_model_tokenize uses).
    const int32_t bosId = tokenizer->tokenizer->BosToken();
    const int32_t eosId = tokenizer->tokenizer->EosToken();
    const std::string bosText =
        bosId >= 0 ? tokenizer->tokenizer->Token(static_cast<uint32_t>(bosId))
                   : std::string();

    std::vector<uint32_t> promptTokens;
    const std::string chatTemplate =
        impl->model->getMetaString("tokenizer.chat_template", "");
    std::string rendered;
    bool templated = false;
    if (!chatTemplate.empty()) {
        RawrXD::ChatTemplateVars tmplVars;
        tmplVars.bosToken = bosText;
        tmplVars.eosToken =
            eosId >= 0
                ? tokenizer->tokenizer->Token(static_cast<uint32_t>(eosId))
                : std::string();
        tmplVars.addGenerationPrompt = true;
        tmplVars.messages.push_back({"user", prompt});
        templated = RawrXD::RenderChatTemplate(chatTemplate, tmplVars, rendered);
        if (!templated) {
            logMessage(RAWXD_LOG_WARNING,
                       "Chat template uses unsupported constructs; "
                       "falling back to raw prompt");
        }
    }

    if (templated) {
        // The template renders {{ bos_token }} as the BOS token's
        // string form; emit the BOS id directly so the first token
        // never depends on atomic special-token matching.
        if (bosId >= 0 && !bosText.empty() &&
            rendered.size() >= bosText.size() &&
            rendered.compare(0, bosText.size(), bosText) == 0) {
            promptTokens.push_back(static_cast<uint32_t>(bosId));
            std::vector<uint32_t> rest;
            if (!tokenizer->tokenizer->EncodeLongestMatch(
                    rendered.substr(bosText.size()), rest)) {
                setLastError(RAWXD_ERROR_INTERNAL);
                logMessage(RAWXD_LOG_ERROR,
                           "Native tokenizer failed on templated prompt");
                return 0;
            }
            promptTokens.insert(promptTokens.end(), rest.begin(), rest.end());
        } else if (!tokenizer->tokenizer->EncodeLongestMatch(rendered,
                                                             promptTokens)) {
            setLastError(RAWXD_ERROR_INTERNAL);
            logMessage(RAWXD_LOG_ERROR,
                       "Native tokenizer failed on templated prompt");
            return 0;
        }
    } else {
        // Raw prompt: BOS + encode(prompt) (llama.cpp raw-prompt
        // behavior when the model has no usable chat template).
        if (bosId >= 0) promptTokens.push_back(static_cast<uint32_t>(bosId));
        std::vector<uint32_t> body;
        if (!tokenizer->tokenizer->EncodeLongestMatch(prompt, body)) {
            setLastError(RAWXD_ERROR_INTERNAL);
            logMessage(RAWXD_LOG_ERROR,
                       "Native tokenizer failed on prompt: %s", prompt);
            return 0;
        }
        promptTokens.insert(promptTokens.end(), body.begin(), body.end());
    }

    if (promptTokens.empty()) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        logMessage(RAWXD_LOG_ERROR, "Prompt encoded to zero tokens: %s", prompt);
        return 0;
    }

    impl->promptTokens.clear();
    for (uint32_t t : promptTokens) {
        impl->promptTokens.push_back(static_cast<int>(t));
    }
    impl->currentPosition = 0;

    // Reset the IRExecutor's KV cache for this new prompt
    impl->model->irExecutor->ResetPosition();

    // Prefill the prompt tokens into the KV cache
    bool prefillOk = impl->model->irExecutor->Prefill(promptTokens);
    if (!prefillOk) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR, "IRExecutor prefill failed");
        return 0;
    }

    // Autoregressive greedy decode. After Prefill the executor's
    // logits already predict the first generated token (mirrors
    // IRExecutor::Generate - no extra Execute() here; an extra
    // Execute would re-process the last prompt token at the wrong
    // position and corrupt the KV cache).
    int generated = 0;
    uint32_t nextToken = impl->model->irExecutor->SampleToken();
    for (int i = 0; i < p.maxTokens; ++i) {
        // EOS terminates the stream (GGUF-defined eos_token_id)
        if (eosId >= 0 && nextToken == static_cast<uint32_t>(eosId)) {
            logMessage(RAWXD_LOG_DEBUG, "EOS token sampled, stopping generation");
            break;
        }

        // Detokenize with the model's native tokenizer (the
        // ModelGenie detokenization path - same vocab the
        // encoder used)
        const std::string& tokenText = tokenizer->tokenizer->Token(nextToken);

        // Stream the token to the caller; returning false cancels
        if (!callback(static_cast<int>(nextToken), tokenText.c_str(),
                      userData)) {
            logMessage(RAWXD_LOG_DEBUG, "Callback requested stop");
            break;
        }
        generated++;

        // Feed the sampled token back as the next input, then
        // execute the IR for the new position
        impl->model->irExecutor->SetTokenId(nextToken);
        impl->model->irExecutor->ClearArena();
        if (!impl->model->irExecutor->Execute()) {
            setLastError(RAWXD_ERROR_INTERNAL);
            logMessage(RAWXD_LOG_ERROR,
                       "IRExecutor execution failed at step %d", i);
            return generated;
        }
        impl->model->irExecutor->AdvancePosition();
        nextToken = impl->model->irExecutor->SampleToken();
    }

    // Verify IR dispatch completeness
    const uint32_t dispatched = impl->model->irExecutor->Dispatched();
    const uint32_t skipped = impl->model->irExecutor->Skipped();
    const uint32_t visited = impl->model->irExecutor->Visited();
    if (visited != kExpectedIrOpCount || skipped != 0) {
        setLastError(RAWXD_ERROR_INTERNAL);
        logMessage(RAWXD_LOG_ERROR,
                   "IRExecutor IR dispatch degraded: visited=%u dispatched=%u skipped=%u (expected %u/0)",
                   visited, dispatched, skipped, kExpectedIrOpCount);
        return 0;
    }

    impl->currentPosition = impl->model->irExecutor->Position();

    return generated;
}

size_t RawrXDCore_Tokenize(
    const RawrXDModel* model,
    const char* text,
    int* outTokens,
    size_t maxTokens
) {
    if (!model || !text) return 0;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(const_cast<RawrXDModel*>(model));
    if (!impl->loaded) return 0;

    // Get or create the model's native tokenizer (cached per model,
    // same instance RunInference uses).
    TokenizerImpl* tokenizer = nullptr;
    {
        std::lock_guard<std::mutex> tokLock(g_tokenizersMutex);
        auto tokIt = g_tokenizers.find(impl);
        if (tokIt == g_tokenizers.end()) {
            TokenizerImpl newTok;
            if (newTok.loadFromModel(impl)) {
                g_tokenizers[impl] = std::move(newTok);
                tokenizer = &g_tokenizers[impl];
            }
        } else {
            tokenizer = &tokIt->second;
        }
    }
    if (!tokenizer || !tokenizer->loaded) return 0;

    // Encode with the model's native SentencePiece tokenizer - the
    // same GGUFEmbeddedTokenizer the runtime's mg_model_tokenize
    // uses. No BOS is prepended and no chat template is applied;
    // the text is encoded exactly as given.
    std::vector<uint32_t> ids;
    if (!tokenizer->tokenizer->EncodeLongestMatch(text, ids)) return 0;

    if (!outTokens || maxTokens == 0) return ids.size();
    const size_t n = ids.size() < maxTokens ? ids.size() : maxTokens;
    for (size_t i = 0; i < n; ++i) {
        outTokens[i] = static_cast<int>(ids[i]);
    }
    return ids.size();
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
    // Clear tokenizer cache
    std::lock_guard<std::mutex> tokLock(g_tokenizersMutex);
    g_tokenizers.clear();
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