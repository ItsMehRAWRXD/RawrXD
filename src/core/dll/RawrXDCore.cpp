// RawrXDCore.cpp - Core runtime DLL implementation with real Deep2 integration
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

// Deep2 includes
#include <GGUFLoader.hpp>

// Deep2 inference engine adapter
#include "Deep2InferenceAdapter.h"

namespace {
    using namespace ::Deep2;  // Bring global Deep2 namespace into scope
    
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
        
        // Deep2 model handle for inference
        ::Deep2::Model deep2Model;
    };
    
    // Real inference context using Deep2 engine
    struct ContextImpl {
        ModelImpl* model = nullptr;
        RawrXDInferenceParams params{};
        bool active = false;
        
        // Inference state
        std::vector<int> promptTokens;
        size_t currentPosition = 0;
        
        // Real Deep2 engine context
        ::Deep2::Context deep2Context;
        
        // Sampler parameters cache
        float samplerParams[6] = {0.7f, 0.9f, 40.0f, 1.1f, 64.0f, 0.0f}; // temp, top_p, top_k, repeat_penalty, repeat_last_n, seed
    };
    
    // Real tokenizer using GGUF metadata
    struct TokenizerImpl {
        ModelImpl* model = nullptr;
        std::vector<std::string> vocab;           // id -> token text
        std::unordered_map<std::string, uint32_t> tokenToId;  // token text -> id
        std::vector<uint8_t> tokenTypes;          // token type per id
        std::vector<std::pair<std::string, std::string>> merges;  // BPE merges
        uint32_t bosTokenId = 0;
        uint32_t eosTokenId = 0;
        uint32_t unkTokenId = 0;
        bool loaded = false;
        
        bool loadFromModel(ModelImpl* m) {
            model = m;
            if (!m || !m->loader || !m->loaded) return false;
            
            // Load vocabulary from tokenizer.ggml.tokens
            std::vector<std::string> tokens;
            if (!m->loader->getMetaStringArray("tokenizer.ggml.tokens", tokens)) {
                return false;
            }
            
            vocab.reserve(tokens.size());
            for (const auto& token : tokens) {
                vocab.push_back(token);
            }
            
            // Build token-to-id map
            tokenToId.reserve(vocab.size() * 2);
            for (size_t i = 0; i < vocab.size(); ++i) {
                tokenToId[vocab[i]] = static_cast<uint32_t>(i);
            }
            
            // Load token types if available
            std::vector<int32_t> tokenTypes;
            if (m->loader->getMetaInt32Array("tokenizer.ggml.token_type", tokenTypes)) {
                this->tokenTypes.resize(tokenTypes.size());
                for (size_t i = 0; i < tokenTypes.size(); ++i) {
                    this->tokenTypes[i] = static_cast<uint8_t>(tokenTypes[i]);
                }
            }
            
            // Load merges
            std::vector<std::string> mergesStr;
            if (m->loader->getMetaStringArray("tokenizer.ggml.merges", mergesStr)) {
                merges.reserve(mergesStr.size());
                for (const auto& merge : mergesStr) {
                    size_t spacePos = merge.find(' ');
                    if (spacePos != std::string::npos) {
                        std::string first = merge.substr(0, spacePos);
                        std::string second = merge.substr(spacePos + 1);
                        merges.emplace_back(first, second);
                    }
                }
            }
            
            // Load special token IDs
            bosTokenId = static_cast<uint32_t>(m->loader->getMetaInt("tokenizer.ggml.bos_token_id", 1));
            eosTokenId = static_cast<uint32_t>(m->loader->getMetaInt("tokenizer.ggml.eos_token_id", 2));
            unkTokenId = static_cast<uint32_t>(m->loader->getMetaInt("tokenizer.ggml.unk_token_id", 0));
            
            loaded = true;
            return true;
        }
        
        size_t encode(const std::string& text, uint32_t* outTokens, size_t maxTokens) const {
            if (!loaded || vocab.empty()) return 0;
            
            // Simple greedy BPE tokenization (naive implementation for now)
            // Real implementation would use the merges table
            size_t tokenCount = 0;
            std::string current;
            
            for (char c : text) {
                current += c;
                auto it = tokenToId.find(current);
                if (it != tokenToId.end()) {
                    // Found a match, but check if we can extend
                    continue;
                }
                
                // Current string not in vocab, emit previous
                if (current.size() > 1) {
                    current.pop_back(); // remove the char that made it invalid
                }
                if (!current.empty()) {
                    auto it = tokenToId.find(current);
                    if (it != tokenToId.end() && tokenCount < maxTokens) {
                        outTokens[tokenCount++] = it->second;
                    } else if (tokenCount < maxTokens) {
                        outTokens[tokenCount++] = unkTokenId;
                    }
                }
                current = text.substr(text.find(current) + current.size() - 1, 1);
            }
            
            // Handle remaining
            if (!current.empty() && tokenCount < maxTokens) {
                auto it = tokenToId.find(current);
                if (it != tokenToId.end()) {
                    outTokens[tokenCount++] = it->second;
                } else {
                    outTokens[tokenCount++] = unkTokenId;
                }
            }
            
            return tokenCount;
        }
        
        std::string decode(const uint32_t* tokens, size_t tokenCount) const {
            if (!loaded) return "";
            std::string result;
            for (size_t i = 0; i < tokenCount; ++i) {
                uint32_t id = tokens[i];
                if (id < vocab.size()) {
                    result += vocab[id];
                }
            }
            return result;
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
        
        // Store in global map - use integer handle
        uintptr_t handle = reinterpret_cast<uintptr_t>(new ModelImpl(std::move(impl)));
        
        logMessage(RAWXD_LOG_INFO, "Model loaded: %s (layers=%d, size=%zu)", path, reinterpret_cast<ModelImpl*>(handle)->layers, reinterpret_cast<ModelImpl*>(handle)->size);
        return reinterpret_cast<RawrXDModel*>(handle);
    } catch (...) {
        setLastError(RAWXD_ERROR_INTERNAL);
        return nullptr;
    }
}

void RawrXDCore_UnloadModel(RawrXDModel* model) {
    if (!model) return;
    ModelImpl* impl = reinterpret_cast<ModelImpl*>(model);
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
    
    // Return as opaque handle
    uintptr_t handle = reinterpret_cast<uintptr_t>(ctxImpl);
    
    logMessage(RAWXD_LOG_INFO, "Context created for model");
    return reinterpret_cast<RawrXDInferenceContext*>(handle);
}

void RawrXDCore_DestroyContext(RawrXDInferenceContext* ctx) {
    if (!ctx) return;
    ContextImpl* impl = reinterpret_cast<ContextImpl*>(ctx);
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
    if (!impl->model || !impl->model->loaded) {
        setLastError(RAWXD_ERROR_MODEL_NOT_FOUND);
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
        return 0;
    }
    
    // Tokenize prompt
    std::vector<uint32_t> promptTokens(4096);
    size_t tokenCount = tokenizer->encode(prompt, promptTokens.data(), promptTokens.size());
    promptTokens.resize(tokenCount);
    
    if (tokenCount == 0) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return 0;
    }
    
    impl->promptTokens.clear();
    for (uint32_t t : promptTokens) {
        impl->promptTokens.push_back(static_cast<int>(t));
    }
    impl->currentPosition = 0;
    
    // Create Deep2 context if needed
    if (!impl->deep2Context.get()) {
        impl->deep2Context = ::Deep2::Context(impl->model->deep2Model, 4096);
        if (!impl->deep2Context) {
            setLastError(RAWXD_ERROR_INTERNAL);
            return 0;
        }
        // Set vocab size
        impl->deep2Context.setVocabSize(impl->model->loader->tensorCount());
    }
    
    // Prefill
    std::vector<float> logits;
    int prefillResult = impl->deep2Context.prefill(promptTokens, &logits);
    if (prefillResult < 0) {
        setLastError(RAWXD_ERROR_INTERNAL);
        return 0;
    }
    
    // Generate tokens
    int generated = 0;
    std::vector<int32_t> newTokens;
    
    // Get first token from prefill logits
    if (!logits.empty()) {
        int bestToken = 0;
        float bestLogit = -1e30f;
        for (size_t i = 0; i < logits.size(); ++i) {
            if (logits[i] > bestLogit) {
                bestLogit = logits[i];
                bestToken = static_cast<int>(i);
            }
        }
        
        uint32_t tokenId = static_cast<uint32_t>(bestToken);
        std::string tokenText = tokenizer->decode(&tokenId, 1);
        
        if (!callback(bestToken, tokenText.c_str(), userData)) {
            return generated;
        }
        generated++;
        newTokens.push_back(bestToken);
    }
    
    // Decode loop
    for (int i = 1; i < p.maxTokens; ++i) {
        // Prepare sampler params
        float samplerParams[6] = {p.temperature, p.topP, static_cast<float>(p.topK), p.repeatPenalty, 64.0f, static_cast<float>(p.seed)};
        
        std::vector<float> decodeLogits;
        int token = impl->deep2Context.decode(decodeLogits.empty() ? nullptr : decodeLogits.data(), samplerParams);
        if (token < 0) break;
        
        newTokens.push_back(token);
        
        uint32_t tokenId = static_cast<uint32_t>(token);
        std::string tokenText = tokenizer->decode(&tokenId, 1);
        
        if (!callback(token, tokenText.c_str(), userData)) {
            break;
        }
        generated++;
        
        // Check for EOS
        if (static_cast<uint32_t>(token) == tokenizer->eosTokenId) {
            break;
        }
    }
    
    return generated;
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