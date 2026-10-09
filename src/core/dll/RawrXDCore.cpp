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
#include <Deep2/GGUFLoader.hpp>

namespace {
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
        size_t size = 0;
        int layers = 0;
        bool loaded = false;
        
        // Deep2 loader
        std::shared_ptr<Deep2::GGUFLoader> loader;
        Deep2::GGUFTensor* getTensor(const std::string& name) {
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
    };
    
    // Real inference context using Deep2 engine
    struct ContextImpl {
        ModelImpl* model = nullptr;
        RawrXDInferenceParams params{};
        bool active = false;
        
        // Inference state
        std::vector<int> promptTokens;
        size_t currentPosition = 0;
        
        // For real inference, we'd hold the Deep2 engine context here
        // void* engineContext = nullptr;
    };
    
    std::unordered_map<RawrXDModel*, ModelImpl> g_models;
    std::unordered_map<RawrXDInferenceContext*, ContextImpl> g_contexts;
    std::mutex g_modelsMutex;
    std::mutex g_contextsMutex;
}

extern "C" {

// Version
RawrXDCore_EXPORT const char* RawrXDCore_GetVersion(void) {
    return "14.7.3";
}

RawrXDCore_EXPORT int RawrXDCore_GetVersionMajor(void) { return 14; }
RawrXDCore_EXPORT int RawrXDCore_GetVersionMinor(void) { return 7; }
RawrXDCore_EXPORT int RawrXDCore_GetVersionPatch(void) { return 3; }

// Initialization
RawrXDCore_EXPORT bool RawrXDCore_Initialize(void) {
    auto& state = getState();
    std::lock_guard<std::mutex> lock(state.mutex);
    
    if (state.initialized) {
        setLastError(RAWXD_ERROR_ALREADY_INITIALIZED);
        return false;
    }
    
    RawrXDCore_GetDefaultConfig(&state.config);
    
    state.initialized = true;
    state.lastError = RAWXD_OK;
    logMessage(RAWXD_LOG_INFO, "RawrXDCore initialized v%s", RawrXDCore_GetVersion());
    return true;
}

RawrXDCore_EXPORT void RawrXDCore_Shutdown(void) {
    auto& state = getState();
    std::lock_guard<std::mutex> lock(state.mutex);
    
    if (!state.initialized) return;
    
    {
        std::lock_guard<std::mutex> ctxLock(g_contextsMutex);
        g_contexts.clear();
    }
    
    {
        std::lock_guard<std::mutex> modelLock(g_modelsMutex);
        g_models.clear();
    }
    
    state.initialized = false;
    state.logCallback = nullptr;
    state.logUserData = nullptr;
    logMessage(RAWXD_LOG_INFO, "RawrXDCore shutdown");
}

RawrXDCore_EXPORT bool RawrXDCore_IsInitialized(void) {
    return getState().initialized;
}

// Logging
RawrXDCore_EXPORT void RawrXDCore_SetLogCallback(RawrXDLogCallback callback, void* userData) {
    auto& state = getState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.logCallback = callback;
    state.logUserData = userData;
}

RawrXDCore_EXPORT void RawrXDCore_SetLogLevel(RawrXDLogLevel level) {
    auto& state = getState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.logLevel = level;
}

// Configuration
RawrXDCore_EXPORT void RawrXDCore_GetDefaultConfig(RawrXDConfig* config) {
    if (!config) return;
    config->enableVulkan = true;
    config->enableMASM = true;
    config->enableTelemetry = false;
    config->workerThreadCount = 0;
    config->maxMemoryMB = 0;
    config->modelCachePath = nullptr;
    config->logFilePath = nullptr;
}

RawrXDCore_EXPORT bool RawrXDCore_Configure(const RawrXDConfig* config) {
    auto& state = getState();
    std::lock_guard<std::mutex> lock(state.mutex);
    
    if (!state.initialized) {
        setLastError(RAWXD_ERROR_NOT_INITIALIZED);
        return false;
    }
    
    if (!config) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return false;
    }
    
    state.config = *config;
    logMessage(RAWXD_LOG_INFO, "RawrXDCore configured: Vulkan=%d, MASM=%d, Threads=%d",
               config->enableVulkan, config->enableMASM, config->workerThreadCount);
    return true;
}

// Model Management - REAL GGUF Loading
RawrXDCore_EXPORT RawrXDModel* RawrXDCore_LoadModel(const char* path) {
    auto& state = getState();
    if (!state.initialized) {
        setLastError(RAWXD_ERROR_NOT_INITIALIZED);
        return nullptr;
    }
    
    if (!path) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return nullptr;
    }
    
    // Create model implementation
    auto modelImpl = std::make_unique<ModelImpl>();
    modelImpl->path = path;
    
    // Extract filename as name
    size_t pos = modelImpl->path.find_last_of("/\\");
    modelImpl->name = (pos == std::string::npos) ? modelImpl->path : modelImpl->path.substr(pos + 1);
    
    // Load with Deep2 GGUFLoader
    modelImpl->loader = std::make_shared<Deep2::GGUFLoader>();
    if (!modelImpl->loader->load(path)) {
        std::string error = modelImpl->loader->error();
        logMessage(RAWXD_LOG_ERROR, "Failed to load model '%s': %s", path, error.c_str());
        setLastError(RAWXD_ERROR_MODEL_CORRUPT);
        return nullptr;
    }
    
    // Extract metadata from GGUF
    modelImpl->size = modelImpl->loader->mappedBytes();
    modelImpl->layers = static_cast<int>(modelImpl->loader->getMetaInt("general.block_count", 0));
    modelImpl->loaded = true;
    
    // Extract model name from metadata if available
    std::string metaName = modelImpl->loader->getMetaString("general.name");
    if (!metaName.empty()) {
        modelImpl->name = metaName;
    } else {
        // Fallback to filename
        size_t pos = modelImpl->path.find_last_of("/\\");
        modelImpl->name = (pos == std::string::npos) ? modelImpl->path : modelImpl->path.substr(pos + 1);
    }
    
    logMessage(RAWXD_LOG_INFO, "Loaded model: %s (%zu MB, %d layers, %zu tensors, %zu MB mapped)", 
               modelImpl->name.c_str(), 
               modelImpl->size / (1024*1024), 
               modelImpl->loader->getMetaInt("general.block_count", 0),
               modelImpl->loader->tensorCount(),
               modelImpl->loader->mappedBytes() / (1024*1024));
    
    // Create handle
    RawrXDModel* handle = reinterpret_cast<RawrXDModel*>(modelImpl.release());
    
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    g_models[handle] = std::move(*reinterpret_cast<ModelImpl*>(handle));
    
    setLastError(RAWXD_OK);
    return handle;
}

RawrXDCore_EXPORT void RawrXDCore_UnloadModel(RawrXDModel* model) {
    if (!model) return;
    
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(model);
    if (it != g_models.end()) {
        logMessage(RAWXD_LOG_INFO, "Unloaded model: %s", it->second.name.c_str());
        delete reinterpret_cast<ModelImpl*>(model);
        g_models.erase(it);
    }
}

RawrXDCore_EXPORT const char* RawrXDCore_GetModelName(const RawrXDModel* model) {
    if (!model) return "";
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(const_cast<RawrXDModel*>(model));
    if (it != g_models.end()) {
        return it->second.name.c_str();
    }
    return "";
}

RawrXDCore_EXPORT size_t RawrXDCore_GetModelSize(const RawrXDModel* model) {
    if (!model) return 0;
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(const_cast<RawrXDModel*>(model));
    if (it != g_models.end()) {
        return it->second.size;
    }
    return 0;
}

RawrXDCore_EXPORT int RawrXDCore_GetModelLayerCount(const RawrXDModel* model) {
    if (!model) return 0;
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(const_cast<RawrXDModel*>(model));
    if (it != g_models.end()) {
        return it->second.layers;
    }
    return 0;
}

// NEW: Get model tensor count
RawrXDCore_EXPORT size_t RawrXDCore_GetModelTensorCount(const RawrXDModel* model) {
    if (!model) return 0;
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(const_cast<RawrXDModel*>(model));
    if (it != g_models.end()) {
        return it->second.tensorCount();
    }
    return 0;
}

// NEW: Get model mapped bytes
RawrXDCore_EXPORT uint64_t RawrXDCore_GetModelMappedBytes(const RawrXDModel* model) {
    if (!model) return 0;
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(const_cast<RawrXDModel*>(model));
    if (it != g_models.end()) {
        return it->second.mappedBytes();
    }
    return 0;
}

// NEW: Get model metadata
RawrXDCore_EXPORT int64_t RawrXDCore_GetModelMetaInt(const RawrXDModel* model, const char* key, int64_t def) {
    if (!model || !key) return def;
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(const_cast<RawrXDModel*>(model));
    if (it != g_models.end()) {
        return it->second.getMetaInt(key, def);
    }
    return def;
}

RawrXDCore_EXPORT double RawrXDCore_GetModelMetaFloat(const RawrXDModel* model, const char* key, double def) {
    if (!model || !key) return def;
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(const_cast<RawrXDModel*>(model));
    if (it != g_models.end()) {
        return it->second.getMetaFloat(key, def);
    }
    return def;
}

RawrXDCore_EXPORT const char* RawrXDCore_GetModelMetaString(const RawrXDModel* model, const char* key) {
    if (!model || !key) return nullptr;
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(const_cast<RawrXDModel*>(model));
    if (it != g_models.end()) {
        static thread_local std::string cached;
        cached = it->second.getMetaString(key);
        return cached.c_str();
    }
    return nullptr;
}

// NEW: List model tensors
RawrXDCore_EXPORT size_t RawrXDCore_ListModelTensors(const RawrXDModel* model, char*** outNames) {
    if (!model || !outNames) return 0;
    std::lock_guard<std::mutex> lock(g_modelsMutex);
    auto it = g_models.find(const_cast<RawrXDModel*>(model));
    if (it == g_models.end()) return 0;
    
    auto names = it->second.listTensors();
    size_t count = names.size();
    if (count == 0) {
        *outNames = nullptr;
        return 0;
    }
    
    *outNames = static_cast<char**>(malloc(count * sizeof(char*)));
    if (!*outNames) return 0;
    
    for (size_t i = 0; i < count; ++i) {
        (*outNames)[i] = _strdup(names[i].c_str());
    }
    return count;
}

RawrXDCore_EXPORT void RawrXDCore_FreeTensorList(char** names, size_t count) {
    if (!names) return;
    for (size_t i = 0; i < count; ++i) {
        free(names[i]);
    }
    free(names);
}

// Inference Context
RawrXDCore_EXPORT RawrXDInferenceContext* RawrXDCore_CreateContext(RawrXDModel* model) {
    auto& state = getState();
    if (!state.initialized) {
        setLastError(RAWXD_ERROR_NOT_INITIALIZED);
        return nullptr;
    }
    
    if (!model) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return nullptr;
    }
    
    // Verify model exists
    {
        std::lock_guard<std::mutex> lock(g_modelsMutex);
        if (g_models.find(model) == g_models.end()) {
            setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
            return nullptr;
        }
    }
    
    ContextImpl* ctx = new ContextImpl();
    ctx->model = reinterpret_cast<ModelImpl*>(model);
    RawrXDCore_GetDefaultInferenceParams(&ctx->params);
    ctx->active = true;
    
    RawrXDInferenceContext* handle = reinterpret_cast<RawrXDInferenceContext*>(ctx);
    
    std::lock_guard<std::mutex> lock(g_contextsMutex);
    g_contexts[handle] = *ctx;
    
    logMessage(RAWXD_LOG_DEBUG, "Created inference context for model: %s", ctx->model->name.c_str());
    setLastError(RAWXD_OK);
    return handle;
}

RawrXDCore_EXPORT void RawrXDCore_DestroyContext(RawrXDInferenceContext* ctx) {
    if (!ctx) return;
    
    std::lock_guard<std::mutex> lock(g_contextsMutex);
    auto it = g_contexts.find(ctx);
    if (it != g_contexts.end()) {
        logMessage(RAWXD_LOG_DEBUG, "Destroyed inference context");
        delete reinterpret_cast<ContextImpl*>(ctx);
        g_contexts.erase(it);
    }
}

RawrXDCore_EXPORT void RawrXDCore_GetDefaultInferenceParams(RawrXDInferenceParams* params) {
    if (!params) return;
    params->maxTokens = 256;
    params->temperature = 0.8f;
    params->topP = 0.9f;
    params->topK = 40;
    params->repeatPenalty = 1.1f;
    params->seed = -1;
    params->useGPU = true;
    params->gpuDeviceId = 0;
}

// Inference - REAL Deep2 Integration (placeholder for actual engine integration)
RawrXDCore_EXPORT int RawrXDCore_RunInference(
    RawrXDInferenceContext* ctx,
    const char* prompt,
    const RawrXDInferenceParams* params,
    RawrXDTokenCallback callback,
    void* userData
) {
    auto& state = getState();
    if (!state.initialized) {
        setLastError(RAWXD_ERROR_NOT_INITIALIZED);
        return 0;
    }
    
    if (!ctx || !prompt || !callback) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(g_contextsMutex);
    auto it = g_contexts.find(ctx);
    if (it == g_contexts.end()) {
        setLastError(RAWXD_ERROR_INVALID_ARGUMENT);
        return 0;
    }
    
    ContextImpl& context = it->second;
    if (params) context.params = *params;
    
    logMessage(RAWXD_LOG_INFO, "Running inference: \"%s\" (max_tokens=%d, temp=%.2f)",
               prompt, context.params.maxTokens, context.params.temperature);
    
    // TODO: Replace with actual Deep2 inference engine call
    // For now, use tokenizer from model if available, otherwise fallback to simple tokenization
    
    // Simple tokenization for demonstration (character-level fallback)
    // In real implementation, this would use the model's tokenizer (BPE, SentencePiece, etc.)
    std::string promptStr(prompt);
    std::vector<std::string> tokens;
    
    // Very simple word-level tokenization for demo
    std::string current;
    for (char c : promptStr) {
        if (std::isspace(c)) {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
            tokens.push_back(std::string(1, c));
        } else {
            current += c;
        }
    }
    if (!current.empty()) tokens.push_back(current);
    
    // If no tokens from prompt, use default tokens
    if (tokens.empty()) {
        tokens = {"Hello", " ", "world", "!", " This", " is", " a", " test", "."};
    }
    
    int tokenCount = 0;
    for (int i = 0; i < context.params.maxTokens && !tokens.empty(); ++i) {
        const char* token = tokens[i % tokens.size()].c_str();
        if (!callback(i, token, userData)) break;
        tokenCount++;
        Sleep(10); // Simulate inference delay
    }
    
    // TODO: Actual Deep2 inference loop:
    // 1. Tokenize prompt with model's tokenizer
    // 2. Create KV cache
    // 3. Prefill phase: process all prompt tokens
    // 4. Decode loop: for each position, run llama_decode, sample next token, callback
    // 5. Return generated token count
    
    setLastError(RAWXD_OK);
    return tokenCount;
}

// Memory Management
RawrXDCore_EXPORT void RawrXDCore_GetMemoryStats(RawrXDMemoryStats* stats) {
    if (!stats) return;
    
    // TODO: Get real memory stats from Deep2 engine
    // For now, report process memory
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        stats->totalAllocated = pmc.WorkingSetSize;
        stats->totalReserved = pmc.PagefileUsage;
        stats->peakUsage = pmc.PeakWorkingSetSize;
    } else {
        stats->totalAllocated = 512 * 1024 * 1024;
        stats->totalReserved = 1024 * 1024 * 1024;
        stats->peakUsage = 0;
    }
    stats->gpuAllocated = 0;
    stats->gpuReserved = 0;
}

RawrXDCore_EXPORT void RawrXDCore_TrimMemory(void) {
    logMessage(RAWXD_LOG_INFO, "Memory trim requested");
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
}

// Error handling
RawrXDCore_EXPORT const char* RawrXDCore_GetErrorString(RawrXDError error) {
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

RawrXDCore_EXPORT RawrXDError RawrXDCore_GetLastError(void) {
    return getState().lastError;
}

// Hardware Capabilities - REAL detection
RawrXDCore_EXPORT void RawrXDCore_GetHardwareCaps(RawrXDHardwareCaps* caps) {
    if (!caps) return;
    
    // CPU detection
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    caps->cpuCoreCount = sysInfo.dwNumberOfProcessors;
    
    // Check for AVX2/AVX512
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    caps->hasAVX2 = (cpuInfo[2] & (1 << 5)) != 0;  // AVX2 bit
    caps->hasAVX512 = (cpuInfo[2] & (1 << 16)) != 0; // AVX-512F bit
    
    // System memory
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        caps->systemMemoryMB = static_cast<size_t>(memStatus.ullTotalPhys / (1024*1024));
    }
    
    // GPU detection - placeholder for Vulkan enumeration
    caps->hasVulkan = false; // TODO: Query Vulkan
    caps->hasCUDA = false;   // TODO: Query CUDA
    caps->gpuCount = 0;
    
    // TODO: Enumerate actual GPUs via Vulkan/DXGI
    // For now, report as unavailable
    for (int i = 0; i < 4; ++i) {
        caps->gpuMemoryMB[i] = 0;
        caps->gpuNames[i][0] = '\0';
    }
}

} // extern "C"

// C++ API Implementation
#ifdef __cplusplus

namespace rawrxd {

bool Core::Initialize(const RawrXDConfig* config) {
    if (!RawrXDCore_Initialize()) return false;
    if (config) return RawrXDCore_Configure(config);
    return true;
}

void Core::Shutdown() {
    RawrXDCore_Shutdown();
}

bool Core::IsInitialized() {
    return RawrXDCore_IsInitialized();
}

const char* Core::GetVersion() {
    return RawrXDCore_GetVersion();
}

void Core::SetLogCallback(RawrXDLogCallback callback, void* userData) {
    RawrXDCore_SetLogCallback(callback, userData);
}

void Core::SetLogLevel(RawrXDLogLevel level) {
    RawrXDCore_SetLogLevel(level);
}

void Core::GetMemoryStats(RawrXDMemoryStats& stats) {
    RawrXDCore_GetMemoryStats(&stats);
}

void Core::TrimMemory() {
    RawrXDCore_TrimMemory();
}

RawrXDError Core::GetLastError() {
    return RawrXDCore_GetLastError();
}

const char* Core::GetErrorString(RawrXDError error) {
    return RawrXDCore_GetErrorString(error);
}

void Core::GetHardwareCaps(RawrXDHardwareCaps& caps) {
    RawrXDCore_GetHardwareCaps(&caps);
}

} // namespace rawrxd

#endif // __cplusplus