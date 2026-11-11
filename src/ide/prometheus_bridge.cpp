/*=============================================================================
 * prometheus_bridge.cpp
 * C Bridge Implementation for PrometheusMoE Integration
 *
 * Wraps the C++ PrometheusMoE class with a C-compatible interface.
 * Thread-safe singleton pattern with fail-closed error handling.
 *=============================================================================*/

#include "prometheus_bridge.h"
#include "../inference/PrometheusMoE.h"
#include "../execution/execution_gateway_impl.h"
#include <memory>
#include <mutex>
#include <cstring>
#include <vector>
#include <sstream>
#include <thread>
#include <chrono>
#include <cstring>

using namespace RawrXD::Inference;
using namespace rawrxd;

/*=============================================================================
 * Bridge State
 *=============================================================================*/

static struct BridgeState {
    std::unique_ptr<PrometheusMoE> engine;
    std::unique_ptr<execution::RealExecutionGateway> execGateway;
    std::mutex mutex;
    bool initialized = false;
    PB_ModelState state = PB_STATE_NONE;
    std::wstring lastError;
    bool completionActive = false;
    std::unique_ptr<std::thread> completionThread;
    
    // Cached config and model path
    PB_MoEConfig cachedConfig = {};
    std::wstring modelPath;
} g_Bridge;

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

static void SetError(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    
    wchar_t buffer[PB_MAX_ERROR_LEN];
    vswprintf_s(buffer, PB_MAX_ERROR_LEN, format, args);
    g_Bridge.lastError = buffer;
    
    va_end(args);
}

static void ClearError() {
    g_Bridge.lastError.clear();
}

static PB_MoEConfig ConvertConfig(const MoEConfig& cfg) {
    PB_MoEConfig result = {};
    result.isMoE = cfg.isMoE;
    result.numLayers = cfg.numLayers;
    result.numExperts = cfg.numExperts;
    result.expertsPerToken = cfg.expertsPerToken;
    result.numSharedExperts = cfg.numSharedExperts;
    result.hiddenDim = cfg.hiddenDim;
    result.intermediateDim = cfg.intermediateDim;
    result.numHeads = cfg.numHeads;
    result.numKVHeads = cfg.numKVHeads;
    result.headDim = cfg.headDim;
    result.vocabSize = cfg.vocabSize;
    result.topK = cfg.topK;
    result.totalParams = cfg.totalParams;
    result.activeParams = cfg.activeParams;
    result.modelSizeBytes = cfg.modelSizeBytes;
    result.kvCacheBytes = cfg.kvCacheBytes;
    result.quantType = cfg.quantType;
    result.isDeepSeekV3 = (cfg.numExperts == 256 && cfg.expertsPerToken == 8);
    return result;
}

static std::string WideToUtf8(const wchar_t* wide) {
    if (!wide || !*wide) return "";
    
    int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &result[0], size, nullptr, nullptr);
    return result;
}

static std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (size <= 0) return L"";
    
    std::wstring result(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], size);
    return result;
}

/*=============================================================================
 * Bridge API Implementation
 *=============================================================================*/

PB_Status PB_Init(void) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    
    if (g_Bridge.initialized) {
        return PB_OK; // Already initialized
    }
    
    try {
        g_Bridge.engine = std::make_unique<PrometheusMoE>();
        g_Bridge.initialized = true;
        g_Bridge.state = PB_STATE_NONE;
        ClearError();
        return PB_OK;
    }
    catch (const std::exception& e) {
        SetError(L"Failed to initialize Prometheus bridge: %S", e.what());
        return PB_ERROR_BRIDGE_ERROR;
    }
}

void PB_Shutdown(void) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    
    if (g_Bridge.completionThread && g_Bridge.completionThread->joinable()) {
        g_Bridge.completionThread->join();
    }
    g_Bridge.completionThread.reset();
    
    g_Bridge.engine.reset();
    g_Bridge.initialized = false;
    g_Bridge.state = PB_STATE_NONE;
    g_Bridge.completionActive = false;
}

bool PB_IsReady(void) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    return g_Bridge.initialized;
}

PB_Status PB_ProbeModel(const wchar_t* path, PB_MoEConfig* config) {
    if (!path || !config) {
        return PB_ERROR_INVALID_PARAM;
    }
    
    try {
        std::string utf8Path = WideToUtf8(path);
        MoEConfig cfg = PrometheusMoE::Probe(utf8Path);
        
        *config = ConvertConfig(cfg);
        return PB_OK;
    }
    catch (const std::exception& e) {
        SetError(L"Failed to probe model: %S", e.what());
        return PB_ERROR_LOAD_FAILED;
    }
}

PB_Status PB_LoadModel(const wchar_t* path, int gpuLayers) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    
    if (!g_Bridge.initialized) {
        return PB_ERROR_NOT_INITIALIZED;
    }
    
    if (g_Bridge.state == PB_STATE_LOADED) {
        return PB_ERROR_ALREADY_LOADED;
    }
    
    if (!path || !*path) {
        return PB_ERROR_INVALID_PARAM;
    }
    
    try {
        g_Bridge.state = PB_STATE_LOADING;
        ClearError();
        
        std::string utf8Path = WideToUtf8(path);
        
        // Load weights via PrometheusMoE
        if (!g_Bridge.engine->Load(utf8Path, gpuLayers)) {
            g_Bridge.state = PB_STATE_ERROR;
            SetError(L"Failed to load model weights from: %s", path);
            return PB_ERROR_LOAD_FAILED;
        }
        
        // Initialize execution gateway for real inference
        g_Bridge.execGateway = std::make_unique<execution::RealExecutionGateway>();
        if (!g_Bridge.execGateway->Initialize()) {
            g_Bridge.engine->Unload();
            g_Bridge.state = PB_STATE_ERROR;
            SetError(L"Failed to initialize execution gateway for: %s", path);
            return PB_ERROR_LOAD_FAILED;
        }
        
        // Cache the config and model path
        const MoEConfig& cfg = g_Bridge.engine->GetConfig();
        g_Bridge.cachedConfig = ConvertConfig(cfg);
        g_Bridge.modelPath = path;
        g_Bridge.state = PB_STATE_LOADED;
        
        return PB_OK;
    }
    catch (const std::exception& e) {
        g_Bridge.state = PB_STATE_ERROR;
        SetError(L"Exception during model load: %S", e.what());
        return PB_ERROR_LOAD_FAILED;
    }
}

void PB_UnloadModel(void) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    
    if (g_Bridge.completionThread && g_Bridge.completionThread->joinable()) {
        g_Bridge.completionThread->join();
    }
    g_Bridge.completionThread.reset();
    
    // Clean up execution gateway
    if (g_Bridge.execGateway) {
        g_Bridge.execGateway->Shutdown();
        g_Bridge.execGateway.reset();
    }
    
    if (g_Bridge.engine) {
        g_Bridge.engine->Unload();
    }
    
    g_Bridge.state = PB_STATE_NONE;
    g_Bridge.completionActive = false;
    memset(&g_Bridge.cachedConfig, 0, sizeof(g_Bridge.cachedConfig));
}

bool PB_IsModelLoaded(void) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    return g_Bridge.initialized && 
           g_Bridge.engine && 
           g_Bridge.engine->IsLoaded();
}

PB_ModelState PB_GetModelState(void) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    return g_Bridge.state;
}

PB_Status PB_GetModelConfig(PB_MoEConfig* config) {
    if (!config) {
        return PB_ERROR_INVALID_PARAM;
    }
    
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    
    if (!g_Bridge.initialized || g_Bridge.state != PB_STATE_LOADED) {
        return PB_ERROR_NOT_LOADED;
    }
    
    *config = g_Bridge.cachedConfig;
    return PB_OK;
}

const wchar_t* PB_GetLastError(void) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    return g_Bridge.lastError.empty() ? L"" : g_Bridge.lastError.c_str();
}

PB_Status PB_CompleteSync(
    const PB_CompletionRequest* request,
    PB_CompletionResponse* response
) {
    if (!request || !response) {
        return PB_ERROR_INVALID_PARAM;
    }
    
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    
    if (!g_Bridge.initialized) {
        return PB_ERROR_NOT_INITIALIZED;
    }
    
    if (!g_Bridge.execGateway || !g_Bridge.execGateway->IsReady()) {
        return PB_ERROR_NOT_LOADED;
    }
    
    // Clear response
    memset(response, 0, sizeof(PB_CompletionResponse));
    
    try {
        // Convert context to UTF-8 for the model
        std::string utf8Context = WideToUtf8(request->context);
        
        // Build execution request for inference
        execution::ExecutionRequest execReq;
        execReq.command = execution::CommandType::RUN_INFERENCE;
        execReq.model_path = WideToUtf8(g_Bridge.modelPath.c_str());
        execReq.prompt = utf8Context;
        execReq.max_tokens = request->maxTokens > 0 ? request->maxTokens : 128;
        execReq.temperature = request->temperature;
        
        // Execute generation through ExecutionGateway
        execution::ExecutionResult result = g_Bridge.execGateway->Execute(execReq);
        
        if (result.status != execution::Status::SUCCESS) {
            response->status = PB_ERROR_INFERENCE_FAILED;
            SetError(L"Generation failed: %s", Utf8ToWide(result.error_details).c_str());
            wcscpy_s(response->errorMessage, PB_MAX_ERROR_LEN, PB_GetLastError());
            return PB_ERROR_INFERENCE_FAILED;
        }
        
        // Convert result to wide string
        std::wstring wideResult = Utf8ToWide(result.text_output);
        wcscpy_s(response->text, PB_MAX_SUGGESTION_LEN, wideResult.c_str());
        
        response->tokensGenerated = result.telemetry.tokens_generated;
        response->isComplete = true;
        response->status = PB_OK;
        
        return PB_OK;
    }
    catch (const std::exception& e) {
        response->status = PB_ERROR_INFERENCE_FAILED;
        SetError(L"Inference failed: %S", e.what());
        wcscpy_s(response->errorMessage, PB_MAX_ERROR_LEN, PB_GetLastError());
        return PB_ERROR_INFERENCE_FAILED;
    }
}

PB_Status PB_CompleteAsync(
    const PB_CompletionRequest* request,
    PB_TokenCallback callback
) {
    if (!request || !callback) {
        return PB_ERROR_INVALID_PARAM;
    }
    
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    
    if (!g_Bridge.initialized) {
        return PB_ERROR_NOT_INITIALIZED;
    }
    
    if (!g_Bridge.engine || !g_Bridge.engine->IsLoaded()) {
        return PB_ERROR_NOT_LOADED;
    }
    
    if (g_Bridge.completionActive) {
        return PB_ERROR_ALREADY_LOADED; // Completion already in progress
    }
    
    // For async, we'd spawn a thread and stream tokens
    // This is a simplified implementation
    g_Bridge.completionActive = true;
    
    // Call sync version for now
    PB_CompletionResponse response = {};
    PB_Status status = PB_CompleteSync(request, &response);
    
    // Deliver result via callback
    if (callback) {
        callback(response.text, response.tokensGenerated, true, request->userData);
    }
    
    g_Bridge.completionActive = false;
    return status;
}

void PB_CancelCompletion(void) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    g_Bridge.completionActive = false;
}

bool PB_IsCompletionActive(void) {
    std::lock_guard<std::mutex> lock(g_Bridge.mutex);
    return g_Bridge.completionActive;
}

void PB_FormatModelSize(uint64_t bytes, wchar_t* output, size_t outputLen) {
    if (!output || outputLen == 0) return;
    
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    int unitIndex = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unitIndex < 4) {
        size /= 1024.0;
        unitIndex++;
    }
    
    if (unitIndex == 0) {
        swprintf_s(output, outputLen, L"%llu %s", bytes, units[unitIndex]);
    } else {
        swprintf_s(output, outputLen, L"%.2f %s", size, units[unitIndex]);
    }
}

bool PB_NarrowToWide(const char* narrow, wchar_t* wide, size_t wideLen) {
    if (!narrow || !wide || wideLen == 0) return false;
    
    int result = MultiByteToWideChar(CP_UTF8, 0, narrow, -1, wide, static_cast<int>(wideLen));
    return result > 0;
}

bool PB_WideToNarrow(const wchar_t* wide, char* narrow, size_t narrowLen) {
    if (!wide || !narrow || narrowLen == 0) return false;
    
    int result = WideCharToMultiByte(CP_UTF8, 0, wide, -1, narrow, static_cast<int>(narrowLen), nullptr, nullptr);
    return result > 0;
}
