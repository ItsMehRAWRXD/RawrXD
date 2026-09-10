// ============================================================================
// gguf_loader_masm.cpp — DEPRECATED NAME; Option A façade (same as *_real.cpp)
// ============================================================================
// SPLIT AUTHORITY REJECTED: no standalone GGUFLoader / g_modelLoaded.
// Load/IsLoaded/Unload delegate to process-wide CPUInferenceEngine.
// PROMOTE=0 TIP_CLIMB=HOLD REOPEN_R01=0
// ============================================================================

#include "../cpu_inference_engine.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>

namespace {

std::mutex& BridgeMu() {
    static std::mutex m;
    return m;
}

std::shared_ptr<CPUInferenceEngine>& Engine() {
    static std::shared_ptr<CPUInferenceEngine> e;
    return e;
}

std::string& LastError() {
    static std::string e;
    return e;
}

void SetErr(const char* msg) {
    LastError() = msg ? msg : "";
}

bool EnsureEngine() {
    if (!Engine())
        Engine() = CPUInferenceEngine::GetSharedInstance();
    return Engine() != nullptr;
}

} // namespace

extern "C" {

__declspec(dllexport) bool Win32IDE_InitGGUFLoader() {
    try {
        std::lock_guard<std::mutex> lock(BridgeMu());
        LastError().clear();
        if (!EnsureEngine()) {
            SetErr("CPUInferenceEngine::GetSharedInstance returned null");
            return false;
        }
        OutputDebugStringA("[GGUF] Bridge init → shared CPUInferenceEngine\n");
        return true;
    } catch (...) {
        SetErr("Win32IDE_InitGGUFLoader exception");
        return false;
    }
}

__declspec(dllexport) bool Win32IDE_LoadGGUFModel(const char* path) {
    try {
        std::lock_guard<std::mutex> lock(BridgeMu());
        LastError().clear();
        if (!path || !*path) {
            SetErr("Invalid path");
            return false;
        }
        if (!EnsureEngine()) {
            SetErr("CPUInferenceEngine unavailable");
            return false;
        }
#ifdef _WIN32
        _putenv_s("RAWRXD_HOST_DECODE", "1");
        _putenv_s("RAWRXD_FORCE_CPU_INFERENCE", "1");
        _putenv_s("RAWRXD_PRODUCT_MODEL", path);
#endif
        if (!Engine()->LoadModel(path)) {
            const std::string& detail = Engine()->GetLastLoadErrorMessage();
            SetErr(detail.empty() ? "CPUInferenceEngine::LoadModel failed" : detail.c_str());
            return false;
        }
        if (!Engine()->IsModelLoaded()) {
            SetErr("LoadModel returned true but IsModelLoaded=false");
            return false;
        }
        OutputDebugStringA("[GGUF] Runtime armed (CIE m_modelLoaded=true)\n");
        return true;
    } catch (const std::exception& ex) {
        SetErr(ex.what());
        return false;
    } catch (...) {
        SetErr("Win32IDE_LoadGGUFModel exception");
        return false;
    }
}

__declspec(dllexport) bool Win32IDE_ValidateGGUFModel() {
    try {
        std::lock_guard<std::mutex> lock(BridgeMu());
        if (!EnsureEngine() || !Engine()->IsModelLoaded()) {
            SetErr("No runtime model loaded");
            return false;
        }
        if (Engine()->GetVocabSize() <= 0) {
            SetErr("Runtime vocab_size invalid");
            return false;
        }
        LastError().clear();
        return true;
    } catch (...) {
        SetErr("Win32IDE_ValidateGGUFModel exception");
        return false;
    }
}

__declspec(dllexport) uint64_t Win32IDE_GetGGUFModelSize() {
    try {
        std::lock_guard<std::mutex> lock(BridgeMu());
        if (!EnsureEngine() || !Engine()->IsModelLoaded())
            return 0;
        return static_cast<uint64_t>(Engine()->GetMemoryUsage());
    } catch (...) {
        return 0;
    }
}

__declspec(dllexport) int32_t Win32IDE_GetGGUFMetadata(char* buffer, int32_t bufferSize) {
    try {
        std::lock_guard<std::mutex> lock(BridgeMu());
        if (!EnsureEngine() || !Engine()->IsModelLoaded() || !buffer || bufferSize <= 0)
            return -1;
        char json[512];
        const int n = snprintf(
            json, sizeof(json),
            "{\"loaded\":true,\"vocab_size\":%d,\"embedding_dim\":%d,"
            "\"layer_count\":%d,\"head_count\":%d,\"authority\":\"CPUInferenceEngine\"}",
            Engine()->GetVocabSize(), Engine()->GetEmbeddingDim(),
            Engine()->GetNumLayers(), Engine()->GetNumHeads());
        if (n <= 0 || n >= bufferSize)
            return -2;
        memcpy(buffer, json, static_cast<size_t>(n) + 1);
        LastError().clear();
        return n;
    } catch (...) {
        SetErr("Win32IDE_GetGGUFMetadata exception");
        return -1;
    }
}

__declspec(dllexport) int32_t Win32IDE_GetGGUFTensorCount() {
    try {
        std::lock_guard<std::mutex> lock(BridgeMu());
        if (!EnsureEngine() || !Engine()->IsModelLoaded())
            return 0;
        return Engine()->GetNumLayers();
    } catch (...) {
        return 0;
    }
}

__declspec(dllexport) const char* Win32IDE_GetGGUFLastError() {
    return LastError().c_str();
}

__declspec(dllexport) void Win32IDE_UnloadGGUFModel() {
    try {
        std::lock_guard<std::mutex> lock(BridgeMu());
        if (EnsureEngine())
            (void)Engine()->UnloadModel();
        LastError().clear();
    } catch (...) {
        SetErr("Win32IDE_UnloadGGUFModel exception");
    }
}

__declspec(dllexport) bool Win32IDE_IsGGUFModelLoaded() {
    try {
        std::lock_guard<std::mutex> lock(BridgeMu());
        return EnsureEngine() && Engine()->IsModelLoaded();
    } catch (...) {
        return false;
    }
}

} // extern "C"
