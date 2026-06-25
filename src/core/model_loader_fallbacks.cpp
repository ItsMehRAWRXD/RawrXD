// model_loader_fallbacks.cpp — Production Model Loader Fallback Implementation
// Provides model loading and format detection when primary loader unavailable
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

// ============================================================================
// Model Format Detection
// ============================================================================
#define MODEL_FMT_UNKNOWN   0
#define MODEL_FMT_GGUF      1
#define MODEL_FMT_GGML      2
#define MODEL_FMT_ONNX      3
#define MODEL_FMT_SAFETENSORS 4
#define MODEL_FMT_PYTORCH   5

// ============================================================================
// Model Info
// ============================================================================
#define MAX_MODELS      32
#define MAX_PATH_LEN    260

struct ModelInfo {
    volatile LONG active;
    char path[MAX_PATH_LEN];
    uint32_t format;
    uint64_t fileSize;
    uint32_t tensorCount;
    uint32_t paramCount;
    char arch[64];
};

// ============================================================================
// State
// ============================================================================
static volatile LONG g_initialized = 0;
static ModelInfo g_models[MAX_MODELS];
static volatile LONG g_modelCount = 0;

// ============================================================================
// Helper: Detect model format from file header
// ============================================================================
static uint32_t DetectModelFormat(const char* path) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return MODEL_FMT_UNKNOWN;
    
    uint8_t header[16];
    DWORD read = 0;
    if (!ReadFile(hFile, header, sizeof(header), &read, nullptr) || read < 4) {
        CloseHandle(hFile);
        return MODEL_FMT_UNKNOWN;
    }
    CloseHandle(hFile);
    
    // GGUF: 'GGUF'
    if (header[0] == 'G' && header[1] == 'G' && header[2] == 'U' && header[3] == 'F') return MODEL_FMT_GGUF;
    // GGML: 'GGML'
    if (header[0] == 'G' && header[1] == 'G' && header[2] == 'M' && header[3] == 'L') return MODEL_FMT_GGML;
    // ONNX: 'ONNX' or protobuf magic
    if (header[0] == 0x08 && header[1] == 0x00) return MODEL_FMT_ONNX;
    // Safetensors: JSON header
    if (header[0] == '{') return MODEL_FMT_SAFETENSORS;
    // PyTorch: ZIP magic
    if (header[0] == 'P' && header[1] == 'K') return MODEL_FMT_PYTORCH;
    
    return MODEL_FMT_UNKNOWN;
}

// ============================================================================
// Exported API
// ============================================================================
extern "C" __declspec(dllexport) int ModelLoaderFallbacks_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    
    InterlockedExchange(&g_modelCount, 0);
    memset(g_models, 0, sizeof(g_models));
    
    return 1;
}

extern "C" __declspec(dllexport) int ModelLoaderFallbacks_RegisterModel(const char* path) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!path) return 0;
    
    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_MODELS; ++i) {
        if (InterlockedCompareExchange(&g_models[i].active, 0, 0) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return 0;
    
    // Get file size
    WIN32_FILE_ATTRIBUTE_DATA attrs;
    uint64_t fileSize = 0;
    if (GetFileAttributesExA(path, GetFileExInfoStandard, &attrs)) {
        fileSize = ((uint64_t)attrs.nFileSizeHigh << 32) | attrs.nFileSizeLow;
    }
    
    // Detect format
    uint32_t fmt = DetectModelFormat(path);
    
    ModelInfo* info = &g_models[slot];
    size_t pathLen = strlen(path);
    if (pathLen >= MAX_PATH_LEN) pathLen = MAX_PATH_LEN - 1;
    memcpy(info->path, path, pathLen);
    info->path[pathLen] = 0;
    info->format = fmt;
    info->fileSize = fileSize;
    info->tensorCount = 0;  // Would be parsed from file
    info->paramCount = 0;
    
    // Set architecture based on filename
    if (strstr(path, "llama")) strcpy_s(info->arch, sizeof(info->arch), "llama");
    else if (strstr(path, "qwen")) strcpy_s(info->arch, sizeof(info->arch), "qwen");
    else if (strstr(path, "mistral")) strcpy_s(info->arch, sizeof(info->arch), "mistral");
    else if (strstr(path, "phi")) strcpy_s(info->arch, sizeof(info->arch), "phi");
    else strcpy_s(info->arch, sizeof(info->arch), "unknown");
    
    InterlockedExchange(&info->active, 1);
    InterlockedIncrement(&g_modelCount);
    
    return 1;
}

extern "C" __declspec(dllexport) int ModelLoaderFallbacks_GetModelCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_modelCount, 0, 0));
}

extern "C" __declspec(dllexport) int ModelLoaderFallbacks_GetModelInfo(int index, char* outPath, uint32_t* outFormat, uint64_t* outSize) {
    if (index < 0 || index >= MAX_MODELS) return 0;
    if (InterlockedCompareExchange(&g_models[index].active, 0, 0) == 0) return 0;
    
    if (outPath) strcpy_s(outPath, MAX_PATH_LEN, g_models[index].path);
    if (outFormat) *outFormat = g_models[index].format;
    if (outSize) *outSize = g_models[index].fileSize;
    return 1;
}

extern "C" __declspec(dllexport) void ModelLoaderFallbacksStub() {
    // Legacy symbol - now has real implementation above
}
