/*===========================================================================
 * BraidedModelLoader.cpp
 * Universal Model Loader Implementation
 * 
 * Supports all GGUF architectures with automatic braiding and warmup
 *===========================================================================*/

#include "BraidedModelLoader.h"
#include <cstring>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>

/*===========================================================================
 * GGUF FORMAT DEFINITIONS (minimal)
 *===========================================================================*/
#pragma pack(push, 1)
typedef struct GGUFHeader {
    uint32_t magic;                 // 'GGUF'
    uint32_t version;
    uint64_t tensorCount;
    uint64_t metadataCount;
} GGUFHeader;
#pragma pack(pop)

#define GGUF_MAGIC 0x46554747  // 'GGUF' in little-endian

/*===========================================================================
 * INTERNAL MODEL CONTEXT
 *===========================================================================*/
typedef struct BraidedModelContext {
    BraidedModelConfig  config;
    BraidedModelInfo    info;
    HANDLE              hFile;
    HANDLE              hMapping;
    void*               baseAddress;
    uint64_t            fileSize;
    BOOL                isWarm;
    std::atomic<BOOL>   inferenceRunning{FALSE};
    WCHAR               lastError[512];
    
    // Architecture-specific data
    struct {
        uint32_t*       expertMap;        // For MoE models
        uint32_t        activeExperts;
        uint32_t        braidStride;
    } archData;
} BraidedModelContext;

static std::atomic<BOOL> g_Initialized{FALSE};
static std::vector<BraidedModelContext*> g_LoadedModels;

/*===========================================================================
 * ARCHITECTURE DETECTION
 *===========================================================================*/

static BraidedArchitecture DetectArchitecture(const WCHAR* modelPath) {
    // Quick detection based on filename patterns
    const WCHAR* name = wcsrchr(modelPath, L'\\');
    if (!name) name = modelPath;
    else name++;
    
    WCHAR lowerName[256];
    for (int i = 0; i < 255 && name[i]; i++) {
        lowerName[i] = towlower(name[i]);
    }
    lowerName[255] = L'\0';
    
    if (wcsstr(lowerName, L"deepseek")) {
        if (wcsstr(lowerName, L"v3")) return BRAIDED_ARCH_DEEPSEEK_V3;
        return BRAIDED_ARCH_DEEPSEEK_V3;
    }
    if (wcsstr(lowerName, L"llama")) return BRAIDED_ARCH_LLAMA;
    if (wcsstr(lowerName, L"mixtral")) return BRAIDED_ARCH_MIXTRAL;
    if (wcsstr(lowerName, L"phi")) return BRAIDED_ARCH_PHI;
    if (wcsstr(lowerName, L"qwen")) return BRAIDED_ARCH_QWEN;
    if (wcsstr(lowerName, L"gemma")) return BRAIDED_ARCH_GEMMA;
    if (wcsstr(lowerName, L"mistral")) return BRAIDED_ARCH_MISTRAL;
    if (wcsstr(lowerName, L"command")) return BRAIDED_ARCH_COMMAND_R;
    if (wcsstr(lowerName, L"stable")) return BRAIDED_ARCH_STABLELM;
    
    // Default to Llama for unknown models
    return BRAIDED_ARCH_LLAMA;
}

/*===========================================================================
 * BRAIDING CALCULATION
 *===========================================================================*/

static void CalculateOptimalBraiding(BraidedModelContext* ctx) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    uint32_t numProcs = sysInfo.dwNumberOfProcessors;
    uint64_t totalRAM = 0;
    
    // Get total physical memory
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        totalRAM = memStatus.ullTotalPhys;
    }
    
    // Calculate based on architecture and system
    switch (ctx->info.arch) {
        case BRAIDED_ARCH_DEEPSEEK_V3:
            // DeepSeek-V3: 671B params, 256 experts
            // Use 16-32 braids depending on RAM
            if (totalRAM > 128ULL * 1024 * 1024 * 1024) { // >128GB
                ctx->config.numBraids = 32;
                ctx->config.shardCount = 64;
            } else {
                ctx->config.numBraids = 16;
                ctx->config.shardCount = 32;
            }
            ctx->info.usesMLA = TRUE;
            ctx->info.usesGQA = TRUE;
            ctx->info.usesMoE = TRUE;
            break;
            
        case BRAIDED_ARCH_MIXTRAL:
            // Mixtral: 8 experts
            ctx->config.numBraids = 8;
            ctx->config.shardCount = 16;
            ctx->info.usesMoE = TRUE;
            break;
            
        case BRAIDED_ARCH_LLAMA:
        default:
            // Standard transformer
            ctx->config.numBraids = std::min(numProcs / 2, 16u);
            ctx->config.shardCount = ctx->config.numBraids * 2;
            break;
    }
    
    // Ensure minimums
    if (ctx->config.numBraids == 0) ctx->config.numBraids = 4;
    if (ctx->config.shardCount == 0) ctx->config.shardCount = 8;
    
    // Calculate cache size
    if (ctx->config.cacheSizeGB == 0) {
        uint64_t modelSizeGB = ctx->info.fileSizeBytes / (1024 * 1024 * 1024);
        if (modelSizeGB > 100) {
            ctx->config.cacheSizeGB = 64; // Large models need big cache
        } else if (modelSizeGB > 10) {
            ctx->config.cacheSizeGB = 16;
        } else {
            ctx->config.cacheSizeGB = 4;
        }
    }
}

/*===========================================================================
 * GGUF PARSING
 *===========================================================================*/

static BOOL ParseGGUFHeader(BraidedModelContext* ctx) {
    if (!ctx->baseAddress) return FALSE;
    
    GGUFHeader* header = (GGUFHeader*)ctx->baseAddress;
    
    if (header->magic != GGUF_MAGIC) {
        wcscpy_s(ctx->lastError, L"Invalid GGUF magic");
        return FALSE;
    }
    
    // Store basic info
    ctx->info.fileSizeBytes = ctx->fileSize;
    
    // Estimate parameters from file size (rough heuristic)
    // Q4_K_M: ~0.6 bytes per parameter
    uint64_t estimatedParams = ctx->fileSize / 0.6;
    ctx->info.totalParams = estimatedParams;
    
    // Detect quantization from size
    if (ctx->fileSize < 2ULL * 1024 * 1024 * 1024) { // <2GB
        ctx->info.quantizationBits = 8;  // Q8_0
    } else if (ctx->fileSize < 10ULL * 1024 * 1024 * 1024) { // <10GB
        ctx->info.quantizationBits = 4;  // Q4_K_M
    } else {
        ctx->info.quantizationBits = 4;  // Q4 or lower
    }
    
    return TRUE;
}

/*===========================================================================
 * LIFECYCLE
 *===========================================================================*/

BraidedStatus BraidedModelLoader_Initialize(void) {
    if (g_Initialized) return BRAIDED_OK;
    
    // Initialize WarmupEngine
    WarmupStatus wStatus = WarmupEngine_Initialize();
    if (wStatus != WARMUP_OK) {
        return BRAIDED_ERROR_NOT_INITIALIZED;
    }
    
    g_LoadedModels.clear();
    g_Initialized = TRUE;
    
    return BRAIDED_OK;
}

void BraidedModelLoader_Shutdown(void) {
    if (!g_Initialized) return;
    
    // Unload all models
    for (auto* ctx : g_LoadedModels) {
        BraidedModelLoader_UnloadModel(ctx);
    }
    g_LoadedModels.clear();
    
    WarmupEngine_Shutdown();
    g_Initialized = FALSE;
}

BOOL BraidedModelLoader_IsReady(void) {
    return g_Initialized && WarmupEngine_IsReady();
}

/*===========================================================================
 * MODEL LOADING
 *===========================================================================*/

BraidedStatus BraidedModelLoader_LoadModel(
    const BraidedModelConfig* config,
    BraidedModelHandle* outHandle,
    BraidedProgressCallback progressCb) {
    
    if (!g_Initialized || !config || !outHandle) {
        return BRAIDED_ERROR_INVALID_PARAMS;
    }
    
    // Create context
    BraidedModelContext* ctx = new BraidedModelContext();
    if (!ctx) {
        return BRAIDED_ERROR_MEMORY;
    }
    
    ZeroMemory(ctx, sizeof(BraidedModelContext));
    CopyMemory(&ctx->config, config, sizeof(BraidedModelConfig));
    
    // Report progress
    if (progressCb) progressCb(0.0f, L"Opening model file", config->userData);
    
    // Open file
    ctx->hFile = CreateFileW(
        config->modelPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (ctx->hFile == INVALID_HANDLE_VALUE) {
        wcscpy_s(ctx->lastError, L"Failed to open model file");
        delete ctx;
        return BRAIDED_ERROR_FILE_NOT_FOUND;
    }
    
    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(ctx->hFile, &fileSize)) {
        wcscpy_s(ctx->lastError, L"Failed to get file size");
        CloseHandle(ctx->hFile);
        delete ctx;
        return BRAIDED_ERROR_INVALID_FORMAT;
    }
    ctx->fileSize = fileSize.QuadPart;
    
    // Detect architecture
    ctx->info.arch = DetectArchitecture(config->modelPath);
    
    // Calculate braiding
    CalculateOptimalBraiding(ctx);
    
    // Report progress
    if (progressCb) progressCb(10.0f, L"Mapping model into memory", config->userData);
    
    // Create file mapping
    ctx->hMapping = CreateFileMapping(
        ctx->hFile,
        nullptr,
        PAGE_READONLY,
        0, 0,
        nullptr
    );
    
    if (!ctx->hMapping) {
        wcscpy_s(ctx->lastError, L"Failed to create file mapping");
        CloseHandle(ctx->hFile);
        delete ctx;
        return BRAIDED_ERROR_MEMORY;
    }
    
    // Map view
    ctx->baseAddress = MapViewOfFile(ctx->hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!ctx->baseAddress) {
        wcscpy_s(ctx->lastError, L"Failed to map view of file");
        CloseHandle(ctx->hMapping);
        CloseHandle(ctx->hFile);
        delete ctx;
        return BRAIDED_ERROR_MEMORY;
    }
    
    // Parse GGUF
    if (progressCb) progressCb(20.0f, L"Parsing GGUF metadata", config->userData);
    
    if (!ParseGGUFHeader(ctx)) {
        UnmapViewOfFile(ctx->baseAddress);
        CloseHandle(ctx->hMapping);
        CloseHandle(ctx->hFile);
        delete ctx;
        return BRAIDED_ERROR_INVALID_FORMAT;
    }
    
    // Run warmup if enabled
    if (config->enableWarmup) {
        if (progressCb) progressCb(30.0f, L"Warming up memory", config->userData);
        
        WarmupConfig wConfig = {};
        wConfig.numThreads = 4;
        wConfig.chunkSize = WarmupEngine_CalculateOptimalChunkSize(ctx->fileSize);
        wConfig.sequentialOnly = (ctx->fileSize > 100ULL * 1024 * 1024 * 1024); // Sequential for large models
        wConfig.priorityClass = THREAD_PRIORITY_BELOW_NORMAL;
        
        WarmupStatus wStatus = WarmupEngine_Start(
            ctx->baseAddress,
            ctx->fileSize,
            &wConfig,
            // Progress callback wrapper
            [](uint64_t bytes, uint64_t total, float pct, void* userData) {
                auto* cb = (BraidedProgressCallback)userData;
                if (cb) cb(30.0f + (pct * 0.6f), L"Warming up memory", nullptr);
            },
            // Complete callback
            [](WarmupStatus status, uint64_t bytes, double time, void* userData) {
                (void)status; (void)bytes; (void)time; (void)userData;
            }
        );
        
        if (wStatus == WARMUP_OK) {
            // Wait for warmup (with timeout for very large models)
            WarmupEngine_WaitForComplete(300000); // 5 minute timeout
            ctx->isWarm = TRUE;
        }
    }
    
    if (progressCb) progressCb(100.0f, L"Model loaded", config->userData);
    
    // Add to loaded models
    g_LoadedModels.push_back(ctx);
    *outHandle = ctx;
    
    return BRAIDED_OK;
}

void BraidedModelLoader_UnloadModel(BraidedModelHandle handle) {
    if (!handle) return;
    
    BraidedModelContext* ctx = (BraidedModelContext*)handle;
    
    // Cancel any inference
    BraidedModelLoader_CancelInference(handle);
    
    // Unmap and close
    if (ctx->baseAddress) {
        UnmapViewOfFile(ctx->baseAddress);
    }
    if (ctx->hMapping) {
        CloseHandle(ctx->hMapping);
    }
    if (ctx->hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->hFile);
    }
    
    // Remove from list
    auto it = std::find(g_LoadedModels.begin(), g_LoadedModels.end(), ctx);
    if (it != g_LoadedModels.end()) {
        g_LoadedModels.erase(it);
    }
    
    delete ctx;
}

BraidedStatus BraidedModelLoader_GetModelInfo(
    BraidedModelHandle handle,
    BraidedModelInfo* outInfo) {
    
    if (!handle || !outInfo) return BRAIDED_ERROR_INVALID_PARAMS;
    
    BraidedModelContext* ctx = (BraidedModelContext*)handle;
    CopyMemory(outInfo, &ctx->info, sizeof(BraidedModelInfo));
    
    return BRAIDED_OK;
}

BOOL BraidedModelLoader_IsModelReady(BraidedModelHandle handle) {
    if (!handle) return FALSE;
    BraidedModelContext* ctx = (BraidedModelContext*)handle;
    return ctx->baseAddress != nullptr && !ctx->inferenceRunning;
}

/*===========================================================================
 * INFERENCE (PLACEHOLDER - INTEGRATES WITH Deep2)
 *===========================================================================*/

BraidedStatus BraidedModelLoader_InferSync(
    BraidedModelHandle handle,
    const BraidedInferenceRequest* request,
    BraidedInferenceResponse* response) {
    
    if (!handle || !request || !response) {
        return BRAIDED_ERROR_INVALID_PARAMS;
    }
    
    BraidedModelContext* ctx = (BraidedModelContext*)handle;
    
    if (!ctx->baseAddress) {
        return BRAIDED_ERROR_NOT_INITIALIZED;
    }
    
    // TODO: Integrate with Deep2 inference engine
    // Return placeholder response (Deep2 integration pending)

    response->status = BRAIDED_OK;
    response->textLen = 0;
    response->confidence = 0.0f;
    response->tokensGenerated = 0;
    response->generationTimeMs = 0.0;
    
    return BRAIDED_OK;
}

BraidedStatus BraidedModelLoader_InferAsync(
    BraidedModelHandle handle,
    const BraidedInferenceRequest* request,
    BraidedTokenCallback tokenCb,
    void* completeUserData) {
    
    (void)completeUserData;
    
    if (!handle || !request) {
        return BRAIDED_ERROR_INVALID_PARAMS;
    }
    
    BraidedModelContext* ctx = (BraidedModelContext*)handle;
    
    if (ctx->inferenceRunning) {
        return BRAIDED_ERROR_INFERENCE;
    }
    
    ctx->inferenceRunning = TRUE;
    
    // TODO: Start async inference thread
    // Complete synchronously (async thread implementation pending)

    if (tokenCb) {
        tokenCb("", 0, TRUE, request->userData);
    }
    
    ctx->inferenceRunning = FALSE;
    
    return BRAIDED_OK;
}

void BraidedModelLoader_CancelInference(BraidedModelHandle handle) {
    if (!handle) return;
    BraidedModelContext* ctx = (BraidedModelContext*)handle;
    ctx->inferenceRunning = FALSE;
}

/*===========================================================================
 * UTILITY FUNCTIONS
 *===========================================================================*/

const WCHAR* BraidedModelLoader_GetLastError(void) {
    // Return last error from most recent operation
    if (!g_LoadedModels.empty()) {
        return g_LoadedModels.back()->lastError;
    }
    return L"No error";
}

const WCHAR* BraidedModelLoader_GetVersion(void) {
    return L"BraidedModelLoader v1.0 (Universal)";
}

BraidedStatus BraidedModelLoader_AutoConfig(
    const WCHAR* modelPath,
    BraidedModelConfig* outConfig) {
    
    if (!modelPath || !outConfig) {
        return BRAIDED_ERROR_INVALID_PARAMS;
    }
    
    ZeroMemory(outConfig, sizeof(BraidedModelConfig));
    
    wcsncpy_s(outConfig->modelPath, modelPath, BRAIDED_MAX_MODEL_PATH - 1);
    
    // Detect architecture
    BraidedArchitecture arch = DetectArchitecture(modelPath);
    
    // Set defaults based on architecture
    switch (arch) {
        case BRAIDED_ARCH_DEEPSEEK_V3:
            outConfig->numBraids = 32;
            outConfig->shardCount = 64;
            outConfig->cacheSizeGB = 64;
            break;
        case BRAIDED_ARCH_MIXTRAL:
            outConfig->numBraids = 8;
            outConfig->shardCount = 16;
            outConfig->cacheSizeGB = 16;
            break;
        default:
            outConfig->numBraids = 8;
            outConfig->shardCount = 16;
            outConfig->cacheSizeGB = 8;
            break;
    }
    
    outConfig->backend = BRAIDED_BACKEND_AUTO;
    outConfig->useNVMe = TRUE;
    outConfig->enableWarmup = TRUE;
    outConfig->demandPaging = TRUE;
    
    return BRAIDED_OK;
}

uint64_t BraidedModelLoader_CalculateMemoryRequirement(
    const BraidedModelConfig* config,
    const BraidedModelInfo* info) {
    
    (void)config;
    if (!info) return 0;
    
    // Rough estimate: model size + overhead
    uint64_t baseSize = info->fileSizeBytes;
    uint64_t overhead = baseSize / 10; // 10% overhead
    
    return baseSize + overhead;
}

const WCHAR** BraidedModelLoader_GetSupportedArchitectures(void) {
    static const WCHAR* archs[] = {
        L"Llama/Llama2/Llama3",
        L"DeepSeek-V3 (671B)",
        L"Mixtral 8x7B/8x22B",
        L"Phi-3/Phi-4",
        L"Qwen2/Qwen2.5",
        L"Gemma/Gemma2",
        L"Mistral/Mistral-Nemo",
        L"Command-R",
        L"StableLM",
        nullptr
    };
    return archs;
}

/* E> End of BraidedModelLoader.cpp <3 */
