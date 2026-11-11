/*===========================================================================
 * SovereignInferenceBridge_SharedMem.cpp
 * Shared Memory Implementation of Sovereign Inference Bridge
 * 
 * Replaces pipe-based IPC with zero-copy shared memory for lower latency
 *===========================================================================*/

#include "SovereignInferenceBridge.h"
#include "../runtime/SovereignSharedMemoryServer.hpp"
#include <stdio.h>
#include <string.h>

/*===========================================================================
 * INTERNAL STATE
 *=========================================================================*/

typedef struct SIB_InternalState {
    BOOL                        initialized;
    BOOL                        modelLoaded;
    SIB_ModelInfo               modelInfo;
    BOOL                        inferencing;
    SIB_TokenCallback           currentCallback;
    void*                       currentUserData;
    WCHAR                       lastError[512];
    
    // Shared memory connection
    HANDLE                      hSharedMem;
    HANDLE                      hRequestEvent;
    HANDLE                      hResponseEvent;
    RawrXD::Runtime::SovereignSharedBlock* pSharedBlock;
    
    // Worker thread for async processing
    HANDLE                      hWorkerThread;
    BOOL                        workerRunning;
} SIB_InternalState;

static SIB_InternalState g_sib = {0};

/*===========================================================================
 * WORKER THREAD
 *=========================================================================*/

static DWORD WINAPI SIB_WorkerThread(LPVOID param) {
    (void)param;
    
    while (g_sib.workerRunning) {
        // Wait for response from runtime
        DWORD waitResult = WaitForSingleObject(g_sib.hResponseEvent, 100);
        
        if (waitResult == WAIT_OBJECT_0 && g_sib.pSharedBlock) {
            if (g_sib.pSharedBlock->responseReady.load() == 1) {
                // Read response
                auto& resp = g_sib.pSharedBlock->response;
                
                // Convert to wide string for callback
                WCHAR tokenWide[16384];
                MultiByteToWideChar(CP_UTF8, 0, resp.text, -1, 
                                   tokenWide, 16384);
                
                // Invoke callback
                if (g_sib.currentCallback) {
                    g_sib.currentCallback(tokenWide, resp.tokenCount, 
                                         TRUE, g_sib.currentUserData);
                }
                
                // Mark response consumed
                g_sib.pSharedBlock->responseReady.store(0);
                g_sib.inferencing = FALSE;
            }
        }
    }
    
    return 0;
}

/*===========================================================================
 * LIFECYCLE
 *=========================================================================*/

SIB_Status SIB_Initialize(void) {
    if (g_sib.initialized) {
        return SIB_OK;
    }
    
    ZeroMemory(&g_sib, sizeof(g_sib));
    
    // Open shared memory (created by runtime)
    g_sib.hSharedMem = OpenFileMappingW(
        FILE_MAP_ALL_ACCESS,
        FALSE,
        L"RawrXD_SharedMem_Alpha"
    );
    
    if (!g_sib.hSharedMem) {
        // Runtime not running - try to start it
        // For now, return error
        wcscpy_s(g_sib.lastError, L"Runtime not running. Start SovereignRuntime.exe first.");
        return SIB_ERROR_NOT_INITIALIZED;
    }
    
    // Map view
    g_sib.pSharedBlock = (RawrXD::Runtime::SovereignSharedBlock*)MapViewOfFile(
        g_sib.hSharedMem,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(RawrXD::Runtime::SovereignSharedBlock)
    );
    
    if (!g_sib.pSharedBlock) {
        wcscpy_s(g_sib.lastError, L"Failed to map shared memory view");
        CloseHandle(g_sib.hSharedMem);
        g_sib.hSharedMem = NULL;
        return SIB_ERROR_MEMORY;
    }
    
    // Open events
    g_sib.hRequestEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, 
                                      FALSE, L"RawrXD_RequestEvent");
    g_sib.hResponseEvent = OpenEventW(SYNCHRONIZE, FALSE, L"RawrXD_ResponseEvent");
    
    if (!g_sib.hRequestEvent || !g_sib.hResponseEvent) {
        wcscpy_s(g_sib.lastError, L"Failed to open synchronization events");
        UnmapViewOfFile(g_sib.pSharedBlock);
        CloseHandle(g_sib.hSharedMem);
        return SIB_ERROR_NOT_INITIALIZED;
    }
    
    // Start worker thread
    g_sib.workerRunning = TRUE;
    g_sib.hWorkerThread = CreateThread(NULL, 0, SIB_WorkerThread, NULL, 0, NULL);
    
    if (!g_sib.hWorkerThread) {
        wcscpy_s(g_sib.lastError, L"Failed to create worker thread");
        g_sib.workerRunning = FALSE;
        return SIB_ERROR_MEMORY;
    }
    
    g_sib.initialized = TRUE;
    return SIB_OK;
}

void SIB_Shutdown(void) {
    if (!g_sib.initialized) return;
    
    // Stop worker
    g_sib.workerRunning = FALSE;
    if (g_sib.hWorkerThread) {
        WaitForSingleObject(g_sib.hWorkerThread, 1000);
        CloseHandle(g_sib.hWorkerThread);
    }
    
    // Cleanup shared memory
    if (g_sib.pSharedBlock) {
        UnmapViewOfFile(g_sib.pSharedBlock);
    }
    if (g_sib.hSharedMem) {
        CloseHandle(g_sib.hSharedMem);
    }
    if (g_sib.hRequestEvent) {
        CloseHandle(g_sib.hRequestEvent);
    }
    if (g_sib.hResponseEvent) {
        CloseHandle(g_sib.hResponseEvent);
    }
    
    ZeroMemory(&g_sib, sizeof(g_sib));
}

BOOL SIB_IsReady(void) {
    return g_sib.initialized && g_sib.modelLoaded;
}

/*===========================================================================
 * MODEL MANAGEMENT
 *=========================================================================*/

SIB_Status SIB_LoadModel(const WCHAR* ggufPath, SIB_ModelInfo* outInfo) {
    if (!g_sib.initialized) {
        return SIB_ERROR_NOT_INITIALIZED;
    }
    
    // For now, simulate model load
    // In real implementation, would send load request to runtime
    
    ZeroMemory(&g_sib.modelInfo, sizeof(g_sib.modelInfo));
    wcscpy_s(g_sib.modelInfo.name, L"Deep2-7B-Q4_K_M");
    wcscpy_s(g_sib.modelInfo.path, ggufPath);
    g_sib.modelInfo.contextLength = 32768;
    g_sib.modelInfo.vocabSize = 32000;
    g_sib.modelInfo.numLayers = 32;
    g_sib.modelInfo.hiddenDim = 4096;
    g_sib.modelInfo.numExperts = 8;
    g_sib.modelInfo.expertsPerToken = 2;
    g_sib.modelInfo.totalParams = 7000000000ULL;
    g_sib.modelInfo.fileSizeBytes = 4200000000ULL;
    g_sib.modelInfo.isLoaded = TRUE;
    g_sib.modelInfo.isQuantized = TRUE;
    g_sib.modelInfo.quantizationBits = 4;
    
    g_sib.modelLoaded = TRUE;
    
    if (outInfo) {
        memcpy(outInfo, &g_sib.modelInfo, sizeof(SIB_ModelInfo));
    }
    
    return SIB_OK;
}

void SIB_UnloadModel(void) {
    g_sib.modelLoaded = FALSE;
    ZeroMemory(&g_sib.modelInfo, sizeof(g_sib.modelInfo));
}

BOOL SIB_GetModelInfo(SIB_ModelInfo* outInfo) {
    if (!g_sib.modelLoaded || !outInfo) return FALSE;
    memcpy(outInfo, &g_sib.modelInfo, sizeof(SIB_ModelInfo));
    return TRUE;
}

BOOL SIB_IsModelLoaded(void) {
    return g_sib.modelLoaded;
}

/*===========================================================================
 * INFERENCE
 *=========================================================================*/

SIB_Status SIB_RequestCompletion(
    const SIB_CompletionRequest* request,
    SIB_TokenCallback callback) {
    
    if (!g_sib.initialized) return SIB_ERROR_NOT_INITIALIZED;
    if (!g_sib.modelLoaded) return SIB_ERROR_MODEL_NOT_LOADED;
    if (!request || !callback) return SIB_ERROR_INVALID_PARAM;
    if (g_sib.inferencing) return SIB_ERROR_INFERENCE_FAILED;
    
    if (!g_sib.pSharedBlock) return SIB_ERROR_MEMORY;
    
    // Wait for any pending request to complete
    int retries = 100;
    while (g_sib.pSharedBlock->requestReady.load() == 1 && retries-- > 0) {
        Sleep(1);
    }
    
    if (g_sib.pSharedBlock->requestReady.load() == 1) {
        return SIB_ERROR_TIMEOUT;
    }
    
    // Prepare request
    RawrXD::Runtime::SovereignRequest sreq = {};
    sreq.requestId = GetTickCount64();
    sreq.timestamp = GetTickCount64();
    
    // Convert prompt to UTF-8
    char promptUtf8[4096];
    WideCharToMultiByte(CP_UTF8, 0, request->prompt, -1,
                       promptUtf8, sizeof(promptUtf8), NULL, NULL);
    strncpy_s(sreq.prompt, sizeof(sreq.prompt), promptUtf8, _TRUNCATE);
    
    sreq.maxTokens = request->maxTokens;
    sreq.temperature = request->temperature;
    sreq.topP = request->topP;
    sreq.topK = request->topK;
    sreq.stream = request->streamTokens;
    
    // Store callback
    g_sib.currentCallback = callback;
    g_sib.currentUserData = request->userData;
    g_sib.inferencing = TRUE;
    
    // Submit request
    g_sib.pSharedBlock->request = sreq;
    g_sib.pSharedBlock->requestReady.store(1);
    
    // Signal runtime
    SetEvent(g_sib.hRequestEvent);
    
    return SIB_OK;
}

void SIB_CancelCompletion(void) {
    g_sib.inferencing = FALSE;
    g_sib.currentCallback = NULL;
    
    if (g_sib.pSharedBlock) {
        g_sib.pSharedBlock->requestReady.store(0);
    }
}

BOOL SIB_IsInferencing(void) {
    return g_sib.inferencing;
}

/*===========================================================================
 * UTILITY
 *=========================================================================*/

const WCHAR* SIB_GetLastError(void) {
    return g_sib.lastError[0] ? g_sib.lastError : L"No error";
}

const WCHAR* SIB_GetVersion(void) {
    return L"SovereignInferenceBridge v2.0 (Shared Memory)";
}

void SIB_FormatModelSize(
    const SIB_ModelInfo* info,
    WCHAR* outBuffer,
    size_t bufferSize) {
    
    if (!info || !outBuffer || bufferSize == 0) return;
    
    double paramsB = info->totalParams / 1e9;
    double sizeGB = info->fileSizeBytes / (1024.0 * 1024.0 * 1024.0);
    
    swprintf_s(outBuffer, bufferSize, L"%.1fB params, %.1f GB (%u-bit)",
               paramsB, sizeGB, info->quantizationBits);
}

uint32_t SIB_EstimateTokens(const WCHAR* text) {
    if (!text) return 0;
    // Rough estimate: ~4 chars per token
    return (uint32_t)(wcslen(text) / 4);
}

/*===========================================================================
 * UI INTEGRATION
 *=========================================================================*/

BOOL SIB_PostTokenToUI(
    HWND hWndTarget,
    UINT msg,
    const WCHAR* token,
    BOOL isComplete) {
    
    if (!hWndTarget || !token) return FALSE;
    
    // Copy token to heap for async delivery
    size_t len = (wcslen(token) + 1) * sizeof(WCHAR);
    WCHAR* copy = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, len);
    if (!copy) return FALSE;
    
    memcpy(copy, token, len);
    
    return PostMessageW(hWndTarget, msg, (WPARAM)copy, (LPARAM)isComplete);
}
