/*===========================================================================
 * WarmupEngine.cpp
 * Memory Pre-faulting Engine Implementation
 * 
 * Keeps model weights "hot" in physical RAM by pre-touching memory-mapped pages
 * Uses multi-threaded sequential access to maximize throughput
 *===========================================================================*/

#include "WarmupEngine.h"
#include <cstring>
#include <algorithm>
#include <chrono>

/*===========================================================================
 * INTERNAL STATE
 *=========================================================================*/
typedef struct WarmupContext {
    std::atomic<BOOL>       running{FALSE};
    std::atomic<BOOL>       cancelled{FALSE};
    std::atomic<float>      progress{0.0f};
    std::atomic<uint64_t>   bytesWarmed{0};
    uint64_t                totalBytes{0};
    void*                   baseAddress{nullptr};
    WarmupConfig            config{};
    WarmupProgressCallback  progressCb{nullptr};
    WarmupCompleteCallback  completeCb{nullptr};
    HANDLE                  hThread{nullptr};
    std::chrono::steady_clock::time_point startTime;
    WCHAR                   lastError[512]{};
} WarmupContext;

static WarmupContext g_Warmup = {};
static std::atomic<BOOL> g_Initialized{FALSE};

/*===========================================================================
 * HELPER FUNCTIONS
 *=========================================================================*/

static void SetLastError(const WCHAR* msg) {
    wcsncpy_s(g_Warmup.lastError, msg, 511);
}

static DWORD WINAPI WarmupThreadProc(LPVOID param) {
    (void)param; // Unused
    
    if (!g_Warmup.baseAddress || g_Warmup.totalBytes == 0) {
        SetLastError(L"Invalid warmup parameters");
        if (g_Warmup.completeCb) {
            g_Warmup.completeCb(WARMUP_ERROR_INVALID_PARAMS, 0, 0.0, g_Warmup.config.userData);
        }
        g_Warmup.running = FALSE;
        return 1;
    }

    uint8_t* base = static_cast<uint8_t*>(g_Warmup.baseAddress);
    uint64_t total = g_Warmup.totalBytes;
    uint32_t chunkSize = g_Warmup.config.chunkSize;
    
    if (chunkSize == 0) {
        chunkSize = WARMUP_CHUNK_SIZE;
    }
    
    // Ensure chunk size is reasonable
    if (chunkSize > total) {
        chunkSize = static_cast<uint32_t>(std::min<uint64_t>(total, WARMUP_CHUNK_SIZE));
    }
    
    auto start = std::chrono::steady_clock::now();
    g_Warmup.startTime = start;
    
    uint64_t warmed = 0;
    volatile uint8_t dummy = 0; // Force read, prevent optimization
    
    if (g_Warmup.config.sequentialOnly) {
        // Sequential scan - best for HDD/SATA SSD
        for (uint64_t offset = 0; offset < total && !g_Warmup.cancelled; offset += chunkSize) {
            uint64_t remaining = total - offset;
            uint32_t currentChunk = static_cast<uint32_t>(std::min<uint64_t>(chunkSize, remaining));
            
            // Touch each page in the chunk
            for (uint32_t i = 0; i < currentChunk; i += 4096) {
                dummy += base[offset + i];
            }
            
            warmed += currentChunk;
            g_Warmup.bytesWarmed = warmed;
            
            float pct = (static_cast<float>(warmed) / static_cast<float>(total)) * 100.0f;
            g_Warmup.progress = pct;
            
            if (g_Warmup.progressCb) {
                g_Warmup.progressCb(warmed, total, pct, g_Warmup.config.userData);
            }
            
            // Yield to prevent starving other threads
            if ((offset / chunkSize) % 4 == 0) {
                Sleep(1);
            }
        }
    } else {
        // Interleaved scan - better for NVMe with multiple queues
        uint32_t numThreads = g_Warmup.config.numThreads;
        if (numThreads == 0) numThreads = WARMUP_DEFAULT_THREADS;
        
        uint64_t stride = total / numThreads;
        
        #pragma omp parallel for num_threads(numThreads) reduction(+:warmed)
        for (uint32_t thread = 0; thread < numThreads; ++thread) {
            uint64_t startOffset = thread * stride;
            uint64_t endOffset = (thread == numThreads - 1) ? total : (thread + 1) * stride;
            
            for (uint64_t offset = startOffset; offset < endOffset && !g_Warmup.cancelled; offset += chunkSize) {
                uint64_t remaining = endOffset - offset;
                uint32_t currentChunk = static_cast<uint32_t>(std::min<uint64_t>(chunkSize, remaining));
                
                for (uint32_t i = 0; i < currentChunk; i += 4096) {
                    dummy += base[offset + i];
                }
                
                warmed += currentChunk;
                g_Warmup.bytesWarmed = warmed;
                
                float pct = (static_cast<float>(warmed) / static_cast<float>(total)) * 100.0f;
                g_Warmup.progress = pct;
                
                if (g_Warmup.progressCb && (offset - startOffset) % (chunkSize * 4) == 0) {
                    g_Warmup.progressCb(warmed, total, pct, g_Warmup.config.userData);
                }
            }
        }
    }
    
    (void)dummy; // Prevent unused variable warning
    
    auto end = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();
    
    WarmupStatus status = g_Warmup.cancelled ? WARMUP_ERROR_CANCELLED : WARMUP_OK;
    
    if (g_Warmup.completeCb) {
        g_Warmup.completeCb(status, warmed, elapsed, g_Warmup.config.userData);
    }
    
    g_Warmup.running = FALSE;
    return (status == WARMUP_OK) ? 0 : 1;
}

/*===========================================================================
 * LIFECYCLE IMPLEMENTATION
 *===========================================================================*/

WarmupStatus WarmupEngine_Initialize(void) {
    if (g_Initialized) {
        return WARMUP_OK;
    }
    
    ZeroMemory(&g_Warmup, sizeof(g_Warmup));
    g_Initialized = TRUE;
    
    return WARMUP_OK;
}

void WarmupEngine_Shutdown(void) {
    if (!g_Initialized) {
        return;
    }
    
    WarmupEngine_Cancel();
    WarmupEngine_WaitForComplete(5000);
    
    ZeroMemory(&g_Warmup, sizeof(g_Warmup));
    g_Initialized = FALSE;
}

BOOL WarmupEngine_IsReady(void) {
    return g_Initialized;
}

/*===========================================================================
 * WARMUP OPERATIONS
 *===========================================================================*/

WarmupStatus WarmupEngine_Start(
    void* baseAddress,
    uint64_t sizeBytes,
    const WarmupConfig* config,
    WarmupProgressCallback progressCb,
    WarmupCompleteCallback completeCb) {
    
    if (!g_Initialized) {
        return WARMUP_ERROR_NOT_INITIALIZED;
    }
    
    if (g_Warmup.running) {
        return WARMUP_ERROR_ALREADY_RUNNING;
    }
    
    if (!baseAddress || sizeBytes == 0) {
        return WARMUP_ERROR_INVALID_PARAMS;
    }
    
    // Reset state
    g_Warmup.cancelled = FALSE;
    g_Warmup.progress = 0.0f;
    g_Warmup.bytesWarmed = 0;
    g_Warmup.totalBytes = sizeBytes;
    g_Warmup.baseAddress = baseAddress;
    g_Warmup.progressCb = progressCb;
    g_Warmup.completeCb = completeCb;
    
    if (config) {
        CopyMemory(&g_Warmup.config, config, sizeof(WarmupConfig));
    } else {
        // Default config
        g_Warmup.config.numThreads = WARMUP_DEFAULT_THREADS;
        g_Warmup.config.chunkSize = WARMUP_CHUNK_SIZE;
        g_Warmup.config.sequentialOnly = FALSE;
        g_Warmup.config.cancelOnInference = TRUE;
    }
    
    g_Warmup.running = TRUE;
    
    // Start warmup thread
    g_Warmup.hThread = CreateThread(
        nullptr,
        0,
        WarmupThreadProc,
        nullptr,
        0,
        nullptr
    );
    
    if (!g_Warmup.hThread) {
        g_Warmup.running = FALSE;
        SetLastError(L"Failed to create warmup thread");
        return WARMUP_ERROR_MEMORY_ACCESS;
    }
    
    // Set thread priority if specified
    if (g_Warmup.config.priorityClass) {
        SetThreadPriority(g_Warmup.hThread, g_Warmup.config.priorityClass);
    }
    
    return WARMUP_OK;
}

void WarmupEngine_Cancel(void) {
    if (!g_Initialized || !g_Warmup.running) {
        return;
    }
    
    g_Warmup.cancelled = TRUE;
}

BOOL WarmupEngine_IsRunning(void) {
    return g_Initialized && g_Warmup.running;
}

float WarmupEngine_GetProgress(void) {
    if (!g_Initialized) {
        return 0.0f;
    }
    return g_Warmup.progress;
}

BOOL WarmupEngine_WaitForComplete(uint32_t timeoutMs) {
    if (!g_Initialized || !g_Warmup.hThread) {
        return TRUE;
    }
    
    DWORD result = WaitForSingleObject(g_Warmup.hThread, timeoutMs);
    
    if (result == WAIT_OBJECT_0) {
        CloseHandle(g_Warmup.hThread);
        g_Warmup.hThread = nullptr;
        return TRUE;
    }
    
    return FALSE;
}

/*===========================================================================
 * UTILITY FUNCTIONS
 *===========================================================================*/

const WCHAR* WarmupEngine_GetLastError(void) {
    return g_Warmup.lastError[0] ? g_Warmup.lastError : L"No error";
}

const WCHAR* WarmupEngine_GetVersion(void) {
    return L"WarmupEngine v1.0";
}

uint32_t WarmupEngine_CalculateOptimalChunkSize(uint64_t modelSize) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    // Use allocation granularity as base
    uint32_t pageSize = static_cast<uint32_t>(sysInfo.dwAllocationGranularity);
    if (pageSize == 0) pageSize = 4096;
    
    // For large models, use larger chunks
    if (modelSize > 100ULL * 1024 * 1024 * 1024) { // >100GB
        return 256 * 1024 * 1024; // 256MB
    } else if (modelSize > 10ULL * 1024 * 1024 * 1024) { // >10GB
        return 64 * 1024 * 1024; // 64MB
    } else {
        return 16 * 1024 * 1024; // 16MB
    }
}

double WarmupEngine_EstimateTime(uint64_t modelSizeBytes, uint32_t storageType) {
    // Rough estimates based on storage type
    double mbPerSecond;
    
    switch (storageType) {
        case 0: // HDD
            mbPerSecond = 150.0;
            break;
        case 1: // SATA SSD
            mbPerSecond = 500.0;
            break;
        case 2: // NVMe
            mbPerSecond = 3000.0;
            break;
        case 3: // Optane
            mbPerSecond = 8000.0;
            break;
        default:
            mbPerSecond = 500.0;
    }
    
    double sizeMB = static_cast<double>(modelSizeBytes) / (1024.0 * 1024.0);
    return sizeMB / mbPerSecond;
}

/*===========================================================================
 * INTEGRATION HELPERS
 *===========================================================================*/

WarmupStatus WarmupEngine_WarmupFile(HANDLE hFile, const WarmupConfig* config) {
    if (!g_Initialized || hFile == INVALID_HANDLE_VALUE) {
        return WARMUP_ERROR_INVALID_PARAMS;
    }
    
    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        SetLastError(L"Failed to get file size");
        return WARMUP_ERROR_INVALID_PARAMS;
    }
    
    // Create file mapping
    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        SetLastError(L"Failed to create file mapping");
        return WARMUP_ERROR_MEMORY_ACCESS;
    }
    
    // Map view
    void* baseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!baseAddress) {
        CloseHandle(hMapping);
        SetLastError(L"Failed to map view of file");
        return WARMUP_ERROR_MEMORY_ACCESS;
    }
    
    // Start warmup
    WarmupStatus status = WarmupEngine_Start(baseAddress, fileSize.QuadPart, config, nullptr, nullptr);
    
    if (status == WARMUP_OK) {
        // Wait for completion
        WarmupEngine_WaitForComplete(0);
    }
    
    // Cleanup
    UnmapViewOfFile(baseAddress);
    CloseHandle(hMapping);
    
    return status;
}

WarmupStatus WarmupEngine_WarmupAsync(void* baseAddress, uint64_t sizeBytes, WarmupProgressCallback progressCb) {
    WarmupConfig config = {};
    config.numThreads = WARMUP_DEFAULT_THREADS;
    config.chunkSize = WarmupEngine_CalculateOptimalChunkSize(sizeBytes);
    config.sequentialOnly = FALSE;
    config.cancelOnInference = TRUE;
    
    return WarmupEngine_Start(baseAddress, sizeBytes, &config, progressCb, nullptr);
}

/* E> End of WarmupEngine.cpp <3 */
