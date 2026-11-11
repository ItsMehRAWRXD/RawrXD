// ============================================================================
// subsystem_api_stubs.cpp - Stub implementations for subsystem API functions
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" {

// AD (Advanced Decompression) functions
bool AD_ProcessGGUF(const char* path, void* outData, size_t* outSize) {
    (void)path;
    (void)outData;
    (void)outSize;
    OutputDebugStringA("[AD] AD_ProcessGGUF stub called\n");
    return false;
}

// SO (Sovereign) functions
bool SO_LoadExecFile(const char* path) {
    (void)path;
    OutputDebugStringA("[SO] SO_LoadExecFile stub called\n");
    return false;
}

bool SO_InitializeVulkan() {
    OutputDebugStringA("[SO] SO_InitializeVulkan stub called\n");
    return false;
}

void* SO_CreateMemoryArena(size_t size) {
    (void)size;
    OutputDebugStringA("[SO] SO_CreateMemoryArena stub called\n");
    return nullptr;
}

bool SO_CreateComputePipelines() {
    OutputDebugStringA("[SO] SO_CreateComputePipelines stub called\n");
    return false;
}

void SO_PrintStatistics() {
    OutputDebugStringA("[SO] SO_PrintStatistics stub called\n");
}

bool SO_InitializeStreaming() {
    OutputDebugStringA("[SO] SO_InitializeStreaming stub called\n");
    return false;
}

void* SO_CreateThreadPool(int threads) {
    (void)threads;
    OutputDebugStringA("[SO] SO_CreateThreadPool stub called\n");
    return nullptr;
}

bool SO_StartDEFLATEThreads() {
    OutputDebugStringA("[SO] SO_StartDEFLATEThreads stub called\n");
    return false;
}

void* SO_InitializePrefetchQueue() {
    OutputDebugStringA("[SO] SO_InitializePrefetchQueue stub called\n");
    return nullptr;
}

void SO_PrintMetrics() {
    OutputDebugStringA("[SO] SO_PrintMetrics stub called\n");
}

} // extern "C"
