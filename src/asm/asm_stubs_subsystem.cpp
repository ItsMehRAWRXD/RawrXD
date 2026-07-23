// asm_stubs_subsystem.cpp - Stub implementations for rawrxd_subsystem_api exports

#include <cstdint>
#include <cstddef>

extern "C" {

// Audio Decoder stubs
int AD_ProcessGGUF(void* ctx, const char* ggufPath) {
    (void)ctx; (void)ggufPath;
    return -1;  // Not implemented
}

// Sovereign Orchestrator stubs
int SO_LoadExecFile(const char* path, void** outHandle) {
    (void)path; (void)outHandle;
    return -1;  // Not implemented
}

int SO_InitializeVulkan(void* ctx) {
    (void)ctx;
    return -1;  // Not implemented
}

void* SO_CreateMemoryArena(size_t size) {
    (void)size;
    return nullptr;  // Not implemented
}

int SO_CreateComputePipelines(void* ctx) {
    (void)ctx;
    return -1;  // Not implemented
}

void SO_PrintStatistics(void* ctx) {
    (void)ctx;
    // No-op stub
}

int SO_InitializeStreaming(void* ctx) {
    (void)ctx;
    return -1;  // Not implemented
}

void* SO_CreateThreadPool(uint32_t numThreads) {
    (void)numThreads;
    return nullptr;  // Not implemented
}

int SO_StartDEFLATEThreads(void* pool) {
    (void)pool;
    return -1;  // Not implemented
}

int SO_InitializePrefetchQueue(void* ctx, size_t capacity) {
    (void)ctx; (void)capacity;
    return -1;  // Not implemented
}

void SO_PrintMetrics(void* ctx) {
    (void)ctx;
    // No-op stub
}

} // extern "C"
