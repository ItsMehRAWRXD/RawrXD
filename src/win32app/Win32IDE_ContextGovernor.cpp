// Win32IDE_ContextGovernor.cpp - Production Implementation
// Provides context governor for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_CONTEXTS    32
#define MAX_CTX_NAME    64

struct ContextEntry {
    volatile LONG active;
    uint32_t ctxId;
    char name[MAX_CTX_NAME];
    uint32_t priority;
    uint64_t created;
    uint32_t active_flag;
    uint32_t refCount;
};

static volatile LONG g_initialized = 0;
static ContextEntry g_contexts[MAX_CONTEXTS];
static volatile LONG g_nextCtxId = 1;
static volatile LONG g_activeContexts = 0;

extern "C" __declspec(dllexport) int Win32IDE_ContextGovernor_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextCtxId, 1);
    InterlockedExchange(&g_activeContexts, 0);
    memset(g_contexts, 0, sizeof(g_contexts));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_ContextGovernor_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ContextGovernor_CreateContext(const char* name, uint32_t priority, uint32_t* outCtxId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outCtxId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_CONTEXTS; ++i) {
        if (InterlockedCompareExchange(&g_contexts[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    ContextEntry* ctx = &g_contexts[slot];
    ctx->ctxId = InterlockedIncrement(&g_nextCtxId);
    size_t len = strlen(name);
    if (len >= MAX_CTX_NAME) len = MAX_CTX_NAME - 1;
    memcpy(ctx->name, name, len);
    ctx->name[len] = 0;
    ctx->priority = priority;
    ctx->created = GetTickCount64();
    ctx->active_flag = 1;
    ctx->refCount = 1;
    InterlockedExchange(&ctx->active, 1);
    InterlockedIncrement(&g_activeContexts);
    *outCtxId = ctx->ctxId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_ContextGovernor_ActivateContext(uint32_t ctxId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_CONTEXTS; ++i) {
        if (InterlockedCompareExchange(&g_contexts[i].active, 0, 0) == 1 && g_contexts[i].ctxId == ctxId) {
            g_contexts[i].active_flag = 1;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ContextGovernor_DeactivateContext(uint32_t ctxId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_CONTEXTS; ++i) {
        if (InterlockedCompareExchange(&g_contexts[i].active, 0, 0) == 1 && g_contexts[i].ctxId == ctxId) {
            g_contexts[i].active_flag = 0;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ContextGovernor_AddRef(uint32_t ctxId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_CONTEXTS; ++i) {
        if (InterlockedCompareExchange(&g_contexts[i].active, 0, 0) == 1 && g_contexts[i].ctxId == ctxId) {
            InterlockedIncrement(&g_contexts[i].refCount);
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ContextGovernor_Release(uint32_t ctxId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_CONTEXTS; ++i) {
        if (InterlockedCompareExchange(&g_contexts[i].active, 0, 0) == 1 && g_contexts[i].ctxId == ctxId) {
            if (InterlockedDecrement(&g_contexts[i].refCount) == 0) {
                InterlockedExchange(&g_contexts[i].active, 0);
                InterlockedDecrement(&g_activeContexts);
            }
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ContextGovernor_GetActiveCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_activeContexts, 0, 0));
}
