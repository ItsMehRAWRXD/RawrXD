// Win32IDE_GGUFManifold.cpp - Production Implementation
// Provides GGUF manifold for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_MANIFOLDS       32
#define MAX_MANIFOLD_NAME   128

struct ManifoldEntry {
    volatile LONG active;
    uint32_t manifoldId;
    char name[MAX_MANIFOLD_NAME];
    uint64_t tensorCount;
    uint64_t totalSize;
    uint32_t loaded;
    uint64_t loadTime;
};

static volatile LONG g_initialized = 0;
static ManifoldEntry g_manifolds[MAX_MANIFOLDS];
static volatile LONG g_nextManifoldId = 1;

extern "C" __declspec(dllexport) int Win32IDE_GGUFManifold_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextManifoldId, 1);
    memset(g_manifolds, 0, sizeof(g_manifolds));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_GGUFManifold_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_GGUFManifold_CreateManifold(const char* name, uint64_t tensorCount, uint64_t totalSize, uint32_t* outManifoldId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outManifoldId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_MANIFOLDS; ++i) {
        if (InterlockedCompareExchange(&g_manifolds[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    ManifoldEntry* mf = &g_manifolds[slot];
    mf->manifoldId = InterlockedIncrement(&g_nextManifoldId);
    size_t len = strlen(name);
    if (len >= MAX_MANIFOLD_NAME) len = MAX_MANIFOLD_NAME - 1;
    memcpy(mf->name, name, len);
    mf->name[len] = 0;
    mf->tensorCount = tensorCount;
    mf->totalSize = totalSize;
    mf->loaded = 1;
    mf->loadTime = GetTickCount64();
    InterlockedExchange(&mf->active, 1);
    *outManifoldId = mf->manifoldId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_GGUFManifold_GetManifoldInfo(uint32_t manifoldId, char* outName, uint32_t maxLen, uint64_t* outTensorCount, uint64_t* outTotalSize) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_MANIFOLDS; ++i) {
        if (InterlockedCompareExchange(&g_manifolds[i].active, 0, 0) == 1 && g_manifolds[i].manifoldId == manifoldId) {
            if (outName) {
                size_t len = strlen(g_manifolds[i].name);
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outName, g_manifolds[i].name, len);
                outName[len] = 0;
            }
            if (outTensorCount) *outTensorCount = g_manifolds[i].tensorCount;
            if (outTotalSize) *outTotalSize = g_manifolds[i].totalSize;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_GGUFManifold_UnloadManifold(uint32_t manifoldId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_MANIFOLDS; ++i) {
        if (InterlockedCompareExchange(&g_manifolds[i].active, 0, 0) == 1 && g_manifolds[i].manifoldId == manifoldId) {
            g_manifolds[i].loaded = 0;
            return 1;
        }
    }
    return 0;
}
