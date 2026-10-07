// ExtensionEngine_bridge.cpp - Production Implementation
// Provides extension engine bridge for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_EXTENSIONS      64
#define MAX_EXT_NAME        128

struct ExtensionEntry {
    volatile LONG active;
    uint32_t extId;
    char name[MAX_EXT_NAME];
    uint32_t loaded;
    uint32_t enabled;
    uint64_t loadTime;
    uint32_t apiVersion;
};

static volatile LONG g_initialized = 0;
static ExtensionEntry g_extensions[MAX_EXTENSIONS];
static volatile LONG g_nextExtId = 1;
static volatile LONG g_loadedCount = 0;

extern "C" __declspec(dllexport) int ExtensionEngine_bridge_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextExtId, 1);
    InterlockedExchange(&g_loadedCount, 0);
    memset(g_extensions, 0, sizeof(g_extensions));
    return 1;
}

extern "C" __declspec(dllexport) int ExtensionEngine_bridge_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int ExtensionEngine_bridge_RegisterExtension(const char* name, uint32_t apiVersion, uint32_t* outExtId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outExtId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_EXTENSIONS; ++i) {
        if (InterlockedCompareExchange(&g_extensions[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    ExtensionEntry* ext = &g_extensions[slot];
    ext->extId = InterlockedIncrement(&g_nextExtId);
    size_t len = strlen(name);
    if (len >= MAX_EXT_NAME) len = MAX_EXT_NAME - 1;
    memcpy(ext->name, name, len);
    ext->name[len] = 0;
    ext->apiVersion = apiVersion;
    ext->loaded = 1;
    ext->enabled = 1;
    ext->loadTime = GetTickCount64();
    InterlockedExchange(&ext->active, 1);
    InterlockedIncrement(&g_loadedCount);
    *outExtId = ext->extId;
    return 1;
}

extern "C" __declspec(dllexport) int ExtensionEngine_bridge_EnableExtension(uint32_t extId, uint32_t enabled) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_EXTENSIONS; ++i) {
        if (InterlockedCompareExchange(&g_extensions[i].active, 0, 0) == 1 && g_extensions[i].extId == extId) {
            g_extensions[i].enabled = enabled ? 1 : 0;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int ExtensionEngine_bridge_GetExtensionInfo(uint32_t extId, char* outName, uint32_t maxLen, uint32_t* outApiVersion, uint32_t* outEnabled) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_EXTENSIONS; ++i) {
        if (InterlockedCompareExchange(&g_extensions[i].active, 0, 0) == 1 && g_extensions[i].extId == extId) {
            if (outName) {
                size_t len = strlen(g_extensions[i].name);
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outName, g_extensions[i].name, len);
                outName[len] = 0;
            }
            if (outApiVersion) *outApiVersion = g_extensions[i].apiVersion;
            if (outEnabled) *outEnabled = g_extensions[i].enabled;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int ExtensionEngine_bridge_GetLoadedCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_loadedCount, 0, 0));
}
