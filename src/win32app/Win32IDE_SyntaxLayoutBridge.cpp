// Win32IDE_SyntaxLayoutBridge.cpp - Production Implementation
// Provides syntax layout bridge for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_LAYOUTS     64
#define MAX_LAYOUT_NAME 128

struct LayoutEntry {
    volatile LONG active;
    uint32_t layoutId;
    char name[MAX_LAYOUT_NAME];
    uint32_t lineCount;
    uint32_t tokenCount;
    uint32_t foldLevel;
    uint32_t visible;
};

static volatile LONG g_initialized = 0;
static LayoutEntry g_layouts[MAX_LAYOUTS];
static volatile LONG g_nextLayoutId = 1;

extern "C" __declspec(dllexport) int Win32IDE_SyntaxLayoutBridge_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextLayoutId, 1);
    memset(g_layouts, 0, sizeof(g_layouts));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_SyntaxLayoutBridge_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_SyntaxLayoutBridge_CreateLayout(const char* name, uint32_t* outLayoutId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outLayoutId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_LAYOUTS; ++i) {
        if (InterlockedCompareExchange(&g_layouts[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    LayoutEntry* layout = &g_layouts[slot];
    layout->layoutId = InterlockedIncrement(&g_nextLayoutId);
    size_t len = strlen(name);
    if (len >= MAX_LAYOUT_NAME) len = MAX_LAYOUT_NAME - 1;
    memcpy(layout->name, name, len);
    layout->name[len] = 0;
    layout->lineCount = 0;
    layout->tokenCount = 0;
    layout->foldLevel = 0;
    layout->visible = 1;
    InterlockedExchange(&layout->active, 1);
    *outLayoutId = layout->layoutId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_SyntaxLayoutBridge_UpdateMetrics(uint32_t layoutId, uint32_t lineCount, uint32_t tokenCount, uint32_t foldLevel) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_LAYOUTS; ++i) {
        if (InterlockedCompareExchange(&g_layouts[i].active, 0, 0) == 1 && g_layouts[i].layoutId == layoutId) {
            g_layouts[i].lineCount = lineCount;
            g_layouts[i].tokenCount = tokenCount;
            g_layouts[i].foldLevel = foldLevel;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_SyntaxLayoutBridge_GetLayoutInfo(uint32_t layoutId, char* outName, uint32_t maxLen, uint32_t* outLineCount, uint32_t* outTokenCount, uint32_t* outFoldLevel) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_LAYOUTS; ++i) {
        if (InterlockedCompareExchange(&g_layouts[i].active, 0, 0) == 1 && g_layouts[i].layoutId == layoutId) {
            if (outName) {
                size_t len = strlen(g_layouts[i].name);
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outName, g_layouts[i].name, len);
                outName[len] = 0;
            }
            if (outLineCount) *outLineCount = g_layouts[i].lineCount;
            if (outTokenCount) *outTokenCount = g_layouts[i].tokenCount;
            if (outFoldLevel) *outFoldLevel = g_layouts[i].foldLevel;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_SyntaxLayoutBridge_SetVisibility(uint32_t layoutId, uint32_t visible) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_LAYOUTS; ++i) {
        if (InterlockedCompareExchange(&g_layouts[i].active, 0, 0) == 1 && g_layouts[i].layoutId == layoutId) {
            g_layouts[i].visible = visible ? 1 : 0;
            return 1;
        }
    }
    return 0;
}
