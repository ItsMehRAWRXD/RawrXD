// SidebarStagingPanel.cpp - Production Implementation
// Provides sidebar staging panel for IDE file staging and review
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_STAGED_ITEMS    256
#define MAX_ITEM_PATH       256

enum StagedState {
    STAGED_UNCHANGED = 0,
    STAGED_ADDED,
    STAGED_MODIFIED,
    STAGED_DELETED,
    STAGED_RENAMED
};

struct StagedItem {
    volatile LONG active;
    uint32_t itemId;
    char path[MAX_ITEM_PATH];
    StagedState state;
    uint32_t selected;
    uint64_t timestamp;
};

static volatile LONG g_initialized = 0;
static StagedItem g_items[MAX_STAGED_ITEMS];
static volatile LONG g_nextItemId = 1;
static volatile LONG g_stagedCount = 0;

extern "C" __declspec(dllexport) int SidebarStagingPanel_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextItemId, 1);
    InterlockedExchange(&g_stagedCount, 0);
    memset(g_items, 0, sizeof(g_items));
    return 1;
}

extern "C" __declspec(dllexport) int SidebarStagingPanel_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int SidebarStagingPanel_StageItem(const char* path, int state, uint32_t* outItemId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!path || !outItemId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_STAGED_ITEMS; ++i) {
        if (InterlockedCompareExchange(&g_items[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    StagedItem* item = &g_items[slot];
    item->itemId = InterlockedIncrement(&g_nextItemId);
    size_t len = strlen(path);
    if (len >= MAX_ITEM_PATH) len = MAX_ITEM_PATH - 1;
    memcpy(item->path, path, len);
    item->path[len] = 0;
    item->state = static_cast<StagedState>(state);
    item->selected = 0;
    item->timestamp = GetTickCount64();
    InterlockedExchange(&item->active, 1);
    InterlockedIncrement(&g_stagedCount);
    *outItemId = item->itemId;
    return 1;
}

extern "C" __declspec(dllexport) int SidebarStagingPanel_UnstageItem(uint32_t itemId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_STAGED_ITEMS; ++i) {
        if (InterlockedCompareExchange(&g_items[i].active, 0, 0) == 1 && g_items[i].itemId == itemId) {
            InterlockedExchange(&g_items[i].active, 0);
            InterlockedDecrement(&g_stagedCount);
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int SidebarStagingPanel_SetSelected(uint32_t itemId, uint32_t selected) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_STAGED_ITEMS; ++i) {
        if (InterlockedCompareExchange(&g_items[i].active, 0, 0) == 1 && g_items[i].itemId == itemId) {
            g_items[i].selected = selected ? 1 : 0;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int SidebarStagingPanel_GetItemInfo(uint32_t itemId, char* outPath, uint32_t maxLen, int* outState, uint32_t* outSelected) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_STAGED_ITEMS; ++i) {
        if (InterlockedCompareExchange(&g_items[i].active, 0, 0) == 1 && g_items[i].itemId == itemId) {
            if (outPath) {
                size_t len = strlen(g_items[i].path);
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outPath, g_items[i].path, len);
                outPath[len] = 0;
            }
            if (outState) *outState = static_cast<int>(g_items[i].state);
            if (outSelected) *outSelected = g_items[i].selected;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int SidebarStagingPanel_GetStagedCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_stagedCount, 0, 0));
}

extern "C" __declspec(dllexport) int SidebarStagingPanel_ClearAll() {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_STAGED_ITEMS; ++i) {
        InterlockedExchange(&g_items[i].active, 0);
    }
    InterlockedExchange(&g_stagedCount, 0);
    return 1;
}
