// rawrxd_workspace_matrix.cpp - Production Implementation
// Provides workspace layout matrix for IDE pane management
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_PANES       32
#define MAX_PANE_NAME   64

struct PaneEntry {
    volatile LONG active;
    uint32_t paneId;
    char name[MAX_PANE_NAME];
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
    uint32_t visible;
    uint32_t zOrder;
};

static volatile LONG g_initialized = 0;
static PaneEntry g_panes[MAX_PANES];
static volatile LONG g_nextPaneId = 1;
static volatile LONG g_visibleCount = 0;

extern "C" __declspec(dllexport) int rawrxd_workspace_matrix_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextPaneId, 1);
    InterlockedExchange(&g_visibleCount, 0);
    memset(g_panes, 0, sizeof(g_panes));
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_workspace_matrix_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_workspace_matrix_CreatePane(const char* name, int32_t x, int32_t y, int32_t w, int32_t h, uint32_t* outPaneId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outPaneId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_PANES; ++i) {
        if (InterlockedCompareExchange(&g_panes[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    PaneEntry* pane = &g_panes[slot];
    pane->paneId = InterlockedIncrement(&g_nextPaneId);
    size_t len = strlen(name);
    if (len >= MAX_PANE_NAME) len = MAX_PANE_NAME - 1;
    memcpy(pane->name, name, len);
    pane->name[len] = 0;
    pane->x = x;
    pane->y = y;
    pane->width = w;
    pane->height = h;
    pane->visible = 1;
    pane->zOrder = static_cast<uint32_t>(slot);
    InterlockedExchange(&pane->active, 1);
    InterlockedIncrement(&g_visibleCount);
    *outPaneId = pane->paneId;
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_workspace_matrix_MovePane(uint32_t paneId, int32_t x, int32_t y) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_PANES; ++i) {
        if (InterlockedCompareExchange(&g_panes[i].active, 0, 0) == 1 && g_panes[i].paneId == paneId) {
            g_panes[i].x = x;
            g_panes[i].y = y;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_workspace_matrix_ResizePane(uint32_t paneId, int32_t w, int32_t h) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_PANES; ++i) {
        if (InterlockedCompareExchange(&g_panes[i].active, 0, 0) == 1 && g_panes[i].paneId == paneId) {
            g_panes[i].width = w;
            g_panes[i].height = h;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_workspace_matrix_SetVisibility(uint32_t paneId, uint32_t visible) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_PANES; ++i) {
        if (InterlockedCompareExchange(&g_panes[i].active, 0, 0) == 1 && g_panes[i].paneId == paneId) {
            uint32_t oldVis = g_panes[i].visible;
            g_panes[i].visible = visible ? 1 : 0;
            if (oldVis == 0 && visible) InterlockedIncrement(&g_visibleCount);
            if (oldVis == 1 && !visible) InterlockedDecrement(&g_visibleCount);
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_workspace_matrix_GetPaneRect(uint32_t paneId, int32_t* outX, int32_t* outY, int32_t* outW, int32_t* outH) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_PANES; ++i) {
        if (InterlockedCompareExchange(&g_panes[i].active, 0, 0) == 1 && g_panes[i].paneId == paneId) {
            if (outX) *outX = g_panes[i].x;
            if (outY) *outY = g_panes[i].y;
            if (outW) *outW = g_panes[i].width;
            if (outH) *outH = g_panes[i].height;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_workspace_matrix_GetVisibleCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_visibleCount, 0, 0));
}
