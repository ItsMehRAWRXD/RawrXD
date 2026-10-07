// Win32IDE_AgentCursorOverlay.cpp - Production Implementation
// Provides agent cursor overlay for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_OVERLAYS        16
#define MAX_OVERLAY_LABEL   64

struct OverlayEntry {
    volatile LONG active;
    uint32_t overlayId;
    int32_t x;
    int32_t y;
    uint32_t color;
    uint32_t visible;
    char label[MAX_OVERLAY_LABEL];
    uint64_t lastUpdate;
};

static volatile LONG g_initialized = 0;
static OverlayEntry g_overlays[MAX_OVERLAYS];
static volatile LONG g_nextOverlayId = 1;

extern "C" __declspec(dllexport) int Win32IDE_AgentCursorOverlay_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextOverlayId, 1);
    memset(g_overlays, 0, sizeof(g_overlays));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_AgentCursorOverlay_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_AgentCursorOverlay_CreateOverlay(const char* label, uint32_t color, uint32_t* outOverlayId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!label || !outOverlayId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_OVERLAYS; ++i) {
        if (InterlockedCompareExchange(&g_overlays[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    OverlayEntry* ov = &g_overlays[slot];
    ov->overlayId = InterlockedIncrement(&g_nextOverlayId);
    size_t len = strlen(label);
    if (len >= MAX_OVERLAY_LABEL) len = MAX_OVERLAY_LABEL - 1;
    memcpy(ov->label, label, len);
    ov->label[len] = 0;
    ov->x = 0;
    ov->y = 0;
    ov->color = color;
    ov->visible = 1;
    ov->lastUpdate = GetTickCount64();
    InterlockedExchange(&ov->active, 1);
    *outOverlayId = ov->overlayId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_AgentCursorOverlay_MoveOverlay(uint32_t overlayId, int32_t x, int32_t y) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_OVERLAYS; ++i) {
        if (InterlockedCompareExchange(&g_overlays[i].active, 0, 0) == 1 && g_overlays[i].overlayId == overlayId) {
            g_overlays[i].x = x;
            g_overlays[i].y = y;
            g_overlays[i].lastUpdate = GetTickCount64();
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_AgentCursorOverlay_SetVisibility(uint32_t overlayId, uint32_t visible) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_OVERLAYS; ++i) {
        if (InterlockedCompareExchange(&g_overlays[i].active, 0, 0) == 1 && g_overlays[i].overlayId == overlayId) {
            g_overlays[i].visible = visible ? 1 : 0;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_AgentCursorOverlay_GetOverlayPos(uint32_t overlayId, int32_t* outX, int32_t* outY) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_OVERLAYS; ++i) {
        if (InterlockedCompareExchange(&g_overlays[i].active, 0, 0) == 1 && g_overlays[i].overlayId == overlayId) {
            if (outX) *outX = g_overlays[i].x;
            if (outY) *outY = g_overlays[i].y;
            return 1;
        }
    }
    return 0;
}
