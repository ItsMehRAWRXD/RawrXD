// agent_cursor_renderer.cpp - Production Implementation
// Provides agent cursor rendering and animation for IDE overlay
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_CURSORS     16
#define CURSOR_SIZE     32

struct AgentCursor {
    volatile LONG active;
    uint32_t cursorId;
    int32_t x;
    int32_t y;
    uint32_t color;
    uint32_t visible;
    uint64_t lastUpdate;
    char label[32];
};

static volatile LONG g_initialized = 0;
static AgentCursor g_cursors[MAX_CURSORS];
static volatile LONG g_nextCursorId = 1;

extern "C" __declspec(dllexport) int agent_cursor_renderer_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextCursorId, 1);
    memset(g_cursors, 0, sizeof(g_cursors));
    return 1;
}

extern "C" __declspec(dllexport) int agent_cursor_renderer_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int agent_cursor_renderer_CreateCursor(const char* label, uint32_t color, uint32_t* outCursorId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!label || !outCursorId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_CURSORS; ++i) {
        if (InterlockedCompareExchange(&g_cursors[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    AgentCursor* cur = &g_cursors[slot];
    cur->cursorId = InterlockedIncrement(&g_nextCursorId);
    size_t len = strlen(label);
    if (len >= 32) len = 31;
    memcpy(cur->label, label, len);
    cur->label[len] = 0;
    cur->x = 0;
    cur->y = 0;
    cur->color = color;
    cur->visible = 1;
    cur->lastUpdate = GetTickCount64();
    InterlockedExchange(&cur->active, 1);
    *outCursorId = cur->cursorId;
    return 1;
}

extern "C" __declspec(dllexport) int agent_cursor_renderer_MoveCursor(uint32_t cursorId, int32_t x, int32_t y) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_CURSORS; ++i) {
        if (InterlockedCompareExchange(&g_cursors[i].active, 0, 0) == 1 && g_cursors[i].cursorId == cursorId) {
            g_cursors[i].x = x;
            g_cursors[i].y = y;
            g_cursors[i].lastUpdate = GetTickCount64();
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int agent_cursor_renderer_SetVisibility(uint32_t cursorId, uint32_t visible) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_CURSORS; ++i) {
        if (InterlockedCompareExchange(&g_cursors[i].active, 0, 0) == 1 && g_cursors[i].cursorId == cursorId) {
            g_cursors[i].visible = visible ? 1 : 0;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int agent_cursor_renderer_GetCursorPos(uint32_t cursorId, int32_t* outX, int32_t* outY) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_CURSORS; ++i) {
        if (InterlockedCompareExchange(&g_cursors[i].active, 0, 0) == 1 && g_cursors[i].cursorId == cursorId) {
            if (outX) *outX = g_cursors[i].x;
            if (outY) *outY = g_cursors[i].y;
            return 1;
        }
    }
    return 0;
}
