// collab_cursor_fallbacks.cpp — Production Collaboration Cursor Implementation
// Provides multi-user cursor tracking and presence for collaborative editing
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

// ============================================================================
// Cursor Position
// ============================================================================
#define MAX_USERS       16
#define MAX_USER_NAME   64
#define MAX_DOC_PATH    260

struct CursorPosition {
    volatile LONG active;
    uint32_t userId;
    char userName[MAX_USER_NAME];
    char docPath[MAX_DOC_PATH];
    uint32_t line;
    uint32_t column;
    uint32_t color;
    uint64_t lastUpdate;
};

// ============================================================================
// State
// ============================================================================
static volatile LONG g_initialized = 0;
static CursorPosition g_cursors[MAX_USERS];
static volatile LONG g_userCount = 0;

// ============================================================================
// Color Palette
// ============================================================================
static const uint32_t USER_COLORS[] = {
    0xFF0000, 0x00FF00, 0x0000FF, 0xFFFF00,
    0xFF00FF, 0x00FFFF, 0xFF8000, 0x8000FF,
    0x0080FF, 0xFF0080, 0x80FF00, 0x00FF80,
    0xFF4040, 0x40FF40, 0x4040FF, 0xFFFFFF
};

// ============================================================================
// Exported API
// ============================================================================
extern "C" __declspec(dllexport) int CollabCursor_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    
    InterlockedExchange(&g_userCount, 0);
    memset(g_cursors, 0, sizeof(g_cursors));
    
    return 1;
}

extern "C" __declspec(dllexport) int CollabCursor_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    
    for (int i = 0; i < MAX_USERS; ++i) {
        InterlockedExchange(&g_cursors[i].active, 0);
    }
    InterlockedExchange(&g_userCount, 0);
    
    return 0;
}

extern "C" __declspec(dllexport) int CollabCursor_RegisterUser(const char* userName, uint32_t* outUserId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!userName || !outUserId) return 0;
    
    int slot = -1;
    for (int i = 0; i < MAX_USERS; ++i) {
        if (InterlockedCompareExchange(&g_cursors[i].active, 0, 0) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return 0;
    
    CursorPosition* cursor = &g_cursors[slot];
    cursor->userId = slot + 1;
    size_t nameLen = strlen(userName);
    if (nameLen >= MAX_USER_NAME) nameLen = MAX_USER_NAME - 1;
    memcpy(cursor->userName, userName, nameLen);
    cursor->userName[nameLen] = 0;
    cursor->line = 1;
    cursor->column = 1;
    cursor->color = USER_COLORS[slot % (sizeof(USER_COLORS) / sizeof(USER_COLORS[0]))];
    cursor->lastUpdate = GetTickCount64();
    
    InterlockedExchange(&cursor->active, 1);
    InterlockedIncrement(&g_userCount);
    *outUserId = cursor->userId;
    
    return 1;
}

extern "C" __declspec(dllexport) int CollabCursor_UpdatePosition(uint32_t userId, const char* docPath, uint32_t line, uint32_t column) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    
    for (int i = 0; i < MAX_USERS; ++i) {
        if (InterlockedCompareExchange(&g_cursors[i].active, 0, 0) == 1 &&
            g_cursors[i].userId == userId) {
            if (docPath) {
                size_t pathLen = strlen(docPath);
                if (pathLen >= MAX_DOC_PATH) pathLen = MAX_DOC_PATH - 1;
                memcpy(g_cursors[i].docPath, docPath, pathLen);
                g_cursors[i].docPath[pathLen] = 0;
            }
            g_cursors[i].line = line;
            g_cursors[i].column = column;
            g_cursors[i].lastUpdate = GetTickCount64();
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int CollabCursor_GetUserCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_userCount, 0, 0));
}

extern "C" __declspec(dllexport) int CollabCursor_GetCursorInfo(uint32_t userId, char* outUserName, uint32_t* outLine, uint32_t* outColumn, uint32_t* outColor) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    
    for (int i = 0; i < MAX_USERS; ++i) {
        if (InterlockedCompareExchange(&g_cursors[i].active, 0, 0) == 1 &&
            g_cursors[i].userId == userId) {
            if (outUserName) strcpy_s(outUserName, MAX_USER_NAME, g_cursors[i].userName);
            if (outLine) *outLine = g_cursors[i].line;
            if (outColumn) *outColumn = g_cursors[i].column;
            if (outColor) *outColor = g_cursors[i].color;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) void CollabCursorFallbacksStub() {
    // Legacy symbol - now has real implementation above
}
