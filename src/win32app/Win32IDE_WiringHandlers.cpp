// Win32IDE_WiringHandlers.cpp - Production Implementation
// Provides wiring handlers for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_HANDLERS        128
#define MAX_HANDLER_NAME    64

enum HandlerType {
    HANDLER_EVENT = 0,
    HANDLER_COMMAND,
    HANDLER_NOTIFICATION,
    HANDLER_REQUEST
};

struct HandlerEntry {
    volatile LONG active;
    uint32_t handlerId;
    char name[MAX_HANDLER_NAME];
    HandlerType type;
    uint32_t enabled;
    uint64_t triggerCount;
    uint64_t lastTrigger;
};

static volatile LONG g_initialized = 0;
static HandlerEntry g_handlers[MAX_HANDLERS];
static volatile LONG g_nextHandlerId = 1;
static volatile LONG g_enabledCount = 0;

extern "C" __declspec(dllexport) int Win32IDE_WiringHandlers_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextHandlerId, 1);
    InterlockedExchange(&g_enabledCount, 0);
    memset(g_handlers, 0, sizeof(g_handlers));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_WiringHandlers_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_WiringHandlers_RegisterHandler(const char* name, int type, uint32_t* outHandlerId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outHandlerId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_HANDLERS; ++i) {
        if (InterlockedCompareExchange(&g_handlers[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    HandlerEntry* hnd = &g_handlers[slot];
    hnd->handlerId = InterlockedIncrement(&g_nextHandlerId);
    size_t len = strlen(name);
    if (len >= MAX_HANDLER_NAME) len = MAX_HANDLER_NAME - 1;
    memcpy(hnd->name, name, len);
    hnd->name[len] = 0;
    hnd->type = static_cast<HandlerType>(type);
    hnd->enabled = 1;
    hnd->triggerCount = 0;
    hnd->lastTrigger = 0;
    InterlockedExchange(&hnd->active, 1);
    InterlockedIncrement(&g_enabledCount);
    *outHandlerId = hnd->handlerId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_WiringHandlers_EnableHandler(uint32_t handlerId, uint32_t enabled) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_HANDLERS; ++i) {
        if (InterlockedCompareExchange(&g_handlers[i].active, 0, 0) == 1 && g_handlers[i].handlerId == handlerId) {
            uint32_t oldEnabled = g_handlers[i].enabled;
            g_handlers[i].enabled = enabled ? 1 : 0;
            if (oldEnabled == 0 && enabled) InterlockedIncrement(&g_enabledCount);
            if (oldEnabled == 1 && !enabled) InterlockedDecrement(&g_enabledCount);
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_WiringHandlers_TriggerHandler(uint32_t handlerId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_HANDLERS; ++i) {
        if (InterlockedCompareExchange(&g_handlers[i].active, 0, 0) == 1 && g_handlers[i].handlerId == handlerId) {
            if (g_handlers[i].enabled) {
                g_handlers[i].triggerCount++;
                g_handlers[i].lastTrigger = GetTickCount64();
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_WiringHandlers_GetHandlerInfo(uint32_t handlerId, char* outName, uint32_t maxLen, int* outType, uint32_t* outEnabled, uint64_t* outTriggerCount) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_HANDLERS; ++i) {
        if (InterlockedCompareExchange(&g_handlers[i].active, 0, 0) == 1 && g_handlers[i].handlerId == handlerId) {
            if (outName) {
                size_t len = strlen(g_handlers[i].name);
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outName, g_handlers[i].name, len);
                outName[len] = 0;
            }
            if (outType) *outType = static_cast<int>(g_handlers[i].type);
            if (outEnabled) *outEnabled = g_handlers[i].enabled;
            if (outTriggerCount) *outTriggerCount = g_handlers[i].triggerCount;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_WiringHandlers_GetEnabledCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_enabledCount, 0, 0));
}
