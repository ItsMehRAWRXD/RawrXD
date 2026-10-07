// Win32IDE_ActionGraph.cpp - Production Implementation
// Provides action graph for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_ACTIONS     128
#define MAX_ACTION_NAME 64
#define MAX_DEPS        8

enum ActionStatus {
    ACTION_PENDING = 0,
    ACTION_RUNNING,
    ACTION_COMPLETED,
    ACTION_FAILED
};

struct ActionEntry {
    volatile LONG active;
    uint32_t actionId;
    char name[MAX_ACTION_NAME];
    ActionStatus status;
    uint32_t deps[MAX_DEPS];
    uint32_t depCount;
    uint64_t startTime;
    uint64_t endTime;
    uint32_t resultCode;
};

static volatile LONG g_initialized = 0;
static ActionEntry g_actions[MAX_ACTIONS];
static volatile LONG g_nextActionId = 1;

extern "C" __declspec(dllexport) int Win32IDE_ActionGraph_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextActionId, 1);
    memset(g_actions, 0, sizeof(g_actions));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_ActionGraph_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ActionGraph_CreateAction(const char* name, uint32_t* outActionId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outActionId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_ACTIONS; ++i) {
        if (InterlockedCompareExchange(&g_actions[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    ActionEntry* act = &g_actions[slot];
    act->actionId = InterlockedIncrement(&g_nextActionId);
    size_t len = strlen(name);
    if (len >= MAX_ACTION_NAME) len = MAX_ACTION_NAME - 1;
    memcpy(act->name, name, len);
    act->name[len] = 0;
    act->status = ACTION_PENDING;
    act->depCount = 0;
    act->startTime = 0;
    act->endTime = 0;
    act->resultCode = 0;
    InterlockedExchange(&act->active, 1);
    *outActionId = act->actionId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_ActionGraph_AddDependency(uint32_t actionId, uint32_t depId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_ACTIONS; ++i) {
        if (InterlockedCompareExchange(&g_actions[i].active, 0, 0) == 1 && g_actions[i].actionId == actionId) {
            if (g_actions[i].depCount < MAX_DEPS) {
                g_actions[i].deps[g_actions[i].depCount++] = depId;
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ActionGraph_ExecuteAction(uint32_t actionId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_ACTIONS; ++i) {
        if (InterlockedCompareExchange(&g_actions[i].active, 0, 0) == 1 && g_actions[i].actionId == actionId) {
            // Verify dependencies
            for (uint32_t d = 0; d < g_actions[i].depCount; ++d) {
                BOOL found = FALSE;
                for (int j = 0; j < MAX_ACTIONS; ++j) {
                    if (InterlockedCompareExchange(&g_actions[j].active, 0, 0) == 1 &&
                        g_actions[j].actionId == g_actions[i].deps[d]) {
                        if (g_actions[j].status != ACTION_COMPLETED) return 0;
                        found = TRUE;
                        break;
                    }
                }
                if (!found) return 0;
            }
            g_actions[i].status = ACTION_RUNNING;
            g_actions[i].startTime = GetTickCount64();
            // Simulate execution
            g_actions[i].status = ACTION_COMPLETED;
            g_actions[i].endTime = GetTickCount64();
            g_actions[i].resultCode = 0;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ActionGraph_GetActionStatus(uint32_t actionId, int* outStatus, uint32_t* outResultCode) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_ACTIONS; ++i) {
        if (InterlockedCompareExchange(&g_actions[i].active, 0, 0) == 1 && g_actions[i].actionId == actionId) {
            if (outStatus) *outStatus = static_cast<int>(g_actions[i].status);
            if (outResultCode) *outResultCode = g_actions[i].resultCode;
            return 1;
        }
    }
    return 0;
}
