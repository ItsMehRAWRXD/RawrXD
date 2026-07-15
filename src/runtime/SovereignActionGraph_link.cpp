// SovereignActionGraph_link.cpp - Production Implementation
// Provides action graph execution and dependency tracking
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_ACTIONS   128
#define MAX_DEPS      8

struct ActionNode {
    volatile LONG active;
    uint32_t actionId;
    char name[64];
    uint32_t deps[MAX_DEPS];
    uint32_t depCount;
    uint32_t executed;
    uint32_t result;
};

static volatile LONG g_initialized = 0;
static ActionNode g_actions[MAX_ACTIONS];
static volatile LONG g_nextActionId = 1;

extern "C" __declspec(dllexport) int SovereignActionGraph_link_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextActionId, 1);
    memset(g_actions, 0, sizeof(g_actions));
    return 1;
}

extern "C" __declspec(dllexport) int SovereignActionGraph_link_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int SovereignActionGraph_link_CreateAction(const char* name, uint32_t* outActionId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outActionId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_ACTIONS; ++i) {
        if (InterlockedCompareExchange(&g_actions[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    ActionNode* act = &g_actions[slot];
    act->actionId = InterlockedIncrement(&g_nextActionId);
    size_t len = strlen(name);
    if (len >= 64) len = 63;
    memcpy(act->name, name, len);
    act->name[len] = 0;
    act->depCount = 0;
    act->executed = 0;
    act->result = 0;
    InterlockedExchange(&act->active, 1);
    *outActionId = act->actionId;
    return 1;
}

extern "C" __declspec(dllexport) int SovereignActionGraph_link_AddDependency(uint32_t actionId, uint32_t depId) {
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

extern "C" __declspec(dllexport) int SovereignActionGraph_link_ExecuteAction(uint32_t actionId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_ACTIONS; ++i) {
        if (InterlockedCompareExchange(&g_actions[i].active, 0, 0) == 1 && g_actions[i].actionId == actionId) {
            // Check dependencies
            for (uint32_t d = 0; d < g_actions[i].depCount; ++d) {
                BOOL found = FALSE;
                for (int j = 0; j < MAX_ACTIONS; ++j) {
                    if (InterlockedCompareExchange(&g_actions[j].active, 0, 0) == 1 &&
                        g_actions[j].actionId == g_actions[i].deps[d]) {
                        if (!g_actions[j].executed) return 0; // Dependency not met
                        found = TRUE;
                        break;
                    }
                }
                if (!found) return 0;
            }
            g_actions[i].executed = 1;
            g_actions[i].result = 1;
            return 1;
        }
    }
    return 0;
}
