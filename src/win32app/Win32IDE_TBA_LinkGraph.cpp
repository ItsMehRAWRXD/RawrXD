// Win32IDE_TBA_LinkGraph.cpp - Production Implementation
// Provides TBA link graph for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_LINKS       256
#define MAX_LINK_NAME   128
#define MAX_TARGETS     8

struct LinkEntry {
    volatile LONG active;
    uint32_t linkId;
    char name[MAX_LINK_NAME];
    uint32_t sourceId;
    uint32_t targets[MAX_TARGETS];
    uint32_t targetCount;
    uint32_t weight;
    uint32_t active_flag;
};

static volatile LONG g_initialized = 0;
static LinkEntry g_links[MAX_LINKS];
static volatile LONG g_nextLinkId = 1;

extern "C" __declspec(dllexport) int Win32IDE_TBA_LinkGraph_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextLinkId, 1);
    memset(g_links, 0, sizeof(g_links));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_TBA_LinkGraph_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_TBA_LinkGraph_CreateLink(const char* name, uint32_t sourceId, uint32_t weight, uint32_t* outLinkId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outLinkId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_LINKS; ++i) {
        if (InterlockedCompareExchange(&g_links[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    LinkEntry* link = &g_links[slot];
    link->linkId = InterlockedIncrement(&g_nextLinkId);
    size_t len = strlen(name);
    if (len >= MAX_LINK_NAME) len = MAX_LINK_NAME - 1;
    memcpy(link->name, name, len);
    link->name[len] = 0;
    link->sourceId = sourceId;
    link->weight = weight;
    link->targetCount = 0;
    link->active_flag = 1;
    InterlockedExchange(&link->active, 1);
    *outLinkId = link->linkId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_TBA_LinkGraph_AddTarget(uint32_t linkId, uint32_t targetId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_LINKS; ++i) {
        if (InterlockedCompareExchange(&g_links[i].active, 0, 0) == 1 && g_links[i].linkId == linkId) {
            if (g_links[i].targetCount < MAX_TARGETS) {
                g_links[i].targets[g_links[i].targetCount++] = targetId;
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_TBA_LinkGraph_GetLinkInfo(uint32_t linkId, char* outName, uint32_t maxLen, uint32_t* outSourceId, uint32_t* outWeight, uint32_t* outTargetCount) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_LINKS; ++i) {
        if (InterlockedCompareExchange(&g_links[i].active, 0, 0) == 1 && g_links[i].linkId == linkId) {
            if (outName) {
                size_t len = strlen(g_links[i].name);
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outName, g_links[i].name, len);
                outName[len] = 0;
            }
            if (outSourceId) *outSourceId = g_links[i].sourceId;
            if (outWeight) *outWeight = g_links[i].weight;
            if (outTargetCount) *outTargetCount = g_links[i].targetCount;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_TBA_LinkGraph_SetActive(uint32_t linkId, uint32_t active) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_LINKS; ++i) {
        if (InterlockedCompareExchange(&g_links[i].active, 0, 0) == 1 && g_links[i].linkId == linkId) {
            g_links[i].active_flag = active ? 1 : 0;
            return 1;
        }
    }
    return 0;
}
