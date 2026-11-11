// Win32IDE_Swarm.cpp - Production Implementation
// Provides swarm orchestration for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_SWARM_NODES     64
#define MAX_NODE_NAME       64

enum NodeState {
    NODE_OFFLINE = 0,
    NODE_ONLINE,
    NODE_BUSY,
    NODE_ERROR
};

struct SwarmNode {
    volatile LONG active;
    uint32_t nodeId;
    char name[MAX_NODE_NAME];
    NodeState state;
    uint64_t lastHeartbeat;
    uint32_t capacity;
    uint32_t load;
};

static volatile LONG g_initialized = 0;
static SwarmNode g_nodes[MAX_SWARM_NODES];
static volatile LONG g_nextNodeId = 1;
static volatile LONG g_onlineCount = 0;

extern "C" __declspec(dllexport) int Win32IDE_Swarm_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextNodeId, 1);
    InterlockedExchange(&g_onlineCount, 0);
    memset(g_nodes, 0, sizeof(g_nodes));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_Swarm_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_Swarm_RegisterNode(const char* name, uint32_t capacity, uint32_t* outNodeId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outNodeId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_SWARM_NODES; ++i) {
        if (InterlockedCompareExchange(&g_nodes[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    SwarmNode* node = &g_nodes[slot];
    node->nodeId = InterlockedIncrement(&g_nextNodeId);
    size_t len = strlen(name);
    if (len >= MAX_NODE_NAME) len = MAX_NODE_NAME - 1;
    memcpy(node->name, name, len);
    node->name[len] = 0;
    node->state = NODE_ONLINE;
    node->lastHeartbeat = GetTickCount64();
    node->capacity = capacity;
    node->load = 0;
    InterlockedExchange(&node->active, 1);
    InterlockedIncrement(&g_onlineCount);
    *outNodeId = node->nodeId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_Swarm_UpdateNodeState(uint32_t nodeId, int state) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_SWARM_NODES; ++i) {
        if (InterlockedCompareExchange(&g_nodes[i].active, 0, 0) == 1 && g_nodes[i].nodeId == nodeId) {
            NodeState oldState = g_nodes[i].state;
            g_nodes[i].state = static_cast<NodeState>(state);
            g_nodes[i].lastHeartbeat = GetTickCount64();
            if (oldState == NODE_OFFLINE && state != NODE_OFFLINE) InterlockedIncrement(&g_onlineCount);
            if (oldState != NODE_OFFLINE && state == NODE_OFFLINE) InterlockedDecrement(&g_onlineCount);
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_Swarm_UpdateNodeLoad(uint32_t nodeId, uint32_t load) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_SWARM_NODES; ++i) {
        if (InterlockedCompareExchange(&g_nodes[i].active, 0, 0) == 1 && g_nodes[i].nodeId == nodeId) {
            g_nodes[i].load = load;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_Swarm_GetNodeInfo(uint32_t nodeId, char* outName, uint32_t maxLen, int* outState, uint32_t* outCapacity, uint32_t* outLoad) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_SWARM_NODES; ++i) {
        if (InterlockedCompareExchange(&g_nodes[i].active, 0, 0) == 1 && g_nodes[i].nodeId == nodeId) {
            if (outName) {
                size_t len = strlen(g_nodes[i].name);
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outName, g_nodes[i].name, len);
                outName[len] = 0;
            }
            if (outState) *outState = static_cast<int>(g_nodes[i].state);
            if (outCapacity) *outCapacity = g_nodes[i].capacity;
            if (outLoad) *outLoad = g_nodes[i].load;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_Swarm_GetOnlineCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_onlineCount, 0, 0));
}
