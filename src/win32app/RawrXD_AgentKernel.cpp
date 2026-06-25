// RawrXD_AgentKernel.cpp - Production Implementation
// Provides agent kernel for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_AGENTS      32
#define MAX_AGENT_NAME  64

enum AgentState {
    AGENT_IDLE = 0,
    AGENT_RUNNING,
    AGENT_PAUSED,
    AGENT_COMPLETED,
    AGENT_ERROR
};

struct AgentEntry {
    volatile LONG active;
    uint32_t agentId;
    char name[MAX_AGENT_NAME];
    AgentState state;
    uint64_t startTime;
    uint64_t lastHeartbeat;
    uint32_t taskCount;
    uint32_t completedTasks;
};

static volatile LONG g_initialized = 0;
static AgentEntry g_agents[MAX_AGENTS];
static volatile LONG g_nextAgentId = 1;
static volatile LONG g_activeAgents = 0;

extern "C" __declspec(dllexport) int RawrXD_AgentKernel_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextAgentId, 1);
    InterlockedExchange(&g_activeAgents, 0);
    memset(g_agents, 0, sizeof(g_agents));
    return 1;
}

extern "C" __declspec(dllexport) int RawrXD_AgentKernel_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int RawrXD_AgentKernel_CreateAgent(const char* name, uint32_t* outAgentId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outAgentId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_AGENTS; ++i) {
        if (InterlockedCompareExchange(&g_agents[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    AgentEntry* agent = &g_agents[slot];
    agent->agentId = InterlockedIncrement(&g_nextAgentId);
    size_t len = strlen(name);
    if (len >= MAX_AGENT_NAME) len = MAX_AGENT_NAME - 1;
    memcpy(agent->name, name, len);
    agent->name[len] = 0;
    agent->state = AGENT_IDLE;
    agent->startTime = 0;
    agent->lastHeartbeat = GetTickCount64();
    agent->taskCount = 0;
    agent->completedTasks = 0;
    InterlockedExchange(&agent->active, 1);
    *outAgentId = agent->agentId;
    return 1;
}

extern "C" __declspec(dllexport) int RawrXD_AgentKernel_StartAgent(uint32_t agentId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_AGENTS; ++i) {
        if (InterlockedCompareExchange(&g_agents[i].active, 0, 0) == 1 && g_agents[i].agentId == agentId) {
            if (g_agents[i].state == AGENT_IDLE) {
                g_agents[i].state = AGENT_RUNNING;
                g_agents[i].startTime = GetTickCount64();
                InterlockedIncrement(&g_activeAgents);
                return 1;
            }
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int RawrXD_AgentKernel_StopAgent(uint32_t agentId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_AGENTS; ++i) {
        if (InterlockedCompareExchange(&g_agents[i].active, 0, 0) == 1 && g_agents[i].agentId == agentId) {
            if (g_agents[i].state == AGENT_RUNNING) {
                g_agents[i].state = AGENT_COMPLETED;
                InterlockedDecrement(&g_activeAgents);
                return 1;
            }
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int RawrXD_AgentKernel_GetAgentState(uint32_t agentId, int* outState, uint32_t* outTaskCount, uint32_t* outCompleted) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_AGENTS; ++i) {
        if (InterlockedCompareExchange(&g_agents[i].active, 0, 0) == 1 && g_agents[i].agentId == agentId) {
            if (outState) *outState = static_cast<int>(g_agents[i].state);
            if (outTaskCount) *outTaskCount = g_agents[i].taskCount;
            if (outCompleted) *outCompleted = g_agents[i].completedTasks;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int RawrXD_AgentKernel_GetActiveAgentCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_activeAgents, 0, 0));
}
