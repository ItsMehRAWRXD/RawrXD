// agentic_planning_persistence.cpp - Production Implementation
// Persists agentic plans to disk and loads them on restart
// ============================================================================

#include <windows.h>
#include <cstdio>
#include <cstring>

// ============================================================================
// Constants
// ============================================================================
#define MAX_PLANS       64
#define MAX_PLAN_NAME   128
#define MAX_PLAN_DATA   8192
#define PLAN_MAGIC      0x52415750  // 'RAWP'
#define PLAN_VERSION    1

// ============================================================================
// Plan Header
// ============================================================================
#pragma pack(push, 1)
struct PlanHeader {
    DWORD magic;
    DWORD version;
    DWORD planId;
    DWORD dataLen;
    DWORD checksum;
    FILETIME created;
    FILETIME modified;
    char name[MAX_PLAN_NAME];
};
#pragma pack(pop)

// ============================================================================
// Plan Entry
// ============================================================================
struct PlanEntry {
    volatile LONG active;
    PlanHeader header;
    char data[MAX_PLAN_DATA];
};

// ============================================================================
// State
// ============================================================================
static volatile LONG g_initialized = 0;
static PlanEntry g_planStore[MAX_PLANS];
static volatile LONG g_nextPlanId = 1;
static char g_planDir[MAX_PATH] = {0};

// ============================================================================
// Helper: Simple checksum
// ============================================================================
static DWORD ComputeChecksum(const void* data, size_t len) {
    const BYTE* p = static_cast<const BYTE*>(data);
    DWORD sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum = (sum * 31) + p[i];
    }
    return sum;
}

// ============================================================================
// Helper: Ensure plan directory exists
// ============================================================================
static void EnsurePlanDir() {
    if (g_planDir[0] == 0) {
        GetTempPathA(MAX_PATH, g_planDir);
        strcat_s(g_planDir, MAX_PATH, "\\RawrXD_Plans");
    }
    CreateDirectoryA(g_planDir, nullptr);
}

// ============================================================================
// Helper: Build plan file path
// ============================================================================
static void BuildPlanPath(int planId, char* outPath, size_t outLen) {
    EnsurePlanDir();
    snprintf(outPath, outLen, "%s\\plan_%08d.rawp", g_planDir, planId);
}

// ============================================================================
// Exported API
// ============================================================================
extern "C" __declspec(dllexport) int agentic_planning_persistence_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    
    InterlockedExchange(&g_nextPlanId, 1);
    for (int i = 0; i < MAX_PLANS; ++i) {
        InterlockedExchange(&g_planStore[i].active, 0);
    }
    EnsurePlanDir();
    return 1;
}

extern "C" __declspec(dllexport) int agentic_planning_persistence_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int agentic_planning_persistence_SavePlan(
    const char* planName, 
    const char* planData, 
    int* outPlanId
) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!planName || !planData || !outPlanId) return 0;
    
    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_PLANS; ++i) {
        if (InterlockedCompareExchange(&g_planStore[i].active, 0, 0) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return 0; // Full
    
    LONG planId = InterlockedIncrement(&g_nextPlanId);
    PlanEntry* entry = &g_planStore[slot];
    
    memset(&entry->header, 0, sizeof(PlanHeader));
    entry->header.magic = PLAN_MAGIC;
    entry->header.version = PLAN_VERSION;
    entry->header.planId = planId;
    
    size_t nameLen = strlen(planName);
    if (nameLen >= MAX_PLAN_NAME) nameLen = MAX_PLAN_NAME - 1;
    memcpy(entry->header.name, planName, nameLen);
    entry->header.name[nameLen] = 0;
    
    size_t dataLen = strlen(planData);
    if (dataLen >= MAX_PLAN_DATA) dataLen = MAX_PLAN_DATA - 1;
    memcpy(entry->data, planData, dataLen);
    entry->data[dataLen] = 0;
    entry->header.dataLen = static_cast<DWORD>(dataLen);
    
    GetSystemTimeAsFileTime(&entry->header.created);
    entry->header.modified = entry->header.created;
    entry->header.checksum = ComputeChecksum(entry->data, dataLen);
    
    // Write to disk
    char path[MAX_PATH];
    BuildPlanPath(planId, path, MAX_PATH);
    
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hFile, &entry->header, sizeof(PlanHeader), &written, nullptr);
        WriteFile(hFile, entry->data, entry->header.dataLen, &written, nullptr);
        CloseHandle(hFile);
    }
    
    InterlockedExchange(&entry->active, 1);
    *outPlanId = planId;
    return 1;
}

extern "C" __declspec(dllexport) int agentic_planning_persistence_LoadPlan(
    int planId, 
    char* outData, 
    int maxLen
) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!outData || maxLen <= 0) return 0;
    
    // Try memory first
    for (int i = 0; i < MAX_PLANS; ++i) {
        if (InterlockedCompareExchange(&g_planStore[i].active, 0, 0) == 1 && 
            g_planStore[i].header.planId == static_cast<DWORD>(planId)) {
            size_t len = g_planStore[i].header.dataLen;
            if (len >= static_cast<size_t>(maxLen)) len = maxLen - 1;
            memcpy(outData, g_planStore[i].data, len);
            outData[len] = 0;
            return 1;
        }
    }
    
    // Try disk
    char path[MAX_PATH];
    BuildPlanPath(planId, path, MAX_PATH);
    
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    
    PlanHeader header;
    DWORD read = 0;
    BOOL ok = ReadFile(hFile, &header, sizeof(PlanHeader), &read, nullptr);
    if (!ok || read != sizeof(PlanHeader) || header.magic != PLAN_MAGIC) {
        CloseHandle(hFile);
        return 0;
    }
    
    DWORD toRead = header.dataLen;
    if (toRead >= static_cast<DWORD>(maxLen)) toRead = maxLen - 1;
    ReadFile(hFile, outData, toRead, &read, nullptr);
    outData[read] = 0;
    CloseHandle(hFile);
    
    return 1;
}

extern "C" __declspec(dllexport) int agentic_planning_persistence_DeletePlan(int planId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    
    for (int i = 0; i < MAX_PLANS; ++i) {
        if (InterlockedCompareExchange(&g_planStore[i].active, 0, 0) == 1 && 
            g_planStore[i].header.planId == static_cast<DWORD>(planId)) {
            InterlockedExchange(&g_planStore[i].active, 0);
        }
    }
    
    char path[MAX_PATH];
    BuildPlanPath(planId, path, MAX_PATH);
    DeleteFileA(path);
    
    return 1;
}
