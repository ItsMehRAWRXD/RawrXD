// Win32IDE_BuildProvenance.cpp - Production Implementation
// Provides build provenance tracking for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_BUILDS      64
#define MAX_BUILD_ID    64
#define MAX_SOURCE_PATH 256

struct BuildEntry {
    volatile LONG active;
    uint32_t buildId;
    char buildTag[MAX_BUILD_ID];
    char sourcePath[MAX_SOURCE_PATH];
    uint64_t timestamp;
    uint32_t success;
    uint32_t durationMs;
    uint64_t outputHash;
};

static volatile LONG g_initialized = 0;
static BuildEntry g_builds[MAX_BUILDS];
static volatile LONG g_nextBuildId = 1;

extern "C" __declspec(dllexport) int Win32IDE_BuildProvenance_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextBuildId, 1);
    memset(g_builds, 0, sizeof(g_builds));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_BuildProvenance_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_BuildProvenance_RecordBuild(const char* buildTag, const char* sourcePath, uint32_t success, uint32_t durationMs, uint64_t outputHash, uint32_t* outBuildId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!buildTag || !sourcePath || !outBuildId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_BUILDS; ++i) {
        if (InterlockedCompareExchange(&g_builds[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    BuildEntry* build = &g_builds[slot];
    build->buildId = InterlockedIncrement(&g_nextBuildId);
    size_t tagLen = strlen(buildTag);
    if (tagLen >= MAX_BUILD_ID) tagLen = MAX_BUILD_ID - 1;
    memcpy(build->buildTag, buildTag, tagLen);
    build->buildTag[tagLen] = 0;
    size_t pathLen = strlen(sourcePath);
    if (pathLen >= MAX_SOURCE_PATH) pathLen = MAX_SOURCE_PATH - 1;
    memcpy(build->sourcePath, sourcePath, pathLen);
    build->sourcePath[pathLen] = 0;
    build->timestamp = GetTickCount64();
    build->success = success ? 1 : 0;
    build->durationMs = durationMs;
    build->outputHash = outputHash;
    InterlockedExchange(&build->active, 1);
    *outBuildId = build->buildId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_BuildProvenance_GetBuildInfo(uint32_t buildId, char* outTag, uint32_t tagMaxLen, char* outSource, uint32_t sourceMaxLen, uint32_t* outSuccess, uint32_t* outDuration) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_BUILDS; ++i) {
        if (InterlockedCompareExchange(&g_builds[i].active, 0, 0) == 1 && g_builds[i].buildId == buildId) {
            if (outTag) {
                size_t len = strlen(g_builds[i].buildTag);
                if (len >= tagMaxLen) len = tagMaxLen - 1;
                memcpy(outTag, g_builds[i].buildTag, len);
                outTag[len] = 0;
            }
            if (outSource) {
                size_t len = strlen(g_builds[i].sourcePath);
                if (len >= sourceMaxLen) len = sourceMaxLen - 1;
                memcpy(outSource, g_builds[i].sourcePath, len);
                outSource[len] = 0;
            }
            if (outSuccess) *outSuccess = g_builds[i].success;
            if (outDuration) *outDuration = g_builds[i].durationMs;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_BuildProvenance_GetLatestBuild(uint32_t* outBuildId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!outBuildId) return 0;
    uint64_t latestTime = 0;
    uint32_t latestId = 0;
    for (int i = 0; i < MAX_BUILDS; ++i) {
        if (InterlockedCompareExchange(&g_builds[i].active, 0, 0) == 1) {
            if (g_builds[i].timestamp > latestTime) {
                latestTime = g_builds[i].timestamp;
                latestId = g_builds[i].buildId;
            }
        }
    }
    if (latestId == 0) return 0;
    *outBuildId = latestId;
    return 1;
}
