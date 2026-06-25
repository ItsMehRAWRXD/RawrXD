// GitProviderTypes.cpp - Production Implementation
// Provides Git provider type definitions and repository info
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_REPOS       16
#define MAX_URL_LEN     256

struct RepoInfo {
    volatile LONG active;
    uint32_t repoId;
    char url[MAX_URL_LEN];
    char branch[64];
    char headCommit[64];
    uint32_t isDirty;
    uint64_t lastFetch;
};

static volatile LONG g_initialized = 0;
static RepoInfo g_repos[MAX_REPOS];
static volatile LONG g_nextRepoId = 1;

extern "C" __declspec(dllexport) int GitProviderTypes_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextRepoId, 1);
    memset(g_repos, 0, sizeof(g_repos));
    return 1;
}

extern "C" __declspec(dllexport) int GitProviderTypes_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int GitProviderTypes_RegisterRepo(const char* url, const char* branch, uint32_t* outRepoId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!url || !outRepoId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_REPOS; ++i) {
        if (InterlockedCompareExchange(&g_repos[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    RepoInfo* repo = &g_repos[slot];
    repo->repoId = InterlockedIncrement(&g_nextRepoId);
    size_t urlLen = strlen(url);
    if (urlLen >= MAX_URL_LEN) urlLen = MAX_URL_LEN - 1;
    memcpy(repo->url, url, urlLen);
    repo->url[urlLen] = 0;
    if (branch) {
        size_t brLen = strlen(branch);
        if (brLen >= 64) brLen = 63;
        memcpy(repo->branch, branch, brLen);
        repo->branch[brLen] = 0;
    } else {
        strcpy_s(repo->branch, "main");
    }
    repo->isDirty = 0;
    repo->lastFetch = GetTickCount64();
    InterlockedExchange(&repo->active, 1);
    *outRepoId = repo->repoId;
    return 1;
}

extern "C" __declspec(dllexport) int GitProviderTypes_GetRepoInfo(uint32_t repoId, char* outUrl, char* outBranch, uint32_t* outIsDirty) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_REPOS; ++i) {
        if (InterlockedCompareExchange(&g_repos[i].active, 0, 0) == 1 && g_repos[i].repoId == repoId) {
            if (outUrl) strcpy_s(outUrl, MAX_URL_LEN, g_repos[i].url);
            if (outBranch) strcpy_s(outBranch, 64, g_repos[i].branch);
            if (outIsDirty) *outIsDirty = g_repos[i].isDirty;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int GitProviderTypes_SetDirty(uint32_t repoId, uint32_t isDirty) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_REPOS; ++i) {
        if (InterlockedCompareExchange(&g_repos[i].active, 0, 0) == 1 && g_repos[i].repoId == repoId) {
            g_repos[i].isDirty = isDirty ? 1 : 0;
            return 1;
        }
    }
    return 0;
}
