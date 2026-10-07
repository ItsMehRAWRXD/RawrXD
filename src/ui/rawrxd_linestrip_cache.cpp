// rawrxd_linestrip_cache.cpp - Production Implementation
// Provides caching for line strip rendering data
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_CACHE_ENTRIES   512
#define MAX_STRIP_LEN       256

struct StripEntry {
    volatile LONG active;
    uint32_t stripId;
    uint32_t lineIds[MAX_STRIP_LEN];
    uint32_t count;
    uint64_t lastAccess;
    uint32_t hitCount;
};

static volatile LONG g_initialized = 0;
static StripEntry g_cache[MAX_CACHE_ENTRIES];
static volatile LONG g_nextStripId = 1;
static volatile LONG g_hitCount = 0;
static volatile LONG g_missCount = 0;

extern "C" __declspec(dllexport) int rawrxd_linestrip_cache_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextStripId, 1);
    InterlockedExchange(&g_hitCount, 0);
    InterlockedExchange(&g_missCount, 0);
    memset(g_cache, 0, sizeof(g_cache));
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_linestrip_cache_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_linestrip_cache_StoreStrip(const uint32_t* lineIds, uint32_t count, uint32_t* outStripId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!lineIds || count == 0 || count > MAX_STRIP_LEN || !outStripId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_CACHE_ENTRIES; ++i) {
        if (InterlockedCompareExchange(&g_cache[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    StripEntry* entry = &g_cache[slot];
    entry->stripId = InterlockedIncrement(&g_nextStripId);
    memcpy(entry->lineIds, lineIds, count * sizeof(uint32_t));
    entry->count = count;
    entry->lastAccess = GetTickCount64();
    entry->hitCount = 0;
    InterlockedExchange(&entry->active, 1);
    *outStripId = entry->stripId;
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_linestrip_cache_LookupStrip(uint32_t stripId, uint32_t* outLineIds, uint32_t maxCount, uint32_t* outActualCount) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_CACHE_ENTRIES; ++i) {
        if (InterlockedCompareExchange(&g_cache[i].active, 0, 0) == 1 && g_cache[i].stripId == stripId) {
            uint32_t count = g_cache[i].count;
            if (count > maxCount) count = maxCount;
            memcpy(outLineIds, g_cache[i].lineIds, count * sizeof(uint32_t));
            if (outActualCount) *outActualCount = count;
            g_cache[i].lastAccess = GetTickCount64();
            InterlockedIncrement(&g_cache[i].hitCount);
            InterlockedIncrement(&g_hitCount);
            return 1;
        }
    }
    InterlockedIncrement(&g_missCount);
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_linestrip_cache_GetStats(int* hits, int* misses) {
    if (hits) *hits = static_cast<int>(InterlockedCompareExchange(&g_hitCount, 0, 0));
    if (misses) *misses = static_cast<int>(InterlockedCompareExchange(&g_missCount, 0, 0));
    return 1;
}
