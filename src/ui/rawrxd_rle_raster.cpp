// rawrxd_rle_raster.cpp - Production Implementation
// Provides Run-Length Encoded rasterization for IDE text rendering
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_RLE_SEGMENTS    2048
#define MAX_RLE_RUNS        64

struct RleRun {
    uint32_t count;
    uint32_t color;
};

struct RleSegment {
    volatile LONG active;
    uint32_t segId;
    RleRun runs[MAX_RLE_RUNS];
    uint32_t runCount;
    uint32_t totalPixels;
};

static volatile LONG g_initialized = 0;
static RleSegment g_segments[MAX_RLE_SEGMENTS];
static volatile LONG g_nextSegId = 1;

extern "C" __declspec(dllexport) int rawrxd_rle_raster_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextSegId, 1);
    memset(g_segments, 0, sizeof(g_segments));
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_rle_raster_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_rle_raster_CreateSegment(const uint32_t* colors, const uint32_t* counts, uint32_t runCount, uint32_t* outSegId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!colors || !counts || runCount == 0 || runCount > MAX_RLE_RUNS || !outSegId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_RLE_SEGMENTS; ++i) {
        if (InterlockedCompareExchange(&g_segments[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    RleSegment* seg = &g_segments[slot];
    seg->segId = InterlockedIncrement(&g_nextSegId);
    seg->runCount = runCount;
    seg->totalPixels = 0;
    for (uint32_t r = 0; r < runCount; ++r) {
        seg->runs[r].color = colors[r];
        seg->runs[r].count = counts[r];
        seg->totalPixels += counts[r];
    }
    InterlockedExchange(&seg->active, 1);
    *outSegId = seg->segId;
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_rle_raster_GetSegmentInfo(uint32_t segId, uint32_t* outRunCount, uint32_t* outTotalPixels) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_RLE_SEGMENTS; ++i) {
        if (InterlockedCompareExchange(&g_segments[i].active, 0, 0) == 1 && g_segments[i].segId == segId) {
            if (outRunCount) *outRunCount = g_segments[i].runCount;
            if (outTotalPixels) *outTotalPixels = g_segments[i].totalPixels;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_rle_raster_GetRun(uint32_t segId, uint32_t runIndex, uint32_t* outCount, uint32_t* outColor) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_RLE_SEGMENTS; ++i) {
        if (InterlockedCompareExchange(&g_segments[i].active, 0, 0) == 1 && g_segments[i].segId == segId) {
            if (runIndex >= g_segments[i].runCount) return 0;
            if (outCount) *outCount = g_segments[i].runs[runIndex].count;
            if (outColor) *outColor = g_segments[i].runs[runIndex].color;
            return 1;
        }
    }
    return 0;
}
