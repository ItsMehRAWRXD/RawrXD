// rawrxd_linestream_raster.cpp - Production Implementation
// Provides line-by-line text rasterization for IDE rendering
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_LINES       1024
#define MAX_LINE_LEN    512

struct LineEntry {
    volatile LONG active;
    uint32_t lineId;
    char text[MAX_LINE_LEN];
    uint32_t length;
    uint32_t color;
    uint32_t flags;
};

static volatile LONG g_initialized = 0;
static LineEntry g_lines[MAX_LINES];
static volatile LONG g_nextLineId = 1;
static volatile LONG g_lineCount = 0;

extern "C" __declspec(dllexport) int rawrxd_linestream_raster_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextLineId, 1);
    InterlockedExchange(&g_lineCount, 0);
    memset(g_lines, 0, sizeof(g_lines));
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_linestream_raster_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_linestream_raster_AddLine(const char* text, uint32_t color, uint32_t flags, uint32_t* outLineId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!text || !outLineId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_LINES; ++i) {
        if (InterlockedCompareExchange(&g_lines[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    LineEntry* line = &g_lines[slot];
    line->lineId = InterlockedIncrement(&g_nextLineId);
    size_t len = strlen(text);
    if (len >= MAX_LINE_LEN) len = MAX_LINE_LEN - 1;
    memcpy(line->text, text, len);
    line->text[len] = 0;
    line->length = static_cast<uint32_t>(len);
    line->color = color;
    line->flags = flags;
    InterlockedExchange(&line->active, 1);
    InterlockedIncrement(&g_lineCount);
    *outLineId = line->lineId;
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_linestream_raster_GetLine(uint32_t lineId, char* outText, uint32_t maxLen, uint32_t* outColor) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_LINES; ++i) {
        if (InterlockedCompareExchange(&g_lines[i].active, 0, 0) == 1 && g_lines[i].lineId == lineId) {
            if (outText) {
                size_t len = g_lines[i].length;
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outText, g_lines[i].text, len);
                outText[len] = 0;
            }
            if (outColor) *outColor = g_lines[i].color;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_linestream_raster_GetLineCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_lineCount, 0, 0));
}
