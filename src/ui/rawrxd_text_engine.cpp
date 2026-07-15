// rawrxd_text_engine.cpp - Production Implementation
// Provides text layout and measurement engine for IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_TEXT_BLOCKS     512
#define MAX_TEXT_LEN        1024

struct TextBlock {
    volatile LONG active;
    uint32_t blockId;
    char text[MAX_TEXT_LEN];
    uint32_t length;
    uint32_t width;
    uint32_t height;
    uint32_t fontSize;
    uint32_t flags;
};

static volatile LONG g_initialized = 0;
static TextBlock g_blocks[MAX_TEXT_BLOCKS];
static volatile LONG g_nextBlockId = 1;
static volatile LONG g_blockCount = 0;

extern "C" __declspec(dllexport) int rawrxd_text_engine_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextBlockId, 1);
    InterlockedExchange(&g_blockCount, 0);
    memset(g_blocks, 0, sizeof(g_blocks));
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_text_engine_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_text_engine_CreateBlock(const char* text, uint32_t fontSize, uint32_t flags, uint32_t* outBlockId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!text || !outBlockId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_TEXT_BLOCKS; ++i) {
        if (InterlockedCompareExchange(&g_blocks[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    TextBlock* blk = &g_blocks[slot];
    blk->blockId = InterlockedIncrement(&g_nextBlockId);
    size_t len = strlen(text);
    if (len >= MAX_TEXT_LEN) len = MAX_TEXT_LEN - 1;
    memcpy(blk->text, text, len);
    blk->text[len] = 0;
    blk->length = static_cast<uint32_t>(len);
    blk->fontSize = fontSize ? fontSize : 12;
    blk->flags = flags;
    // Simple measurement: width = chars * fontSize * 0.6, height = fontSize * 1.2
    blk->width = static_cast<uint32_t>(blk->length * blk->fontSize * 0.6f);
    blk->height = static_cast<uint32_t>(blk->fontSize * 1.2f);
    InterlockedExchange(&blk->active, 1);
    InterlockedIncrement(&g_blockCount);
    *outBlockId = blk->blockId;
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_text_engine_MeasureBlock(uint32_t blockId, uint32_t* outWidth, uint32_t* outHeight) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_TEXT_BLOCKS; ++i) {
        if (InterlockedCompareExchange(&g_blocks[i].active, 0, 0) == 1 && g_blocks[i].blockId == blockId) {
            if (outWidth) *outWidth = g_blocks[i].width;
            if (outHeight) *outHeight = g_blocks[i].height;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_text_engine_UpdateText(uint32_t blockId, const char* newText) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!newText) return 0;
    for (int i = 0; i < MAX_TEXT_BLOCKS; ++i) {
        if (InterlockedCompareExchange(&g_blocks[i].active, 0, 0) == 1 && g_blocks[i].blockId == blockId) {
            size_t len = strlen(newText);
            if (len >= MAX_TEXT_LEN) len = MAX_TEXT_LEN - 1;
            memcpy(g_blocks[i].text, newText, len);
            g_blocks[i].text[len] = 0;
            g_blocks[i].length = static_cast<uint32_t>(len);
            g_blocks[i].width = static_cast<uint32_t>(g_blocks[i].length * g_blocks[i].fontSize * 0.6f);
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_text_engine_GetBlockCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_blockCount, 0, 0));
}
