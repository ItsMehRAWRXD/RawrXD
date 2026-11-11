// rawrxd_syntax_bridge.cpp - Production Implementation
// Provides syntax highlighting bridge between parser and renderer
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_TOKENS      4096
#define MAX_TOKEN_LEN   128

enum RawrTokenType {
    RAWR_TOKEN_UNKNOWN = 0,
    RAWR_TOKEN_KEYWORD,
    RAWR_TOKEN_STRING,
    RAWR_TOKEN_COMMENT,
    RAWR_TOKEN_NUMBER,
    RAWR_TOKEN_IDENTIFIER,
    RAWR_TOKEN_OPERATOR,
    RAWR_TOKEN_TYPE
};

struct SyntaxToken {
    volatile LONG active;
    uint32_t tokenId;
    char text[MAX_TOKEN_LEN];
    RawrTokenType type;
    uint32_t line;
    uint32_t column;
    uint32_t color;
};

static volatile LONG g_initialized = 0;
static SyntaxToken g_tokens[MAX_TOKENS];
static volatile LONG g_nextTokenId = 1;
static volatile LONG g_tokenCount = 0;

extern "C" __declspec(dllexport) int rawrxd_syntax_bridge_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextTokenId, 1);
    InterlockedExchange(&g_tokenCount, 0);
    memset(g_tokens, 0, sizeof(g_tokens));
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_syntax_bridge_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_syntax_bridge_AddToken(const char* text, int type, uint32_t line, uint32_t column, uint32_t color, uint32_t* outTokenId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!text || !outTokenId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_TOKENS; ++i) {
        if (InterlockedCompareExchange(&g_tokens[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    SyntaxToken* tok = &g_tokens[slot];
    tok->tokenId = InterlockedIncrement(&g_nextTokenId);
    size_t len = strlen(text);
    if (len >= MAX_TOKEN_LEN) len = MAX_TOKEN_LEN - 1;
    memcpy(tok->text, text, len);
    tok->text[len] = 0;
    tok->type = static_cast<RawrTokenType>(type);
    tok->line = line;
    tok->column = column;
    tok->color = color;
    InterlockedExchange(&tok->active, 1);
    InterlockedIncrement(&g_tokenCount);
    *outTokenId = tok->tokenId;
    return 1;
}

extern "C" __declspec(dllexport) int rawrxd_syntax_bridge_GetToken(uint32_t tokenId, char* outText, uint32_t maxLen, int* outType, uint32_t* outLine, uint32_t* outColumn) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_TOKENS; ++i) {
        if (InterlockedCompareExchange(&g_tokens[i].active, 0, 0) == 1 && g_tokens[i].tokenId == tokenId) {
            if (outText) {
                size_t len = strlen(g_tokens[i].text);
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outText, g_tokens[i].text, len);
                outText[len] = 0;
            }
            if (outType) *outType = static_cast<int>(g_tokens[i].type);
            if (outLine) *outLine = g_tokens[i].line;
            if (outColumn) *outColumn = g_tokens[i].column;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int rawrxd_syntax_bridge_GetTokenCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_tokenCount, 0, 0));
}

extern "C" __declspec(dllexport) int rawrxd_syntax_bridge_ClearTokens() {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_TOKENS; ++i) {
        InterlockedExchange(&g_tokens[i].active, 0);
    }
    InterlockedExchange(&g_tokenCount, 0);
    return 1;
}
