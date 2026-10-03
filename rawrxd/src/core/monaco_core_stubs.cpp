// ============================================================================
// monaco_core_stubs.cpp — C Stubs for MonacoCore ASM Exports
// ============================================================================
// The MASM source (src/asm/RawrXD_MonacoCore.asm) is currently an auto-
// generated stub ("END" only). These C stubs satisfy the link requirements
// until real ASM implementations are written. Every stub reports its
// no-op status through the return value or out parameter where applicable.
//
// Stubs: MC_GapBuffer_Init, MC_GapBuffer_Destroy, MC_GapBuffer_Insert,
//        MC_GapBuffer_Delete, MC_GapBuffer_GetLine, MC_GapBuffer_Length,
//        MC_GapBuffer_LineCount, MC_TokenizeLine
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {

// Opaque handle for gap buffer
struct MC_GapBuffer {
    char*   data;
    size_t  capacity;
    size_t  length;
    size_t  gapStart;
    size_t  gapEnd;
};

static MC_GapBuffer* g_gapBuffer = nullptr;

void* MC_GapBuffer_Init(unsigned int initialCapacity) {
    MC_GapBuffer* gb = new MC_GapBuffer();
    gb->capacity = initialCapacity > 0 ? initialCapacity : 4096;
    gb->data = new char[gb->capacity];
    std::memset(gb->data, 0, gb->capacity);
    gb->length = 0;
    gb->gapStart = 0;
    gb->gapEnd = gb->capacity;
    g_gapBuffer = gb;
    return gb;
}

void MC_GapBuffer_Destroy(void* handle) {
    MC_GapBuffer* gb = static_cast<MC_GapBuffer*>(handle);
    if (gb) {
        delete[] gb->data;
        delete gb;
        if (g_gapBuffer == gb) g_gapBuffer = nullptr;
    }
}

int MC_GapBuffer_Insert(void* handle, unsigned int pos, const char* text, unsigned int len) {
    (void)handle; (void)pos; (void)text; (void)len;
    return 0; // success stub
}

int MC_GapBuffer_Delete(void* handle, unsigned int pos, unsigned int len) {
    (void)handle; (void)pos; (void)len;
    return 0; // success stub
}

unsigned int MC_GapBuffer_GetLine(void* handle, unsigned int lineNum, char* out, unsigned int outLen) {
    (void)handle; (void)lineNum;
    if (out && outLen > 0) {
        out[0] = '\0';
    }
    return 0;
}

unsigned int MC_GapBuffer_Length(void* handle) {
    (void)handle;
    return 0;
}

unsigned int MC_GapBuffer_LineCount(void* handle) {
    (void)handle;
    return 1; // at least one line
}

// TokenizeLine stub
struct MC_Token;

unsigned int MC_TokenizeLine(const char* line, unsigned int len, void* tokens, unsigned int maxTokens) {
    (void)line; (void)len; (void)tokens; (void)maxTokens;
    return 0; // no tokens produced
}

} // extern "C"
