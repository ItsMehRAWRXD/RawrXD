// ============================================================================
// monaco_core.cpp — RAWRXD_MONACO_CORE_REAL_001
// ============================================================================
// Real implementation of the MC_* editor-core ABI declared in
// include/RawrXD_MonacoCore.h.
//
// WHY THIS FILE REPLACED monaco_core_stubs.cpp
// --------------------------------------------
// src/asm/RawrXD_MonacoCore.asm is an auto-generated file containing only the
// token "END" -- there has never been an implementation. To make the link
// succeed, monaco_core_stubs.cpp was added. It was wrong in three separate
// ways, each independently fatal:
//
//   1. It declared a DIFFERENT ABI than the header. The header declares
//         int      MC_GapBuffer_Init(MC_GapBuffer* pGB, uint32_t initialCapacity);
//         int      MC_GapBuffer_Insert(MC_GapBuffer* pGB, uint32_t pos, ...);
//      while the stub defined
//         void*    MC_GapBuffer_Init(unsigned int initialCapacity);
//         int      MC_GapBuffer_Insert(void* handle, ...);
//      Both are extern "C", so both mangle to the same bare symbol name. The
//      real caller passes &m_buffer as the first argument; the stub read that
//      pointer's low bits as `initialCapacity`. That is not a degraded feature,
//      it is memory corruption on the first call.
//
//   2. MC_GapBuffer_Insert and MC_GapBuffer_Delete ignored every argument and
//      `return 0` -- which the header defines as SUCCESS. An editor whose
//      edits are discarded while reporting success produces false receipts
//      forever.
//
//   3. MC_GapBuffer_GetLine returned 0 and wrote an empty string, and
//      MC_TokenizeLine returned "no tokens produced", so the syntax highlighter
//      had nothing to draw and no way to say so.
//
// This file implements the declared contract for real. It is the C++
// definition of the ABI the header specifies; when a genuine ASM
// RawrXD_MonacoCore.asm is ever written it replaces this TU, not the reverse.
//
// Semantics are taken verbatim from the header:
//   Init/Destroy/Insert/Delete/MoveGap/GetLine/Length/LineCount/TokenizeLine.
// Return values follow the header exactly: 1 on success, 0 on failure.
// ============================================================================

#include "RawrXD_MonacoCore.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <new>

// ============================================================================
// Gap buffer
// ============================================================================
// Layout:  [ 0 .. gapStart ) [ gapStart .. gapEnd ) [ gapEnd .. capacity )
//           \____ content ___/\______ free gap ___/\___ content ___/
//
// `used` is the logical content length; the gap is storage, not content, so the
// logical byte at offset i lives at bufferPos(i):
//     i < gapStart ? i : i + (gapEnd - gapStart)
// ============================================================================

namespace {

inline uint32_t gapSize(const MC_GapBuffer& gb) { return gb.gapEnd - gb.gapStart; }

// Translate a logical offset to a physical offset in pBuffer.
inline uint32_t bufferPos(const MC_GapBuffer& gb, uint32_t logical) {
    return (logical < gb.gapStart) ? logical : logical + gapSize(gb);
}

// Smallest power-of-two capacity >= n, with a floor of 64 so the gap always has
// room to absorb a single insertion without an immediate reallocation.
uint32_t roundCapacity(uint32_t n) {
    uint32_t c = 64;
    while (c < n && c < (1u << 30)) c <<= 1;
    return c;
}

// Sliding `window` bytes of content from logical offset `from` to `to` by memmove.
void slideContent(MC_GapBuffer& gb, uint32_t from, uint32_t to) {
    if (to > from) {
        const uint32_t n = to - from;
        uint8_t* const dst = gb.pBuffer + bufferPos(gb, from);
        uint8_t* const src = gb.pBuffer + bufferPos(gb, from + n);
        std::memmove(dst, src, n);
    }
}

// Count '\n' in the logical content. Called after insert/delete; O(used).
uint32_t recountLines(const MC_GapBuffer& gb) {
    uint32_t n = 1;  // a buffer always has at least one line
    for (uint32_t i = 0; i < gb.used; ++i) {
        if (gb.pBuffer[bufferPos(gb, i)] == '\n') ++n;
    }
    return n;
}

// Ensure at least `need` free gap bytes, growing if required. Returns false on
// allocation failure, leaving the buffer untouched.
bool ensureGap(MC_GapBuffer& gb, uint32_t need) {
    if (gapSize(gb) >= need) return true;
    const uint32_t required = gb.used + need;
    uint32_t newCap = gb.capacity;
    while (newCap < required) {
        if (newCap > (1u << 30)) return false;
        newCap <<= 1;
    }
    if (newCap == 0) newCap = roundCapacity(required);

    uint8_t* const p = static_cast<uint8_t*>(std::realloc(gb.pBuffer, newCap));
    if (!p) return false;
    gb.pBuffer = p;
    gb.capacity = newCap;

    // Rebuild the tail content after the gap, which moved with the realloc.
    const uint32_t tail = gb.used - gb.gapStart;
    if (tail > 0) {
        std::memmove(p + gb.gapStart + gapSize(gb), p + gb.gapStart, tail);
    }
    gb.gapEnd = gb.capacity - tail;
    return true;
}

}  // namespace

extern "C" {

// ---------------------------------------------------------------------------
// Initialize a gap buffer with the given capacity.
// Returns: 1 on success, 0 on allocation failure.
// ---------------------------------------------------------------------------
int MC_GapBuffer_Init(MC_GapBuffer* pGB, uint32_t initialCapacity) {
    if (!pGB) return 0;
    uint32_t cap = roundCapacity(initialCapacity ? initialCapacity : 4096u);
    uint8_t* const p = static_cast<uint8_t*>(std::malloc(cap));
    if (!p) return 0;
    // Start entirely gap: nothing is content yet, so gapStart=0, gapEnd=cap.
    pGB->pBuffer   = p;
    pGB->gapStart  = 0;
    pGB->gapEnd    = cap;
    pGB->capacity  = cap;
    pGB->used      = 0;
    pGB->lineCount = 1;
    pGB->reserved  = 0;
    return 1;
}

// ---------------------------------------------------------------------------
// Free all memory and zero the struct.
// ---------------------------------------------------------------------------
void MC_GapBuffer_Destroy(MC_GapBuffer* pGB) {
    if (!pGB) return;
    std::free(pGB->pBuffer);
    pGB->pBuffer   = nullptr;
    pGB->gapStart  = 0;
    pGB->gapEnd    = 0;
    pGB->capacity  = 0;
    pGB->used      = 0;
    pGB->lineCount = 0;
    pGB->reserved  = 0;
}

// ---------------------------------------------------------------------------
// Move the gap to `pos` (logical byte offset) for O(1) insertion.
// ---------------------------------------------------------------------------
void MC_GapBuffer_MoveGap(MC_GapBuffer* pGB, uint32_t pos) {
    if (!pGB || !pGB->pBuffer) return;
    if (pos > pGB->used) pos = pGB->used;
    const uint32_t g = gapSize(*pGB);
    if (pos == pGB->gapStart) return;

    if (pos < pGB->gapStart) {
        // Move the [pos, gapStart) segment to sit after the gap.
        const uint32_t n = pGB->gapStart - pos;
        std::memmove(pGB->pBuffer + pos + g, pGB->pBuffer + pos, n);
        pGB->gapStart -= n;
        pGB->gapEnd   -= n;
    } else {
        // Move the [gapEnd, pos) segment to sit before the gap.
        const uint32_t n = pos - pGB->gapStart;
        std::memmove(pGB->pBuffer + pGB->gapStart - n,
                     pGB->pBuffer + pGB->gapStart,
                     n);
        pGB->gapStart += n;
        pGB->gapEnd   += n;
    }
}

// ---------------------------------------------------------------------------
// Insert `len` bytes of `text` at logical position `pos`.
// Automatically grows the buffer if needed.
// Returns: 1 on success, 0 on allocation failure.
// ---------------------------------------------------------------------------
int MC_GapBuffer_Insert(MC_GapBuffer* pGB, uint32_t pos,
                        const char* text, uint32_t len) {
    if (!pGB || !pGB->pBuffer) return 0;
    if (len == 0) return 1;              // nothing to do is success, not failure
    if (!text) return 0;
    if (pos > pGB->used) return 0;        // refuse rather than silently clamp

    // Amortised growth: make room for at least len, ideally more so a run of
    // single-character insertions does not reallocate on every keystroke.
    if (!ensureGap(*pGB, len)) return 0;

    MC_GapBuffer_MoveGap(pGB, pos);
    std::memcpy(pGB->pBuffer + pGB->gapStart, text, len);
    pGB->gapStart += len;
    pGB->used     += len;
    pGB->lineCount = recountLines(*pGB);
    return 1;
}

// ---------------------------------------------------------------------------
// Delete `len` bytes starting at logical position `pos`.
// Returns: 1 on success, 0 on failure.
// ---------------------------------------------------------------------------
int MC_GapBuffer_Delete(MC_GapBuffer* pGB, uint32_t pos, uint32_t len) {
    if (!pGB || !pGB->pBuffer) return 0;
    if (len == 0) return 1;
    if (pos > pGB->used) return 0;
    if (pos + len > pGB->used) len = pGB->used - pos;   // clamp to what exists

    // Open a gap at `pos`: slide the following content left by len.
    MC_GapBuffer_MoveGap(pGB, pos);
    slideContent(*pGB, pos + len, pGB->used);
    pGB->used -= len;
    pGB->lineCount = recountLines(*pGB);
    return 1;
}

// ---------------------------------------------------------------------------
// Copy line `lineIdx` (without its newline) into `out`.
// Returns the number of bytes written, excluding the terminator.
// ---------------------------------------------------------------------------
uint32_t MC_GapBuffer_GetLine(MC_GapBuffer* pGB, uint32_t lineIdx,
                              char* out, uint32_t outLen) {
    if (out && outLen) out[0] = '\0';
    if (!pGB || !pGB->pBuffer || !out || outLen == 0) return 0;
    if (lineIdx >= pGB->lineCount) return 0;

    // Walk the content once, counting newlines, to find the line's start.
    uint32_t line = 0;
    uint32_t start = 0;
    for (uint32_t i = 0; i < pGB->used; ++i) {
        if (pGB->pBuffer[bufferPos(*pGB, i)] == '\n') {
            if (line == lineIdx) { start = i; break; }
            ++line;
            start = i + 1;
        }
        if (line == lineIdx && i + 1 == pGB->used) {
            start = i + 1;   // last line has no trailing newline
        }
    }

    uint32_t end = start;
    while (end < pGB->used && pGB->pBuffer[bufferPos(*pGB, end)] != '\n') ++end;

    const uint32_t n = end - start;
    if (n >= outLen) {
        // Do not emit a half line that would look like real content. Copy what
        // fits and terminate; the caller sees outLen-1 bytes and can detect the
        // truncation by comparing against MC_GapBuffer_Length.
        const uint32_t fit = outLen - 1;
        for (uint32_t i = 0; i < fit; ++i) out[i] = (char)pGB->pBuffer[bufferPos(*pGB, start + i)];
        out[fit] = '\0';
        return fit;
    }
    for (uint32_t i = 0; i < n; ++i) out[i] = (char)pGB->pBuffer[bufferPos(*pGB, start + i)];
    out[n] = '\0';
    return n;
}

// ---------------------------------------------------------------------------
// Logical content length in bytes.
// ---------------------------------------------------------------------------
uint32_t MC_GapBuffer_Length(const MC_GapBuffer* pGB) {
    return pGB ? pGB->used : 0;
}

// ---------------------------------------------------------------------------
// Number of lines. An empty buffer has one (empty) line.
// ---------------------------------------------------------------------------
uint32_t MC_GapBuffer_LineCount(const MC_GapBuffer* pGB) {
    if (!pGB) return 0;
    return pGB->lineCount ? pGB->lineCount : 1;
}

// ---------------------------------------------------------------------------
// Tokenize one line of C-family source.
// Returns the number of tokens written (never more than maxTokens).
// ---------------------------------------------------------------------------
uint32_t MC_TokenizeLine(const char* line, uint32_t len,
                         MC_Token* outTokens, uint32_t maxTokens) {
    if (!line || !outTokens || maxTokens == 0 || len == 0) return 0;

    uint32_t n = 0;
    uint32_t i = 0;

    auto push = [&](uint32_t start, uint32_t lenSpan, MC_TokenType type,
                    uint32_t color) -> bool {
        if (n >= maxTokens) return false;
        MC_Token& t = outTokens[n];
        t.startCol = start;
        t.length   = lenSpan;
        t.tokenType = static_cast<uint32_t>(type);
        t.color    = color;
        ++n;
        return true;
    };

    static const char* const kKeywords[] = {
        "alignas","alignof","auto","bool","break","case","catch","char","class",
        "co_await","co_return","co_yield","const","consteval","constexpr","constinit",
        "continue","decltype","default","delete","do","double","dynamic_cast","else",
        "enum","explicit","export","extern","false","float","for","friend","goto",
        "if","inline","int","long","mutable","namespace","new","noexcept","nullptr",
        "operator","private","protected","public","register","reinterpret_cast",
        "requires","return","short","signed","sizeof","static","static_assert",
        "static_cast","struct","switch","template","this","thread_local","throw",
        "true","try","typedef","typeid","typename","union","unsigned","using",
        "virtual","void","volatile","wchar_t","while",
    };

    auto isIdentStart = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    };
    auto isIdentBody = [&](char c, uint32_t idx) {
        return isIdentStart(c) || (c >= '0' && c <= '9') || c == '$';
    };
    auto isKeyword = [](const char* s, uint32_t n) {
        for (const char* kw : kKeywords) {
            if (std::strlen(kw) == n && std::strncmp(kw, s, n) == 0) return true;
        }
        return false;
    };
    auto isSpace = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
    };

    while (i < len) {
        const uint32_t start = i;
        const char c = line[i];

        // Preprocessor directive: '#' at the start of a line through the newline.
        if (c == '#' && (start == 0 || line[start - 1] == '\n')) {
            while (i < len && line[i] != '\n') ++i;
            if (!push(start, i - start, MC_TokenType::Preprocessor,
                     MC_Colors::PREPROCESSOR)) break;
            continue;
        }

        // Line comment.
        if (c == '/' && i + 1 < len && line[i + 1] == '/') {
            while (i < len && line[i] != '\n') ++i;
            if (!push(start, i - start, MC_TokenType::Comment, MC_Colors::COMMENT)) break;
            continue;
        }

        // Block comment (unterminated runs to end of line, which is what a
        // single-line tokenizer can honestly report).
        if (c == '/' && i + 1 < len && line[i + 1] == '*') {
            i += 2;
            while (i + 1 < len && !(line[i] == '*' && line[i + 1] == '/')) ++i;
            i = (i + 1 < len) ? i + 2 : len;
            if (!push(start, i - start, MC_TokenType::Comment, MC_Colors::COMMENT)) break;
            continue;
        }

        // String / char literal, honouring backslash escapes.
        if (c == '"' || c == '\'') {
            const char quote = c;
            ++i;
            while (i < len) {
                if (line[i] == '\\' && i + 1 < len) { i += 2; continue; }
                if (line[i] == quote) { ++i; break; }
                ++i;
            }
            if (!push(start, i - start, MC_TokenType::String, MC_Colors::STRING)) break;
            continue;
        }

        // Number: decimal, hex, float, exponent, digit separators, suffixes.
        if ((c >= '0' && c <= '9') ||
            (c == '.' && i + 1 < len && line[i + 1] >= '0' && line[i + 1] <= '9')) {
            if (c == '0' && i + 1 < len && (line[i + 1] == 'x' || line[i + 1] == 'X')) {
                i += 2;
                while (i < len && (std::isxdigit(static_cast<unsigned char>(line[i])) || line[i] == '\'')) ++i;
            } else {
                while (i < len && ((line[i] >= '0' && line[i] <= '9') || line[i] == '\'')) ++i;
                if (i < len && line[i] == '.') {
                    ++i;
                    while (i < len && ((line[i] >= '0' && line[i] <= '9') || line[i] == '\'')) ++i;
                }
                if (i < len && (line[i] == 'e' || line[i] == 'E')) {
                    uint32_t save = i;
                    ++i;
                    if (i < len && (line[i] == '+' || line[i] == '-')) ++i;
                    if (i < len && line[i] >= '0' && line[i] <= '9') {
                        while (i < len && line[i] >= '0' && line[i] <= '9') ++i;
                    } else {
                        i = save;   // "1e" is a number then an identifier
                    }
                }
            }
            while (i < len && isIdentBody(line[i], i)) ++i;   // f, LL, ULL suffixes
            if (!push(start, i - start, MC_TokenType::Number, MC_Colors::NUMBER)) break;
            continue;
        }

        // Identifier, keyword, or register name (x86 register set).
        if (isIdentStart(c)) {
            while (i < len && isIdentBody(line[i], i)) ++i;
            const uint32_t span = i - start;
            const char* const s = line + start;
            if (isKeyword(s, span)) {
                if (!push(start, span, MC_TokenType::Keyword, MC_Colors::KEYWORD)) break;
            } else {
                static const char* const kRegs[] = {
                    "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11",
                    "r12","r13","r14","r15","eax","ebx","ecx","edx","esi","edi","ebp","esp",
                    "ax","bx","cx","dx","si","di","bp","sp","al","bl","cl","dl","ah","bh","ch","dh",
                    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
                    "ymm0","ymm1","ymm2","ymm3","zmm0","zmm1",
                };
                bool isReg = false;
                for (const char* r : kRegs) {
                    if (std::strlen(r) == span && std::strncmp(r, s, span) == 0) { isReg = true; break; }
                }
                if (!push(start, span,
                          isReg ? MC_TokenType::Register : MC_TokenType::Identifier,
                          isReg ? MC_Colors::REGISTER : MC_Colors::TEXT_DEFAULT)) break;
            }
            continue;
        }

        if (isSpace(c)) {
            while (i < len && isSpace(line[i])) ++i;
            if (!push(start, i - start, MC_TokenType::Whitespace, 0)) break;
            continue;
        }

        // Operator or punctuation. '#' mid-line and anything else lands here.
        ++i;
        if (!push(start, 1, MC_TokenType::Operator, MC_Colors::OPERATOR)) break;
    }

    return n;
}

}  // extern "C"