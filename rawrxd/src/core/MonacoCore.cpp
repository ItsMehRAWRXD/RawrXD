// ============================================================================
// MonacoCore.cpp — real gap-buffer text model and line tokenizer.
//
// RAWRXD_MONACO_REAL_IMPLEMENTATION_001
//
// WHY THIS FILE REPLACES monaco_core_stubs.cpp
//
// src/core/monaco_core_stubs.cpp was added to close link errors, and it was
// also wrong in three independent ways:
//
//   1. IT LIED. Its own header said "C stubs satisfy the link requirements
//      until real ASM implementations are written", and the bodies agreed:
//      Insert and Delete returned 0 while moving no bytes, Length always
//      returned 0, LineCount always returned 1, and TokenizeLine produced no
//      tokens at all. An editor built on that is a window that accepts typing
//      and discards it.
//
//   2. IT DID NOT MATCH THE HEADER ABI. include/RawrXD_MonacoCore.h declares
//        int      MC_GapBuffer_Init(MC_GapBuffer*, uint32_t);
//        void     MC_GapBuffer_MoveGap(MC_GapBuffer*, uint32_t);
//        uint32_t MC_GapBuffer_Length(const MC_GapBuffer*);
//      while the stub declared
//        void*    MC_GapBuffer_Init(unsigned int);
//        uint32_t MC_GapBuffer_Length(void*);
//      and omitted MC_GapBuffer_MoveGap entirely. A symbol can satisfy the
//      linker and still be the wrong function.
//
//   3. THE PROJECT FORBADE IT. rawrxd/CMakeLists.txt refuses to configure
//      RawrXD-Win32IDE when a stub/shim/mock source is linked:
//
//        [PRODUCTION POLICY VIOLATION] RawrXD-Win32IDE
//        Found 1 stub/shim/mock files: src/core/monaco_core_stubs.cpp
//
//      so the "COMPILE=PASS, LINK=PASS" recorded for the IDE was obtained by
//      the exact mechanism the build gate refuses.
//
// This file implements the declared contract for real, in C++, against the
// packed 32-byte MC_GapBuffer and 16-byte MC_Token layouts the header pins
// with static_assert.
//
// ---------------------------------------------------------------------------
// THE GAP BUFFER IS REAL, NOT A STAND-IN
// ---------------------------------------------------------------------------
// A single contiguous buffer with a movable gap:
//
//   | pBuffer[0 .. gapStart) | gap [gapStart .. gapEnd) | pBuffer[gapEnd ..) |
//        <- left text ->            free space            <- right text ->
//
// Logical byte i of the document lives at physical i when i < gapStart, and
// at i + (gapEnd - gapStart) otherwise. Every accessor goes through that
// mapping, so Insert/Delete/GetLine/Length/LineCount all observe one real
// document. Newline count is maintained incrementally on every mutation rather
// than recomputed, so LineCount cannot drift from the content it describes.
// ============================================================================

#include "RawrXD_MonacoCore.h"

#include <cstring>
#include <new>

namespace {

// Logical -> physical offset. The only place this mapping exists.
inline uint32_t physOf(const MC_GapBuffer* gb, uint32_t logical) {
    if (logical < gb->gapStart) return logical;
    return logical + (gb->gapEnd - gb->gapStart);
}

// Grows the allocation, preserving content order. Returns false only when the
// allocator refuses, and never silently truncates: an editor that drops text
// on a failed resize is worse than one that reports failure.
bool growGap(MC_GapBuffer* gb, uint32_t needed) {
    const uint32_t newCap = needed * 2u;
    auto* nb = static_cast<uint8_t*>(::operator new(newCap));
    const uint32_t leftLen  = gb->gapStart;
    const uint32_t rightLen = gb->used - gb->gapStart;

    if (leftLen)  std::memcpy(nb, gb->pBuffer, leftLen);
    if (rightLen) {
        std::memcpy(nb + newCap - rightLen,
                    gb->pBuffer + gb->gapEnd, rightLen);
    }
    ::operator delete(gb->pBuffer);

    gb->pBuffer   = nb;
    gb->capacity  = newCap;
    gb->gapStart  = leftLen;
    gb->gapEnd    = newCap - rightLen;
    return true;
}

// Adds the newline delta implied by a span of bytes. Called with the bytes
// actually inserted or deleted so lineCount tracks content by construction.
inline int32_t countNewlines(const uint8_t* p, uint32_t n) {
    int32_t c = 0;
    for (uint32_t i = 0; i < n; ++i) if (p[i] == '\n') ++c;
    return c;
}

inline bool isIdentStart(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
inline bool isIdentChar(char c) {
    return isIdentStart(c) || (c >= '0' && c <= '9');
}
inline bool isDigit(char c) { return c >= '0' && c <= '9'; }
inline bool isSpace(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

// Case-sensitive comparison against a NUL-terminated literal.
bool equalsKeyword(const char* p, uint32_t len, const char* kw) {
    const uint32_t n = static_cast<uint32_t>(std::strlen(kw));
    if (n != len) return false;
    for (uint32_t i = 0; i < len; ++i) {
        if (p[i] != kw[i]) return false;
    }
    return true;
}

bool isKeyword(const char* p, uint32_t len) {
    static const char* kWords[] = {
        "auto","break","case","char","const","continue","default","do",
        "double","else","enum","extern","float","for","goto","if","inline",
        "int","long","register","return","short","signed","sizeof","static",
        "struct","switch","typedef","union","unsigned","void","volatile",
        "while","class","namespace","template","public","private",
        "protected","virtual","new","delete","this","operator","bool",
        "true","false","nullptr","using","try","catch","throw","constexpr",
        "explicit","friend","mutable","noexcept","typename","wchar_t",
    };
    for (const char* kw : kWords) if (equalsKeyword(p, len, kw)) return true;
    return false;
}

bool isRegister(const char* p, uint32_t len) {
    static const char* kRegs[] = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10",
        "r11","r12","r13","r14","r15","eax","ebx","ecx","edx","esi","edi",
        "ebp","esp",
    };
    for (const char* r : kRegs) if (equalsKeyword(p, len, r)) return true;
    return false;
}

bool isInstruction(const char* p, uint32_t len) {
    static const char* kOps[] = {
        "mov","lea","add","sub","mul","imul","div","idiv","inc","dec",
        "and","or","xor","not","neg","shl","shr","sar","rol","ror","cmp",
        "test","push","pop","call","ret","jmp","je","jne","jz","jnz","jg",
        "jge","jl","jle","ja","jb","jbe","jae","nop","int","loop","leave",
        "enter","xchg",
    };
    for (const char* op : kOps) if (equalsKeyword(p, len, op)) return true;
    return false;
}

} // namespace

extern "C" {

// ---------------------------------------------------------------------------
// RAWRXD_MONACO_RETURN_CONVENTION_001
//
// The header (include/RawrXD_MonacoCore.h) specifies "Returns: 1 on success,
// 0 on allocation failure" for Init, Insert and Delete, and the in-tree callers
// test that as `!= 0`:
//
//     return MC_GapBuffer_Insert(&m_buffer, pos, text, len) != 0;   // "ok"
//
// This file previously returned 0 on success and -1 on failure, which satisfies
// a link and satisfies nothing else: with `!= 0` as the test, every SUCCESSFUL
// edit was reported to the caller as failure (-1 was indistinguishable from
// success, 0 was read as failure). The editor therefore rejected exactly the
// edits that landed and accepted exactly the ones that did not. The convention
// below now matches the declared contract.
int MC_GapBuffer_Init(MC_GapBuffer* pGB, uint32_t initialCapacity) {
    if (!pGB) return 0;
    if (initialCapacity < 64) initialCapacity = 64;
    auto* buf = static_cast<uint8_t*>(::operator new(initialCapacity));
    if (!buf) return 0;

    pGB->pBuffer   = buf;
    pGB->gapStart  = 0;
    pGB->gapEnd    = initialCapacity;
    pGB->capacity  = initialCapacity;
    pGB->used      = 0;
    pGB->lineCount = 0;
    pGB->reserved  = 0;
    return 1;
}

// ---------------------------------------------------------------------------
void MC_GapBuffer_Destroy(MC_GapBuffer* pGB) {
    if (!pGB) return;
    ::operator delete(pGB->pBuffer);
    pGB->pBuffer  = nullptr;
    pGB->gapStart = pGB->gapEnd = 0;
    pGB->capacity = pGB->used = pGB->lineCount = pGB->reserved = 0;
}

// ---------------------------------------------------------------------------
void MC_GapBuffer_MoveGap(MC_GapBuffer* pGB, uint32_t pos) {
    if (!pGB || !pGB->pBuffer) return;
    if (pos > pGB->used) pos = pGB->used;

    const uint32_t gapLen = pGB->gapEnd - pGB->gapStart;
    const uint32_t curGap = pGB->gapStart;
    if (pos == curGap) return;

    if (pos < curGap) {
        // Gap moves left: grow it to the right by (curGap - pos).
        const uint32_t move = curGap - pos;
        std::memmove(pGB->pBuffer + pGB->gapEnd - move,
                     pGB->pBuffer + pos, move);
        pGB->gapStart = pos;
        pGB->gapEnd  -= move;
    } else {
        // Gap moves right: shrink it from the left by (pos - curGap).
        const uint32_t move = pos - curGap;
        if (move > gapLen) {
            // The gap is too small; grow first so the move stays in bounds.
            if (!growGap(pGB, pGB->used + move)) return;
        }
        std::memmove(pGB->pBuffer + pGB->gapStart,
                     pGB->pBuffer + pGB->gapEnd, move);
        pGB->gapStart += move;
        pGB->gapEnd   += move;
    }
}

// ---------------------------------------------------------------------------
int MC_GapBuffer_Insert(MC_GapBuffer* pGB, uint32_t pos,
                        const char* text, uint32_t len) {
    // 1 = success, 0 = failure, per RawrXD_MonacoCore.h. See
    // RAWRXD_MONACO_RETURN_CONVENTION_001 at MC_GapBuffer_Init.
    if (!pGB || !pGB->pBuffer) return 0;
    if (!text && len) return 0;
    if (pos > pGB->used) return 0;
    if (len == 0) return 1;              // nothing to insert is success, not failure

    const uint32_t gapLen = pGB->gapEnd - pGB->gapStart;
    if (len > gapLen) {
        // Need a larger gap. Grow so it is at least len, keeping some slack.
        const uint32_t want = pGB->used + len;
        if (!growGap(pGB, want > pGB->capacity ? want : pGB->capacity)) return 0;
    }

    MC_GapBuffer_MoveGap(pGB, pos);
    std::memcpy(pGB->pBuffer + pGB->gapStart, text, len);
    pGB->gapStart += len;
    pGB->used     += len;
    pGB->lineCount = static_cast<uint32_t>(
        static_cast<int32_t>(pGB->lineCount) +
        countNewlines(reinterpret_cast<const uint8_t*>(text), len));
    return 1;
}

// ---------------------------------------------------------------------------
int MC_GapBuffer_Delete(MC_GapBuffer* pGB, uint32_t pos, uint32_t len) {
    if (!pGB || !pGB->pBuffer) return 0;
    if (pos > pGB->used) return 0;
    if (len == 0) return 1;
    if (pos + len > pGB->used) len = pGB->used - pos;   // clamp, never overrun

    // Count the newlines leaving the document BEFORE the bytes move.
    uint32_t removed = 0;
    for (uint32_t i = 0; i < len; ++i) {
        const uint32_t logical = pos + i;
        if (physOf(pGB, logical) < pGB->capacity) {
            if (pGB->pBuffer[physOf(pGB, logical)] == '\n') ++removed;
        }
    }

    MC_GapBuffer_MoveGap(pGB, pos);
    // The gap now sits at pos; widening it absorbs the deleted range.
    pGB->gapEnd += len;
    pGB->used   -= len;
    pGB->lineCount = (pGB->lineCount >= removed)
                   ? pGB->lineCount - removed : 0;
    return 1;
}

// ---------------------------------------------------------------------------
uint32_t MC_GapBuffer_Length(const MC_GapBuffer* pGB) {
    return pGB ? pGB->used : 0u;
}

// ---------------------------------------------------------------------------
uint32_t MC_GapBuffer_LineCount(const MC_GapBuffer* pGB) {
    if (!pGB) return 0u;
    // Newlines + 1: an empty buffer is still one (empty) line. This is
    // maintained incrementally by Insert/Delete, so it cannot disagree with
    // the bytes it describes.
    return pGB->lineCount + 1u;
}

// ---------------------------------------------------------------------------
uint32_t MC_GapBuffer_GetLine(MC_GapBuffer* pGB, uint32_t lineIdx,
                               char* outBuffer, uint32_t maxLen) {
    if (!pGB || !pGB->pBuffer || !outBuffer || maxLen == 0) return 0u;
    outBuffer[0] = '\0';
    if (lineIdx >= MC_GapBuffer_LineCount(pGB)) return 0u;

    // Walk the document once to find the span of the requested line.
    //
    // RAWRXD_MONACO_GETLINE_OFFBYONE_001
    // `start` is already the first byte of `line` at every point in this loop:
    // it begins at 0 and is only advanced to (newline index + 1) when moving on
    // to the NEXT line. The previous version also advanced it inside the
    // `line == lineIdx` branch, which set start to one byte PAST the newline
    // that terminates the requested line -- i.e. to the beginning of the
    // following line. In any document containing a newline that made GetLine(0)
    // return line 1's text, GetLine(1) return line 2's, and so on: line 0 was
    // unreachable and consecutive indices returned duplicate content, with the
    // final line unreadable. The break must leave `start` alone.
    uint32_t line = 0;
    uint32_t start = 0;
    uint32_t i = 0;
    for (; i < pGB->used; ++i) {
        if (pGB->pBuffer[physOf(pGB, i)] == '\n') {
            if (line == lineIdx) break;   // `start` already points at this line
            ++line;
            start = i + 1;
        }
    }
    if (line < lineIdx) { start = pGB->used; }

    uint32_t end = start;
    while (end < pGB->used && pGB->pBuffer[physOf(pGB, end)] != '\n') ++end;

    uint32_t n = end - start;
    if (n > MC_MAX_LINE_LENGTH) n = MC_MAX_LINE_LENGTH;
    // Always reserve one byte for the terminator, including when truncating.
    if (n > maxLen - 1u) n = maxLen - 1u;

    for (uint32_t k = 0; k < n; ++k)
        outBuffer[k] = static_cast<char>(pGB->pBuffer[physOf(pGB, start + k)]);
    outBuffer[n] = '\0';
    return n;
}

// ---------------------------------------------------------------------------
// Lexer for C/C++-shaped source. Emits typed spans with explicit lengths, so a
// caller can reconstruct the line exactly from the token stream.
//
// Line comments, block comments and string/char literals are consumed as whole
// units, which is what stops a keyword inside a string from being highlighted.
// ---------------------------------------------------------------------------
uint32_t MC_TokenizeLine(const char* line, uint32_t len,
                         MC_Token* outTokens, uint32_t maxTokens) {
    if (!line || !outTokens || maxTokens == 0) return 0u;

    uint32_t produced = 0;
    uint32_t i = 0;
    auto emit = [&](uint32_t startCol, uint32_t length, MC_TokenType t) {
        if (produced >= maxTokens || length == 0) return;
        MC_Token& tok = outTokens[produced++];
        tok.startCol  = startCol;
        tok.length    = length;
        tok.tokenType = static_cast<uint32_t>(t);
        tok.color     = 0;              // 0 = use theme default
    };

    while (i < len && produced < maxTokens) {
        const char c = line[i];

        if (isSpace(c)) {
            const uint32_t s = i;
            while (i < len && isSpace(line[i])) ++i;
            emit(s, i - s, MC_TokenType::Whitespace);
            continue;
        }

        // Line comment: runs to end of line.
        if (c == '/' && i + 1 < len && line[i + 1] == '/') {
            emit(i, len - i, MC_TokenType::Comment);
            return produced;
        }
        // Block comment: ends at the next */ or end of line.
        if (c == '/' && i + 1 < len && line[i + 1] == '*') {
            const uint32_t s = i;
            i += 2;
            while (i + 1 < len && !(line[i] == '*' && line[i + 1] == '/')) ++i;
            i = (i + 1 < len) ? i + 2 : len;
            emit(s, i - s, MC_TokenType::Comment);
            continue;
        }

        // String / char literal, honouring backslash escapes.
        if (c == '"' || c == '\'') {
            const uint32_t s = i;
            const char quote = c;
            ++i;
            while (i < len) {
                if (line[i] == '\\' && i + 1 < len) { i += 2; continue; }
                if (line[i] == quote) { ++i; break; }
                ++i;
            }
            emit(s, i - s, MC_TokenType::String);
            continue;
        }

        // Preprocessor directive: '#' at the start of a line.
        if (c == '#') {
            const uint32_t s = i;
            ++i;
            while (i < len && isIdentChar(line[i])) ++i;
            emit(s, i - s, MC_TokenType::Preprocessor);
            continue;
        }

        if (isDigit(c) ||
            (c == '.' && i + 1 < len && isDigit(line[i + 1]))) {
            const uint32_t s = i;
            while (i < len && (isDigit(line[i]) || line[i] == '.' ||
                               line[i] == 'x' || line[i] == 'X' ||
                               (line[i] >= 'a' && line[i] <= 'f') ||
                               (line[i] >= 'A' && line[i] <= 'F') ||
                               line[i] == 'u' || line[i] == 'U' ||
                               line[i] == 'l' || line[i] == 'L')) ++i;
            emit(s, i - s, MC_TokenType::Number);
            continue;
        }

        if (isIdentStart(c)) {
            const uint32_t s = i;
            while (i < len && isIdentChar(line[i])) ++i;
            const uint32_t n = i - s;
            MC_TokenType t = MC_TokenType::Identifier;
            if      (isKeyword(line + s, n))     t = MC_TokenType::Keyword;
            else if (isRegister(line + s, n))    t = MC_TokenType::Register;
            else if (isInstruction(line + s, n)) t = MC_TokenType::Instruction;
            emit(s, n, t);
            continue;
        }

        // Anything else is an operator, grouped so that '==' is one token
        // rather than two, which matters for renderers that underline spans.
        {
            const uint32_t s = i;
            if (i + 1 < len) {
                const char a = c, b = line[i + 1];
                const bool two = (a == '=' && b == '=') ||
                                 (a == '!' && b == '=') ||
                                 (a == '<' && b == '=') ||
                                 (a == '>' && b == '=') ||
                                 (a == '+' && b == '+') ||
                                 (a == '-' && b == '-') ||
                                 (a == '&' && b == '&') ||
                                 (a == '|' && b == '|') ||
                                 (a == '-' && b == '>') ||
                                 (a == ':' && b == ':');
                if (two) ++i;
            }
            ++i;
            emit(s, i - s, MC_TokenType::Operator);
        }
    }
    return produced;
}

} // extern "C"