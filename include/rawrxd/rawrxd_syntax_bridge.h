#pragma once

// RawrXD Syntax Bridge — Syntax highlighting bridge for software raster
// Gated by RAWRXD_SOFTWARE_BLIT_RASTER=1.

#include <cstddef>
#include <cstdint>
#include <windows.h>
#include "rawrxd_text_engine.h"

namespace rawrxd::ui
{

// Syntax token types
enum class SyntaxTokenType : std::uint8_t
{
    None = 0,
    Keyword,
    Identifier,
    String,
    Number,
    Comment,
    Operator,
    Punctuation,
    Preprocessor,
    Type,
    Function,
    Variable,
    Parameter,
    Property,
    Namespace,
    Class,
    Interface,
    Enum,
    Struct,
    Constant,
    Macro,
    Label,
    Whitespace,
    Error,
    Warning,
    Info,
    Hint,
    Max
};

// Syntax line info — per-line syntax data
struct SyntaxLineInfo
{
    SyntaxColorRun* runs = nullptr;
    std::uint32_t runCount = 0;
    std::uint32_t runCapacity = 0;
    std::uint32_t state = 0; // Parser state for multi-line constructs
};

// Syntax bridge context
struct SyntaxBridgeContext
{
    void* parserState = nullptr;
    const char* fileExtension = nullptr;
    std::uint32_t languageId = 0;
};

// Initialize syntax bridge
bool initializeSyntaxBridge(SyntaxBridgeContext* ctx, const char* fileExtension);

// Shutdown syntax bridge
void shutdownSyntaxBridge(SyntaxBridgeContext* ctx);

// Parse line and generate color runs
std::uint32_t parseLineSyntax(SyntaxBridgeContext* ctx, const char* lineText,
                               std::uint32_t length, std::uint32_t lineIndex,
                               SyntaxColorRun* outRuns, std::uint32_t maxRuns);

// Get default color for token type
std::uint32_t getDefaultTokenColor(SyntaxTokenType type);

// Pack COLORREF to ARGB
constexpr std::uint32_t packColorArgb(COLORREF rgb, std::uint8_t alpha = 255)
{
    return (static_cast<std::uint32_t>(alpha) << 24) |
           (static_cast<std::uint32_t>(GetRValue(rgb)) << 16) |
           (static_cast<std::uint32_t>(GetGValue(rgb)) << 8) |
           static_cast<std::uint32_t>(GetBValue(rgb));
}

// Unpack ARGB to COLORREF
constexpr COLORREF unpackColorRgb(std::uint32_t argb)
{
    return RGB(static_cast<std::uint8_t>(argb >> 16),
               static_cast<std::uint8_t>(argb >> 8),
               static_cast<std::uint8_t>(argb));
}

// Blend two ARGB colors
std::uint32_t blendArgbColors(std::uint32_t dst, std::uint32_t src);

// Syntax bridge enabled check
bool syntaxBridgeEnabled();

} // namespace rawrxd::ui
