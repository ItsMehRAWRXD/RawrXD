// ============================================================================
// ANSIParser.h - ANSI Escape Sequence Parser for Terminal Colors (Day 6)
// ============================================================================
// Parses ANSI escape sequences (SGR codes) and converts them to RichEdit
// character formatting. Supports 16 colors, 256 colors, and RGB true color.
//
// DAY 6 DELIVERABLES:
// - Parse CSI sequences (ESC [ ... m)
// - Support foreground/background colors
// - Support text attributes (bold, italic, underline)
// - Convert to CHARFORMAT2 for RichEdit
// - Handle 16-color, 256-color, and RGB modes
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <richedit.h>

namespace RawrXD {

// ============================================================================
// ANSI Color Codes
// ============================================================================

// Standard 16 colors (0-15)
enum class ANSIColor : uint8_t {
    Black = 0,
    Red = 1,
    Green = 2,
    Yellow = 3,
    Blue = 4,
    Magenta = 5,
    Cyan = 6,
    White = 7,
    BrightBlack = 8,
    BrightRed = 9,
    BrightGreen = 10,
    BrightYellow = 11,
    BrightBlue = 12,
    BrightMagenta = 13,
    BrightCyan = 14,
    BrightWhite = 15
};

// Text attributes
struct ANSIAttributes {
    bool bold = false;
    bool faint = false;
    bool italic = false;
    bool underline = false;
    bool blink = false;
    bool reverse = false;
    bool conceal = false;
    bool strikethrough = false;
    
    // Colors (0-15 = standard, 16-255 = 256 palette, 256+ = RGB)
    int foreground = -1;  // -1 = default
    int background = -1;  // -1 = default
    
    // RGB values for true color (when foreground/background >= 256)
    COLORREF foregroundRGB = 0;
    COLORREF backgroundRGB = 0;
    
    void Reset() {
        bold = faint = italic = underline = blink = reverse = conceal = strikethrough = false;
        foreground = background = -1;
        foregroundRGB = backgroundRGB = 0;
    }
};

// ============================================================================
// Parsed Text Segment
// ============================================================================
struct TextSegment {
    std::string text;
    ANSIAttributes attributes;
    
    TextSegment() = default;
    TextSegment(const std::string& t, const ANSIAttributes& a) : text(t), attributes(a) {}
};

// ============================================================================
// ANSI Parser
// ============================================================================
class ANSIParser {
public:
    ANSIParser();
    ~ANSIParser() = default;
    
    // Parse a string containing ANSI escape sequences
    // Returns segments with text and associated attributes
    std::vector<TextSegment> Parse(const std::string& input);
    
    // Parse and return plain text (strip all ANSI codes)
    std::string StripANSI(const std::string& input);
    
    // Check if string contains any ANSI escape sequences
    bool ContainsANSI(const std::string& input);
    
    // Convert ANSI attributes to RichEdit CHARFORMAT2
    // Returns true if formatting was applied
    static bool ApplyToCharFormat(const ANSIAttributes& attrs, CHARFORMAT2& cf);
    
    // Get default terminal colors
    static COLORREF GetDefaultForeground();
    static COLORREF GetDefaultBackground();
    
    // Set custom color palette (optional)
    void SetColorPalette(const std::vector<COLORREF>& palette);

private:
    // Parse a single CSI sequence (ESC [ ... m)
    // Returns number of characters consumed, 0 if not a valid sequence
    size_t ParseCSISequence(const std::string& input, size_t pos, ANSIAttributes& attrs);
    
    // Parse SGR parameters (the numbers between [ and m)
    void ParseSGRParams(const std::string& params, ANSIAttributes& attrs);
    
    // Convert ANSI color code to RGB
    COLORREF ANSIToRGB(int code);
    
    // 256 color palette
    COLORREF Get256Color(uint8_t index);
    
    // Current color palette (can be customized)
    std::vector<COLORREF> m_colorPalette;
    
    // Default 16-color palette (Windows Console colors)
    static const COLORREF s_defaultPalette[16];
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Parse and apply to RichEdit control
// Returns number of characters inserted
int AppendANSIToRichEdit(HWND hwndRichEdit, const std::string& ansiText);

// Set RichEdit text with ANSI formatting (replaces existing content)
void SetRichEditANSIText(HWND hwndRichEdit, const std::string& ansiText);

} // namespace RawrXD
